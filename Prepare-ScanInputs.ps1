#Requires -Version 7.0
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'artifacts'),
    [switch]$IncludeBinaryCases,
    [switch]$IncludePublicCases,
    [switch]$IncludeReferenceCatalogCases,
    [switch]$IncludeBinaryContentCases
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$PSNativeCommandUseErrorActionPreference = $false

$output = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
if (Test-Path -LiteralPath $output) {
    throw "OutputDirectory already exists; choose a new directory: $output"
}
if (($IncludeBinaryCases -or $IncludeBinaryContentCases) -and -not $IsWindows) {
    throw 'Generating the real Authenticode fixtures requires Windows.'
}
$null = Get-Command tar -ErrorAction Stop
$manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'scenarios.json') -Raw | ConvertFrom-Json
if ($manifest.schemaVersion -ne 1) { throw 'Unsupported scenario manifest version.' }
$cases = @($manifest.cases | Where-Object {
    ($IncludeBinaryCases -or -not $_.binary) -and
    ($IncludePublicCases -or (-not $_.PSObject.Properties['publicSource'] -and
        -not $_.PSObject.Properties['publicReference'])) -and
    ($IncludeReferenceCatalogCases -or -not $_.PSObject.Properties['referenceCatalog']) -and
    ($IncludeBinaryContentCases -or -not $_.PSObject.Properties['binaryContent'])
})
if (@($cases.id | Sort-Object -Unique).Count -ne $cases.Count) {
    throw 'Scenario identifiers must be unique.'
}
$hostBinary = $null
if ($IncludeBinaryCases -or $IncludeBinaryContentCases) {
    $hostBinary = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'dotnet\dotnet.exe'
    if (-not (Test-Path -LiteralPath $hostBinary -PathType Leaf)) {
        throw 'The installed .NET host was not found; no signed fixture can be prepared.'
    }
    if ($IncludeBinaryContentCases) {
        $sdk = & $hostBinary --list-sdks | Select-Object -Last 1
        if ($LASTEXITCODE -ne 0 -or $sdk -notmatch '^(\S+) \[(.+)\]$') {
            throw 'Binary content fixtures require an installed .NET SDK for compiling the benign netmodule.'
        }
        $compilerSdk = $Matches[1]
        $compiler = Join-Path $Matches[2] "$compilerSdk\Roslyn\bincore\csc.dll"
        if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) { throw 'The SDK C# compiler was not found.' }
    }
}

$inputs = Join-Path $output 'inputs'
$archives = Join-Path $output 'archives'
$null = New-Item -ItemType Directory -Path $inputs, $archives
if ($IncludeReferenceCatalogCases) {
    $catalogs = Join-Path $output 'catalogs'
    $null = New-Item -ItemType Directory -Path $catalogs
}
if ($IncludeBinaryContentCases) {
    $contentSources = Join-Path $output 'sources\binary-content'
    $null = New-Item -ItemType Directory -Path $contentSources
    $managedBinary = [System.Text.Json.JsonSerializer].Assembly.Location
    Copy-Item -LiteralPath $hostBinary -Destination (Join-Path $contentSources 'native.exe')
    Copy-Item -LiteralPath $managedBinary -Destination (Join-Path $contentSources 'managed.dll')
    $moduleSource = Join-Path $PSScriptRoot 'fixtures\binary-content\ModuleExample.cs'
    $modulePath = Join-Path $contentSources 'module.netmodule'
    $referenceAssembly = Join-Path ([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) 'System.Private.CoreLib.dll'
    & $hostBinary $compiler /nologo /noconfig /nostdlib+ /target:module /deterministic+ `
        "/reference:$referenceAssembly" "/out:$modulePath" $moduleSource
    if ($LASTEXITCODE -ne 0) { throw 'Could not compile the benign netmodule fixture.' }

    $nativeBytes = [IO.File]::ReadAllBytes((Join-Path $contentSources 'native.exe'))
    $peOffset = [BitConverter]::ToInt32($nativeBytes, 60)
    if ($nativeBytes.Length -lt 64 -or $nativeBytes[0] -ne 0x4D -or $nativeBytes[1] -ne 0x5A -or
        $peOffset -lt 64 -or $peOffset -gt $nativeBytes.Length - 24 -or
        [BitConverter]::ToUInt32($nativeBytes, $peOffset) -ne 0x4550) {
        throw 'The trusted installed host is not a suitable PE fixture.'
    }
    [IO.File]::WriteAllBytes((Join-Path $contentSources 'truncated.dat'), [byte[]]$nativeBytes[0..63])
    $invalidOffset = [byte[]]$nativeBytes.Clone()
    [Array]::Copy([BitConverter]::GetBytes([uint32]::MaxValue), 0, $invalidOffset, 60, 4)
    [IO.File]::WriteAllBytes((Join-Path $contentSources 'invalid-offset.dat'), $invalidOffset)
    $sectionLimit = [byte[]]$nativeBytes.Clone()
    [Array]::Copy([BitConverter]::GetBytes([uint16]97), 0, $sectionLimit, $peOffset + 6, 2)
    [IO.File]::WriteAllBytes((Join-Path $contentSources 'section-limit.dat'), $sectionLimit)

    # Read only the trusted, freshly compiled fixture, never a submitted binary.
    $moduleStream = [IO.File]::OpenRead($modulePath)
    $moduleReader = [System.Reflection.PortableExecutable.PEReader]::new($moduleStream)
    try {
        $metadataBytes = [byte[]]$moduleReader.GetMetadata().GetContent()
        [IO.File]::WriteAllBytes((Join-Path $contentSources 'metadata.dat'), $metadataBytes)
    }
    finally {
        $moduleReader.Dispose()
        $moduleStream.Dispose()
    }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'fixtures\customer\Customer.cs') `
        -Destination (Join-Path $contentSources 'text-control.cs')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'fixtures\headers\Header.cs') `
        -Destination (Join-Path $contentSources 'text-claim.cs')
    $contentProvenance = @{
        native = [ordered]@{
            kind = 'installed-binary'; fileName = 'dotnet.exe'
            fileVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($hostBinary).FileVersion
        }
        managed = [ordered]@{
            kind = 'installed-binary'; fileName = 'System.Text.Json.dll'
            fileVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($managedBinary).FileVersion
            installation = 'PowerShell runtime'
        }
        module = [ordered]@{
            kind = 'compiled-original-source'; sourceFile = 'fixtures/binary-content/ModuleExample.cs'
            sourceSha256 = (Get-FileHash -LiteralPath $moduleSource -Algorithm SHA256).Hash.ToLowerInvariant()
            compilerSdk = $compilerSdk
            referenceAssemblySha256 = (Get-FileHash -LiteralPath $referenceAssembly -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        truncated = [ordered]@{ kind = 'modified-copy'; derivedFrom = 'native.exe'; modification = 'First 64 bytes only.' }
        'invalid-offset' = [ordered]@{ kind = 'modified-copy'; derivedFrom = 'native.exe'; modification = 'e_lfanew replaced with uint32 maximum.' }
        'section-limit' = [ordered]@{ kind = 'modified-copy'; derivedFrom = 'native.exe'; modification = 'COFF NumberOfSections replaced with 97, above the 96-section inspection bound.' }
        metadata = [ordered]@{ kind = 'extracted-metadata'; derivedFrom = 'module.netmodule'; modification = 'Standalone CLR metadata, without its PE container.' }
        'text-control' = [ordered]@{ kind = 'original-text'; sourceFile = 'fixtures/customer/Customer.cs' }
        'text-claim' = [ordered]@{ kind = 'synthetic-ownership-declaration'; sourceFile = 'fixtures/headers/Header.cs' }
    }
}
foreach ($case in $cases) {
    if ($case.id -cnotmatch '^[a-z][a-z0-9-]*$') { throw 'Invalid scenario identifier.' }
    $destination = Join-Path $inputs $case.id
    $null = New-Item -ItemType Directory -Path $destination
    if ($case.PSObject.Properties['binaryContent']) {
        $selection = $case.binaryContent
        $sourceFile = Join-Path $contentSources $selection.sourceFile
        $fileNames = @('sample.dat', 'sample.txt', 'sample.cs', 'sample', 'LICENSE.txt')
        if ($selection.kind -ne 'NotPe') { $fileNames = @('sample.exe', 'sample.dll') + $fileNames }
        foreach ($fileName in $fileNames) {
            Copy-Item -LiteralPath $sourceFile -Destination (Join-Path $destination $fileName)
        }
        $selection | Add-Member -NotePropertyName fileNames -NotePropertyValue $fileNames
        $selection | Add-Member -NotePropertyName sha256 -NotePropertyValue (
            (Get-FileHash -LiteralPath $sourceFile -Algorithm SHA256).Hash.ToLowerInvariant())
        $selection | Add-Member -NotePropertyName byteLength -NotePropertyValue (Get-Item -LiteralPath $sourceFile).Length
        $provenance = $contentProvenance[$selection.variant]
        if ($provenance.Contains('derivedFrom')) {
            $provenance['sourceSha256'] = (Get-FileHash -LiteralPath (
                Join-Path $contentSources $provenance['derivedFrom']) -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        $selection | Add-Member -NotePropertyName provenance -NotePropertyValue $provenance
    }
    elseif ($case.PSObject.Properties['publicReference']) {
        $public = $case.publicReference
        $preparedProject = Join-Path $inputs $public.case
        Copy-Item -LiteralPath (Join-Path $preparedProject $public.path) -Destination $destination
        Copy-Item -LiteralPath (Join-Path $preparedProject 'LICENSE') -Destination $destination
        [IO.File]::WriteAllText((Join-Path $destination 'EXAMPLE-NOTES.txt'),
            "Local scan fixture derived from pinned public source. Variant: $($case.referenceCatalog.variant). " +
            'Edited, line-ending, and snippet variants are modified copies; do not execute them. ' +
            'See the parent manifest for the original repository, commit, file, and catalog.')
    }
    elseif ($case.PSObject.Properties['publicSource']) {
        $source = $case.publicSource
        if ($source.repository -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$' -or
            $source.commit -cnotmatch '^[a-f0-9]{40}$' -or
            $source.archiveSha256 -cnotmatch '^[a-f0-9]{64}$') {
            throw "Invalid pinned public source for $($case.id)."
        }
        $downloads = Join-Path $output 'sources'
        $null = New-Item -ItemType Directory -Path $downloads -Force
        $download = Join-Path $downloads "$($case.id).zip"
        $url = "https://codeload.github.com/$($source.repository)/zip/$($source.commit)"
        Invoke-WebRequest -Uri $url -OutFile $download -TimeoutSec 120 -MaximumRedirection 0
        if ((Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash.ToLowerInvariant() -cne
            $source.archiveSha256) {
            throw "Public source archive hash mismatch for $($case.id); nothing was extracted."
        }
        $rootName = "$(($source.repository -split '/')[1])-$($source.commit)"
        $zip = [IO.Compression.ZipFile]::OpenRead($download)
        try {
            if ($zip.Entries.Count -eq 0 -or @($zip.Entries | Where-Object {
                -not $_.FullName.StartsWith("$rootName/", [StringComparison]::Ordinal)
            }).Count -gt 0) {
                throw "Unexpected public source archive layout for $($case.id)."
            }
        }
        finally { $zip.Dispose() }
        [IO.Compression.ZipFile]::ExtractToDirectory($download, $destination)
        $root = Join-Path $destination $rootName
        Get-ChildItem -LiteralPath $root -Force | Move-Item -Destination $destination
        Remove-Item -LiteralPath $root
        if (-not (Test-Path -LiteralPath (Join-Path $destination $source.licenseFile) -PathType Leaf)) {
            throw "The public source license is missing for $($case.id)."
        }
    }
    else {
        foreach ($template in $case.templates) {
            if ($template -cnotmatch '^[a-z][a-z0-9-]*$') { throw 'Invalid template identifier.' }
            $source = Join-Path $PSScriptRoot "fixtures\$template"
            Copy-Item -Path (Join-Path $source '*') -Destination $destination -Recurse
        }
        Set-Content -LiteralPath (Join-Path $destination 'README.md') -Encoding utf8NoBOM -Value @"
# Synthetic scan input: $($case.id)

This is deliberately synthetic input, not copied product source or verified
ownership. Any origin or publisher declaration is test data.
Do not execute binary fixtures or publish/redistribute generated binaries.
Expected outcomes and limits are documented in the parent fixture repository.
"@
    }
    if ('headers' -in $case.templates) {
        $header = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures\headers\Header.cs'))
        [IO.File]::WriteAllText((Join-Path $destination 'Utf16Header.cs'), $header, [Text.Encoding]::Unicode)
    }
    if ($case.origin) {
        $git = Join-Path $destination '.git'
        $null = New-Item -ItemType Directory -Path $git
        Set-Content -LiteralPath (Join-Path $git 'config') -Encoding utf8NoBOM -Value @"
[remote "origin"]
    url = $($case.origin)
    pushurl = disabled://synthetic-ip-fixture
"@
    }
    if ($case.invalidText) {
        [IO.File]::WriteAllBytes((Join-Path $destination 'LICENSE'), [byte[]](0xC3, 0x28))
    }
    if ($case.PSObject.Properties['referenceCatalog']) {
        $selection = $case.referenceCatalog
        $reference = Join-Path $PSScriptRoot 'fixtures\catalog-reference\Lookup.cs'
        $sourceFile = Join-Path $destination 'Lookup.cs'
        $referenceUrl = 'urn:synthetic:catalog-reference:lookup'
        $provenance = 'Fabricated ownership for local testing only; not a real Microsoft asset.'
        if ($case.PSObject.Properties['publicReference']) {
            $public = $case.publicReference
            $reference = Join-Path (Join-Path $inputs $public.catalogCase) $public.catalogPath
            $sourceFile = Join-Path $destination ([IO.Path]::GetFileName($public.path))
            $upstream = ($cases | Where-Object id -CEQ $public.catalogCase).publicSource
            $referenceUrl = "https://github.com/$($upstream.repository)/blob/$($upstream.commit)/$($public.catalogPath)"
            $provenance = 'Exact bytes from pinned public source; local test attribution, not production ownership approval.'
        }
        $referenceBytes = [IO.File]::ReadAllBytes($reference)
        $referenceText = [IO.File]::ReadAllText($reference)
        $referenceHash = 'sha256:' + (Get-FileHash -LiteralPath $reference -Algorithm SHA256).Hash.ToLowerInvariant()
        $referenceRecord = [ordered]@{
            id = 'synthetic-reference'
            contentKind = 'source'
            sha256 = $referenceHash
            ownerIds = @('microsoft')
            ownerSetComplete = $false
            sourceReference = $referenceUrl
            provenance = $provenance
        }
        $records = @($referenceRecord)
        switch ($selection.variant) {
            'exact' {}
            'renamed' { Move-Item -LiteralPath $sourceFile -Destination (Join-Path $destination 'Renamed.dat') }
            'edited' { [IO.File]::WriteAllBytes($sourceFile, [byte[]]($referenceBytes + 0x0A)) }
            'line-endings' {
                $changed = if ($referenceText.Contains("`r`n")) { $referenceText.Replace("`r`n", "`n") }
                    else { $referenceText.Replace("`n", "`r`n") }
                [IO.File]::WriteAllText($sourceFile, $changed)
            }
            'snippet' {
                if ($case.PSObject.Properties['publicReference']) {
                    $lines = $referenceText -split "`r?`n"
                    $snippet = ($lines | Select-Object -Skip 58 -First 20) -join "`n"
                    [IO.File]::WriteAllText($sourceFile, $snippet + "`n")
                }
            }
            'unmatched' {}
            'missing' {}
            'invalid' {}
            'oversized' {}
            'empty' { $records = @() }
            'conflict' {
                $records += [ordered]@{
                    id = 'synthetic-conflicting-reference'
                    contentKind = 'source'
                    sha256 = $referenceHash
                    ownerIds = @('example-other-owner')
                    ownerSetComplete = $true
                    sourceReference = 'urn:synthetic:catalog-reference:conflict'
                    provenance = 'Deliberately conflicting synthetic ownership assertion.'
                }
            }
            default { throw "Unknown reference catalog variant: $($selection.variant)" }
        }
        $catalog = [ordered]@{
            schemaVersion = '1.0'
            catalogId = 'synthetic-scan-examples'
            version = '1'
            evidenceMode = 'synthetic-demo'
            records = $records
        } | ConvertTo-Json -Depth 10
        if ($selection.variant -eq 'invalid') { $catalog = '{}' }
        if ($selection.variant -eq 'oversized') {
            # Valid JSON, one byte beyond the current 2 MiB catalog limit.
            $catalog += ' ' * (2 * 1024 * 1024 + 1 - [Text.Encoding]::UTF8.GetByteCount($catalog))
        }
        $catalogPath = Join-Path $catalogs "$($case.id).json"
        if ($selection.variant -ne 'missing') { [IO.File]::WriteAllText($catalogPath, $catalog) }
        $selection | Add-Member -NotePropertyName path -NotePropertyValue "catalogs/$($case.id).json"
        $selection | Add-Member -NotePropertyName referenceSha256 -NotePropertyValue $referenceHash
    }
    switch ($case.binary) {
        'signed' {
            Copy-Item -LiteralPath $hostBinary -Destination (Join-Path $destination 'signed.exe')
        }
        { $_ -in @('unsigned', 'unsigned-uppercase') } {
            $fileName = if ($case.binary -eq 'unsigned-uppercase') { 'UNSIGNED.DLL' } else { 'unsigned.dll' }
            Add-Type -TypeDefinition 'namespace SyntheticFixture { public class Unsigned { public int Value => 42; } }' `
                -OutputAssembly (Join-Path $destination $fileName)
        }
        'catalog-only' {
            Copy-Item -LiteralPath (Join-Path ([Environment]::SystemDirectory) 'cmd.exe') `
                -Destination (Join-Path $destination 'catalog-only.exe')
        }
        'tampered' {
            $stream = [IO.File]::OpenRead($hostBinary)
            $reader = [System.Reflection.PortableExecutable.PEReader]::new($stream)
            try {
                $section = $reader.PEHeaders.SectionHeaders |
                    Where-Object SizeOfRawData -GT 128 | Select-Object -First 1
                if ($null -eq $section) { throw 'The signed host has no suitable hashed PE section.' }
                $offset = $section.PointerToRawData + 128
            }
            finally {
                $reader.Dispose()
                $stream.Dispose()
            }
            $bytes = [IO.File]::ReadAllBytes($hostBinary)
            $bytes[$offset] = $bytes[$offset] -bxor 1
            [IO.File]::WriteAllBytes((Join-Path $destination 'tampered.exe'), $bytes)
        }
        'combined' {
            Copy-Item -LiteralPath (Join-Path $inputs 'real-binary-unmapped\signed.exe'),
                (Join-Path $inputs 'unsigned-binary\unsigned.dll'),
                (Join-Path $inputs 'tampered-binary\tampered.exe') -Destination $destination
        }
        $null {}
        default { throw "Unknown binary fixture mode: $($case.binary)" }
    }
    $archive = Join-Path $archives "$($case.id).tar.gz"
    & tar -czf $archive -C $destination .
    if ($LASTEXITCODE -ne 0) { throw "Could not archive scenario $($case.id)." }
    $case | Add-Member -NotePropertyName archiveSha256 -NotePropertyValue (
        (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant())
}

[ordered]@{
    schemaVersion = 1
    preparedAtUtc = [DateTime]::UtcNow.ToString('O')
    binaryFixturesIncluded = [bool]$IncludeBinaryCases
    publicFixturesIncluded = [bool]$IncludePublicCases
    referenceCatalogFixturesIncluded = [bool]$IncludeReferenceCatalogCases
    binaryContentFixturesIncluded = [bool]$IncludeBinaryContentCases
    cases = $cases
} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $output 'manifest.json') -Encoding utf8NoBOM
Write-Host "Prepared $($cases.Count) independent inputs and archives at: $output"
Write-Host 'Preparation only. No detector, service scan, upstream code, or binary fixture was executed.'
if ($IncludePublicCases) {
    Write-Host 'Pinned public source archives were downloaded from GitHub and verified by SHA-256.'
}
else {
    Write-Host 'No remote requests were made.'
}
