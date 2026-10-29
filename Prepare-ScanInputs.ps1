#Requires -Version 7.0
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'artifacts'),
    [switch]$IncludeBinaryCases
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$PSNativeCommandUseErrorActionPreference = $false

$output = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
if (Test-Path -LiteralPath $output) {
    throw "OutputDirectory already exists; choose a new directory: $output"
}
if ($IncludeBinaryCases -and -not $IsWindows) {
    throw 'Generating the real Authenticode fixtures requires Windows.'
}
$null = Get-Command tar -ErrorAction Stop
$manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'scenarios.json') -Raw | ConvertFrom-Json
if ($manifest.schemaVersion -ne 1) { throw 'Unsupported scenario manifest version.' }
$cases = @($manifest.cases | Where-Object { $IncludeBinaryCases -or -not $_.binary })
if (@($cases.id | Sort-Object -Unique).Count -ne $cases.Count) {
    throw 'Scenario identifiers must be unique.'
}
$hostBinary = $null
if ($IncludeBinaryCases) {
    $hostBinary = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'dotnet\dotnet.exe'
    if (-not (Test-Path -LiteralPath $hostBinary -PathType Leaf)) {
        throw 'The installed .NET host was not found; no signed fixture can be prepared.'
    }
}

$inputs = Join-Path $output 'inputs'
$archives = Join-Path $output 'archives'
$null = New-Item -ItemType Directory -Path $inputs, $archives
foreach ($case in $cases) {
    if ($case.id -cnotmatch '^[a-z][a-z0-9-]*$') { throw 'Invalid scenario identifier.' }
    $destination = Join-Path $inputs $case.id
    $null = New-Item -ItemType Directory -Path $destination
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
    switch ($case.binary) {
        'signed' {
            Copy-Item -LiteralPath $hostBinary -Destination (Join-Path $destination 'signed.exe')
        }
        'unsigned' {
            Add-Type -TypeDefinition 'namespace SyntheticFixture { public class Unsigned { public int Value => 42; } }' `
                -OutputAssembly (Join-Path $destination 'unsigned.dll')
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
    cases = $cases
} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $output 'manifest.json') -Encoding utf8NoBOM
Write-Host "Prepared $($cases.Count) independent inputs and archives at: $output"
Write-Host 'Preparation only. No detector, service scan, remote request, or binary fixture was executed.'
