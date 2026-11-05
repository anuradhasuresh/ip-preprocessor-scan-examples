# IP Preprocessor Scan Examples

Portable synthetic inputs, opt-in installed binaries, and real public-project snapshots for exercising
an IP-admission preprocessor. Tracked files contain no scanner implementation,
private SDK dependency, copied product source, credentials, or generated binaries.

Ownership and origin declarations in the synthetic fixtures are deliberately fabricated
test data. They are not verified ownership statements or evidence of a real
source-code leak.

## Prepare scan inputs

Requires PowerShell 7 and `tar`. From this repository:

```powershell
.\Prepare-ScanInputs.ps1
```

This prepares eleven synthetic source-only scenarios under `artifacts`. To prepare
all eighteen synthetic/local-binary scenarios, use Windows with the .NET host installed:

```powershell
.\Prepare-ScanInputs.ps1 -IncludeBinaryCases -OutputDirectory .\artifacts\with-binaries
```

To also download the two real public-project scenarios:

```powershell
.\Prepare-ScanInputs.ps1 -IncludePublicCases -OutputDirectory .\artifacts\with-public-projects
```

This prepares thirteen scenarios. Combine `-IncludePublicCases` and
`-IncludeBinaryCases` for all twenty.

The script refuses to overwrite an existing output directory. Choose a new
`-OutputDirectory` when repeating preparation.

## Run a scan

Use your scanner's supported directory or bundle input:

- Directory: `artifacts\inputs\<scenario>`
- Bundle: `artifacts\archives\<scenario>.tar.gz`

For the binary suite, these paths are under `artifacts\with-binaries` instead.
Every archive places the scenario at its root, without a wrapper directory.
The output `manifest.json` records the selected scenarios and archive SHA-256
hashes. The raw `fixtures` directory contains reusable fragments, not the
complete prepared scenario set.

Preparation does not run a detector, submit a scan, or execute upstream code or
example binaries. Only `-IncludePublicCases` makes network requests: HTTPS
downloads of pinned GitHub source archives. Expected outcomes are fixture
metadata, not scan results. Check actual behavior with your approved scanner.

## Real public-project examples

| Scenario | Upstream project | License | Expected gate outcome |
| --- | --- | --- | --- |
| `public-microsoft-powershellforgithub` | [microsoft/PowerShellForGitHub](https://github.com/microsoft/PowerShellForGitHub/tree/fd4fa65f23ca30f18f85312a85348e660c287a9c) | MIT | Stop: actual Microsoft copyright declarations in the license and source headers |
| `public-serilog` | [serilog/serilog](https://github.com/serilog/serilog/tree/43105b35095337d77f022561a8f2d3db2f9a7937) | Apache-2.0 | Continue: no matching Microsoft ownership declarations |

These use upstream GitHub source archives, not rewritten excerpts. Preparation verifies
the pinned download SHA-256 before extraction and retains upstream file contents,
including README, licenses, and notices. Only GitHub's archive wrapper directory is
removed. `sources` retains the downloaded ZIPs; `manifest.json` records upstream
repository, commit, license, download hash, and generated bundle hash. Downloads
and prepared copies remain Git-ignored under `artifacts`.

No `.git` metadata is fabricated for these projects, so these cases exercise legal
and source-header detection, not catalog-origin matching. The Serilog snapshot
includes `assets/Serilog.snk`, a non-text strong-name key file. The source-header
check records `InvalidTextEncoding` with `NotApplicable` and no review requirement
for that file; the project's overall recommendation remains Continue.

Microsoft open-source code is legitimately public. A Stop here demonstrates the
current Microsoft-IP admission policy, not a license violation or evidence of
leaked proprietary code. Neither project establishes binary Authenticode identity
or a vulnerability-scanning result.

## Scenarios and expected outcomes

`scenarios.json` contains exact expected statuses, recommendation labels,
evidence rules, and platform-specific outcomes for the reference behavior.
`expected` and `signatureStatuses` describe Windows. For configured Linux
verification, use `linuxExpected` and `linuxSignatureStatuses` when present,
otherwise the common expectations. `nonWindowsExpected` retains the fallback
for platforms without a supported verifier; it does not override Linux support.

| Scenario | Expected gate outcome | Purpose |
| --- | --- | --- |
| `customer` | Continue | Ordinary namespace/package-name strings and product URLs are not ownership evidence |
| `license-claim` | Stop | Root and nested legal declarations, including SPDX |
| `header-claim` | Stop | Leading copyright/authorship, SPDX, and UTF-16 source headers |
| `catalog-origin-claim` | Stop when Git metadata is retained | Synthetic literal catalog-origin declaration |
| `combined-signals` | Stop | Independent legal, header, and origin declarations |
| `incomplete-text` | Unassessed | Invalid UTF-8 bytes in a legal document |
| `real-binary-unmapped` | Continue on Windows | Valid signature without a reviewed first-party signer mapping |
| `unsigned-binary` | Continue on Windows | A tiny synthetic unsigned DLL |
| `tampered-binary` | Continue on Windows | A modified signed-file copy without a reviewed signer mapping |
| `combined-with-binaries` | Stop | Independent blocking declarations remain effective alongside binary checks |
| `body-mention-only` | Continue | A quoted declaration inside code is not a leading authorship header |
| `license-code-name` | Continue | `License.cs` is source code, not a whole-file legal document |
| `nested-legal-only` | Stop | A nested notice is detected even without a root license declaration |
| `origin-lookalike` | Continue | A Microsoft organization or repository-name prefix is not an exact catalog match |
| `header-with-incomplete-text` | Stop, with incomplete coverage reported | Positive header evidence is retained alongside an unreadable legal document |
| `catalog-only-binary` | Continue on Windows; Unassessed on Linux | Windows catalog trust does not establish a Linux embedded signature |
| `unsigned-uppercase-dll` | Continue on Windows; Unassessed on Linux | The `.DLL` selector is case-insensitive |
| `header-with-unsigned-binary` | Stop, with incomplete Linux coverage reported | Blocking header evidence takes priority over an unsigned binary's coverage gap |

The Linux POC verifies embedded Authenticode signatures and supported timestamps
using its packaged native verifier and explicit offline trust. Linux expectations
assume the signed host's chain and timestamp are trusted, but its signer has no
reviewed first-party mapping. A valid but unmapped signer remains unassessed;
unsigned, catalog-only and tampered inputs also cannot become clearance.
Independent blocking text/origin evidence still stops processing, while incomplete
coverage remains visible. Continuing is not a safety clearance.

## Exact SHA-256 reference-catalog cases

Prepare ten additional source-only cases without downloading anything:

```powershell
.\Prepare-ScanInputs.ps1 -IncludeReferenceCatalogCases `
  -OutputDirectory .\artifacts\sha256-catalog
```

This prepares 21 cases: the existing eleven source-only cases plus these ten.
The original reusable code lives in `fixtures\catalog-reference\Lookup.cs`;
`fixtures\catalog-snippet\Snippet.cs` contains just its method. No sample code
needs to be compiled or executed.

| Case | Expected advisory result |
| --- | --- |
| `hash-exact` | One exact-byte match |
| `hash-renamed` | Same match after renaming to `.dat` |
| `hash-edited` | No match after appending one byte |
| `hash-line-endings` | No match after changing line endings between LF and CRLF |
| `hash-snippet-only` | No match: whole-file hashes do not identify copied snippets |
| `hash-missing-catalog` | Unavailable, not a clean negative |
| `hash-invalid-catalog` | Unavailable |
| `hash-empty-catalog` | Completed with no matches; no ownership conclusion |
| `hash-conflicting-owners` | One match with conflicting ownership and an unknown Microsoft claim |
| `hash-oversized-catalog` | Unavailable at the current 2 MiB limit |

`catalogs` contains separately supplied JSON catalogs; `manifest.json` identifies
the catalog path and expected outcome for each case. The missing-catalog path is
deliberately absent. Catalogs are **outside** every input directory and archive:
never submit a catalog as part of the untrusted scan input. The reference digest
comes from the original fixture, not from each submitted variation.

Every ownership assertion is marked `synthetic-demo`. A fabricated Microsoft
owner tests matching only; it is not evidence that the snippet belongs to
Microsoft. All ten cases must preserve the baseline `ContinueMDASH` disposition.
Hash matches do not enable scan skipping.

Configure the approved worker with the selected catalog, then scan the individual
prepared directory or archive. Record actual assessments separately under
`artifacts\sha256-catalog\reports` and compare against a catalog-disabled run of
the same input. Inspect catalog identity, match paths, conflicts, coverage errors,
and unchanged admission. Expected values in the manifest are **not assessments**.
The oversized case must be revisited if the catalog byte limit changes.

### Real public-source hash examples

```powershell
.\Prepare-ScanInputs.ps1 -IncludePublicCases -IncludeReferenceCatalogCases `
  -OutputDirectory .\artifacts\sha256-public
```

This prepares 29 cases, including six public-source hash cases. The original
Microsoft reference is `GitHubMiscellaneous.ps1` from the pinned
PowerShellForGitHub revision above. The nonmatching control is `src/Serilog/Log.cs`
from the pinned Serilog revision. The original upstream licenses are retained
in every derived input. Sources stay in ignored generated artifacts, not tracked
fixture files; no upstream code is executed.

`public-hash-exact` and `public-hash-renamed` must match. The edited,
line-ending, snippet-only, and Serilog-control cases must not. The snippet is
lines 59-78 of the pinned Microsoft file, not a standalone executable script.
`EXAMPLE-NOTES.txt` identifies derived/modified copies. Catalog records link to
the exact upstream commit and file; the manifest links each input to its verified
public-project snapshot.

The Microsoft cases already Stop because their retained license declares
Microsoft copyright, even with no catalog. The Serilog control Continues.
Compare catalog-enabled and disabled assessments: the new hash check must not
change either baseline. Public source bytes are real, but catalog attribution
remains explicitly test-only (`synthetic-demo`), not a production ownership approval.

## Filename-independent binary examples

On Windows with PowerShell 7, `tar`, and an installed .NET SDK:

```powershell
.\Prepare-ScanInputs.ps1 -IncludeBinaryContentCases `
  -OutputDirectory .\artifacts\binary-content
```

This prepares twenty scenarios: the eleven default source cases plus nine content
cases below. The switch is independent of `-IncludeBinaryCases` and can be
combined with the other switches. It makes no downloads. Only the original
`fixtures\binary-content\ModuleExample.cs` is compiled; none of the fixture
binaries or source controls is loaded or executed.

| Case | Actual input | Expected content/check |
| --- | --- | --- |
| `content-native-pe` | Installed `dotnet.exe`, unchanged | `NativePe`; signature assessment |
| `content-managed-assembly` | Installed PowerShell runtime `System.Text.Json.dll`, unchanged | `ManagedPe`; signature assessment |
| `content-managed-netmodule` | Original benign C# compiled with `/target:module` | `ManagedPe`; signature assessment; unsigned |
| `content-truncated-pe` | First 64 bytes of the real native host | `Malformed`; review required |
| `content-invalid-pe-offset` | Host copy with an out-of-file PE-header offset | `Malformed`; review required |
| `content-section-limit` | Host copy declaring 97 sections, above the current 96-section bound | `LimitExceeded`; review required |
| `content-standalone-metadata` | Actual metadata extracted from the compiled netmodule, without its PE container | `UnsupportedManaged`; review required |
| `content-text-control` | Original customer code with technology references, no ownership declaration | Text checks remain active; Continue |
| `content-text-claim` | Original synthetic Microsoft-header declaration | Text checks remain active; Stop |

Each of the seven binary/metadata cases contains **identical bytes** named
`sample.exe`, `sample.dll`, `sample.dat`, `sample.txt`, `sample.cs`, `sample`, and
`LICENSE.txt`. The two text controls use the last five names; `.dll`/`.exe` text
is intentionally not included because legacy extension-based eligibility remains
supported. There are 59 filename variants in total. Submit one case at a time.

`sources\binary-content` retains the canonical inputs outside all scan bundles.
The prepared manifest records each case's SHA-256, byte length, filenames,
installed file version or compiler/source provenance, and parent hash for modified
copies. Installed bytes vary by machine; the captured hash, not a filename or
publisher string, identifies this run's input. Netmodules are valid managed PE
files but are not assemblies; both intentionally report `ManagedPe`.

Use the content-selection implementation, not the older filename-only selector.
Check actual reports separately under `artifacts\binary-content\reports`: every
alias must have the same content classification and signature outcome, and none
of these binary aliases may enter source-header or legal-text checks. The native
and managed Windows expectations assume the existing empty signer policy; format
recognition must not establish first-party ownership or change admission.
Signature status for installed binaries is observed, not pinned in the manifest.

This suite targets the separately developed content selector. It does **not**
assume the Linux Authenticode implementation has been integrated: on a runtime
without supported verification, valid PE files must remain Unsupported/Unassessed.
Malformed, unsupported, or limit-exceeding inputs must not become clearance.
The section-limit fixture needs updating if that bound changes. These fixtures
do not test OS sandboxing, hard memory caps, or deployed upload-client retention.

## Choosing a real submission path

Submit an individual prepared scenario, not this entire fixture repository.
Enable and configure your scanner's admission checks separately, including any
required signature-verification trust settings.

Upload clients may exclude binary extensions, build directories, or Git metadata.
Use a supported directory or prebuilt-bundle path that demonstrably retains the
intended files. Verify what reaches the scanner rather than assuming every local
file is included.

Source-only scenarios can exercise declaration and negative-control behavior
without binary support. Do not equate admission inspection with DLL vulnerability
scanning. The prepared archive hashes identify these local artifacts; they do not
implement end-to-end immutable input enforcement.

## Synthetic origin metadata

Origin scenarios create a literal `.git\config` pointing at the public VS Code
catalog entry, with pushing disabled. No upstream code is cloned and no Git
command or hook is executed. This tests recognition of a self-declared origin,
not authentic repository provenance.

Some upload clients strip `.git` metadata, so those clients cannot demonstrate
this signal. Use the legal/header cases for metadata-free input. A `git archive`
of this repository does not reproduce the prepared origin fixtures; use the
preparation script.

## Binary and publication limits

Optional binary fixtures are produced only on your machine:

- The signed sample is copied from the installed .NET host.
- The unsigned DLL is compiled from a tiny synthetic class.
- The tampered sample changes a byte in a hashed PE section.
- The catalog-only sample is copied from the installed Windows `cmd.exe`;
  verify the expected catalog result on the preparation machine.
- The uppercase-extension sample is another locally compiled unsigned DLL.

Do not execute or redistribute the generated binary samples. No signer pins,
certificate allowlists, trust-store changes, or verified first-party binary
classification are supplied by this repository.

`.gitignore` excludes the default prepared-input directory, archives, SARIF
reports, binaries, and build outputs. Keep generated data under `artifacts`;
do not force-add it to Git.

Repository licensing is defined in [LICENSE](LICENSE). Downloaded public projects
retain their own upstream licenses and notices. Declarations inside
`fixtures\legal` and `fixtures\headers` are synthetic test content, not additional
license grants. These fixtures are development examples, not held-out
evaluation data.