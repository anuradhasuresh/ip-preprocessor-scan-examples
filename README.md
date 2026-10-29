# IP Preprocessor Scan Examples

Portable synthetic inputs for exercising an IP-admission preprocessor. This
repository contains no scanner implementation, private SDK dependency, copied
product source, credentials, or generated binaries.

Ownership and origin declarations in the fixtures are deliberately fabricated
test data. They are not verified ownership statements or evidence of a real
source-code leak.

## Prepare scan inputs

Requires PowerShell 7 and `tar`. From this repository:

```powershell
.\Prepare-ScanInputs.ps1
```

This prepares six source-only scenarios under `artifacts`. To prepare all ten,
including local binary cases, use Windows with the .NET host installed:

```powershell
.\Prepare-ScanInputs.ps1 -IncludeBinaryCases -OutputDirectory .\artifacts\with-binaries
```

The script refuses to overwrite an existing output directory. Choose a new
`-OutputDirectory` when repeating preparation.

## Run a scan

**Scan one prepared scenario, not the entire fixture repository.** The whole
collection deliberately contains blocking declarations, so scanning it cannot
demonstrate the clean control.

Use your scanner's supported directory or bundle input:

- Directory: `artifacts\inputs\<scenario>`
- Bundle: `artifacts\archives\<scenario>.tar.gz`

For the binary suite, these paths are under `artifacts\with-binaries` instead.
Every archive places the scenario at its root, without a wrapper directory.
The output `manifest.json` records the selected scenarios and archive SHA-256
hashes. The raw `fixtures` directory contains reusable fragments, not the
complete prepared scenario set.

Preparation does not run a detector, submit a scan, execute the example binaries,
or make remote Git requests. Expected outcomes are fixture metadata, not scan
results. Check actual behavior with your approved scanner.

## Scenarios and expected outcomes

`scenarios.json` contains exact expected statuses, recommendation labels,
evidence rules, and platform-specific outcomes for the reference behavior.

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

The reference behavior cannot verify Authenticode on Linux. Otherwise-clean
binary cases are therefore unassessed there, not cleared. Independent blocking
text/origin evidence still stops processing. Continuing means only that this
admission check permits further processing; it is not a safety clearance.

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

Do not execute or redistribute the generated binary samples. No signer pins,
certificate allowlists, trust-store changes, or verified first-party binary
classification are supplied by this repository.

`.gitignore` excludes the default prepared-input directory, archives, SARIF
reports, binaries, and build outputs. Keep generated data under `artifacts`;
do not force-add it to Git.

Repository licensing is defined in [LICENSE](LICENSE). Declarations inside
`fixtures\legal` and `fixtures\headers` are synthetic test content, not additional
license grants. These fixtures are development examples, not held-out
evaluation data.