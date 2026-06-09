# SARIF Export

## What is SARIF?
SARIF (Static Analysis Results Interchange Format) is an industry-standard JSON-based format for outputting static analysis results. It's widely used by platforms like GitHub Code Scanning and GitLab SAST.

## Why AgilityShift exports SARIF
By exporting SARIF, AgilityShift can seamlessly plug into enterprise DevSecOps pipelines. This allows post-quantum migration risks to be visualized natively alongside standard security vulnerabilities directly inside developer pull requests or security dashboards.

## How to generate SARIF
Use the `--report sarif` or `--report all` flag in the CLI:

## Example command
```bash
agilityshift scan ./examples/vulnerable-bank-api --report sarif
```

## What data is included
The `agilityshift-report.sarif` output contains:
- **Tool Information**: Identified as `AgilityShift`.
- **Rules**: A unique schema of all the PQC limits mapped during the scan.
- **Results**: The actual findings mapping rule IDs to physical locations (file paths and line numbers).
- **Severity Levels**: Auto-mapped from AgilityShift's risk engine (e.g., `CRITICAL` -> `error`).
- **Remediation**: Included as Markdown-compatible messages indicating the precise PQC threshold overflow and suggested fix.

## Limitations
- The current export strictly maps to SARIF 2.1.0 baseline.
- It does not automatically upload to GitHub (this requires the GitHub CodeQL action).

## Future GitHub code scanning upload support
In future versions, we intend to provide native GitHub Action bindings to seamlessly upload the generated SARIF reports directly to the GitHub Advanced Security tab.
