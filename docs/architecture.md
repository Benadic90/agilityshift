# Architecture

**CLI Scanner** → **Detectors** → **PQC Profile** → **Risk Scoring** → **Reports** → **CI Fail**

1. **CLI Scanner**: The Typer CLI entry point starts the scan.
2. **Detectors**: Modules analyze code, DB schemas, and OpenAPI contracts to find hardcoded limits.
3. **PQC Profile**: JSON definitions of PQC algorithms (like ML-DSA) provide the necessary sizes (e.g., 2420 bytes for ML-DSA-44).
4. **Risk Scoring**: Identifies the gap between current hardcoded limits and PQC requirements, assigning a risk score.
5. **Reports**: Generates JSON, HTML, or SARIF output.
6. **CI Fail**: An exit policy determines whether to fail the CI/CD pipeline based on the risk score (e.g., critical).
