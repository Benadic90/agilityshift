# AgilityShift

Find where post-quantum cryptography migration will break your code before production fails.

> "Existing tools tell you where crypto is. AgilityShift tells you where post-quantum migration will break your code."

## What is AgilityShift?
AgilityShift is a local-first Post-Quantum Cryptography (PQC) migration breakage scanner. It deeply analyzes source code, database schemas, and API contracts to find hardcoded size limits that will shatter when you swap old cryptography for large post-quantum algorithms.

## Why this matters
The Problem: Post-quantum migration is coming. As organizations prepare for quantum-safe cryptography, they must transition to algorithms like ML-DSA. However, legacy applications have hidden size assumptions—such as `Buffer.alloc(256)`, `VARCHAR(256)`, or `maxLength: 256`—that implicitly expect tiny RSA or ECDSA artifacts.
The Solution: AgilityShift acts as a pre-migration safety scanner. It highlights exactly where your architecture will silently break, calculates overflow ratios against formal PQC profiles, and suggests remediation strategies.

## Demo Story
Imagine a vulnerable banking API (`examples/vulnerable-bank-api`). It works fine today, but uses hardcoded 256-byte limits for its signatures. Running AgilityShift uncovers 13 distinct breakage points across the frontend JS, the database SQL, and the OpenAPI contract—generating an interactive security dashboard and actionable HTML reports to guide the migration.

## MVP Status
✅ Local CLI scanner
✅ JS/TS detector
✅ SQL schema detector
✅ OpenAPI/YAML/JSON detector
✅ PQC profile and risk scoring
✅ Suggested fix engine
✅ Template security explanation
✅ JSON and HTML reports
✅ CI/CD failure gate
✅ Interactive dashboard

## Features
✅ **Local CLI scanner**: Offline first, no source code upload.
✅ **JS/TS detector**: Catches `Buffer.alloc` and string length assumptions.
✅ **SQL schema detector**: Identifies constrictive `VARCHAR`/`BLOB` fields.
✅ **OpenAPI/YAML/JSON detector**: Detects constrictive `maxLength` bounds.
✅ **PQC profile and risk scoring**: Calculates precise overflow ratios (e.g. 12.93x) against targets like `ML-DSA-65`.
✅ **Suggested fix engine**: Provides remediation code patterns.
✅ **Template security explanation**: Translates obscure constraints into developer guidance and manager summaries.
✅ **JSON and HTML reports**: Robust enterprise output tracking.
✅ **CI/CD failure gate**: Block deployments before risky bounds hit production.
✅ **Interactive dashboard**: React/Tailwind visual triage.

## Tech Stack
- **Core Engine:** Python 3.11, Typer (CLI), Rich (UI), Jinja2 (HTML Generation).
- **Dashboard:** React, Vite, Tailwind CSS.

## Architecture
See [docs/architecture.md](docs/architecture.md) for full pipeline flow.

## Quick Start

### 1. Install Scanner
```bash
pip install -e .
```

### 2. Run Scanner
Run the basic scan:
```bash
agilityshift scan ./examples/vulnerable-bank-api
```

### 3. Generate ReportDisable explanations:
```bash
agilityshift scan ./examples/vulnerable-bank-api --no-explain
```

Explain:
For enterprise safety, AgilityShift uses template-based explanations by default. Future versions may support local LLMs such as Ollama, but the core scanner does not require internet or cloud AI.

## Phase 13: SARIF Export

AgilityShift can export findings in SARIF format for code scanning workflows.

Commands:
```bash
agilityshift scan ./examples/vulnerable-bank-api --report sarif

agilityshift scan ./examples/vulnerable-bank-api --report all
```

Generated file:
`agilityshift-report.sarif`

Explain:
SARIF export helps integrate AgilityShift findings into DevSecOps workflows such as GitHub code scanning.

### 4. CI/CD Failure Gate
Block deployments if CRITICAL issues are discovered:
```bash
agilityshift scan ./examples/vulnerable-bank-api --report all --fail-on critical
```

### 5. Launch Interactive Dashboard
```bash
cd dashboard
npm install
npm run dev
```

### 6. Run Test Suite
```bash
pytest
```

## Example Findings
AgilityShift locates limits like `const sigBuffer = Buffer.alloc(256);` and outputs:
- **Severity**: CRITICAL
- **Required Size**: 3309 bytes (`ML-DSA-65`)
- **Overflow Ratio**: 12.93x
- **Remediation**: Use dynamic decoding and validate against a configurable PQC policy.

## Security and Privacy Model
- **Local-first scanning**: Your code never leaves your machine. No cloud API calls are required to scan or evaluate risk.
- **CI/CD native**: The engine runs inside your private build environment.

## Limitations
- Uses advanced pattern-based detection which may yield false positives.
- Supports a limited subset of languages (JS/TS, SQL schemas, API YAML).

## Future Roadmap
- AST parsing via Tree-sitter for complex data-flow tracing.
- Native SARIF and CBOM (Cryptography Bill of Materials) export.
- Local LLM explanation engine via Ollama.

## Hackathon Demo Script
Check out [demo_script.md](demo_script.md) for our 4-minute presentation guide.

## License
MIT License.
