# Completed Phases of AgilityShift

The following capabilities, tools, and phases have been fully completed and integrated into AgilityShift:

## MVP & Core Engine
- **Local CLI Scanner:** Offline-first architecture requiring no source code upload.
- **JS/TS Detector:** AST-based detection of `Buffer.alloc` and string length assumptions.
- **SQL Schema Detector:** Detection of constrictive `VARCHAR`/`BLOB` fields.
- **OpenAPI/YAML/JSON Detector:** Detection of constrictive `maxLength` bounds and request body limits.
- **PQC Profile and Risk Scoring:** Precise overflow ratio calculations against profiles like `ML-DSA-65`.
- **Suggested Fix Engine:** Remediation code pattern generator.

## Explanations & UI
- **Phase 11 (Template Security Explanation):** Template-based AI explanation layer translating obscure constraints into actionable developer and manager summaries.
- **Interactive Dashboard:** React/Tailwind visual triage.

## Reporting & DevSecOps Integration
- **JSON and HTML Reports:** Robust enterprise output tracking.
- **CI/CD Failure Gate:** Block deployments before risky bounds hit production based on configurable risk severity.
- **Phase 13 (SARIF Export):** Export findings in SARIF format for DevSecOps pipelines and GitHub code scanning.
- **Phase 14 (CBOM Export):** CycloneDX-inspired experimental Cryptography Bill of Materials export for PQC migration readiness.
