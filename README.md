# AgilityShift

AgilityShift is a local-first Post-Quantum Cryptography migration breakage scanner. It scans code, database schemas, and API contracts to find exact file-line limits that may break during PQC migration.

> “Existing tools tell you where crypto is. AgilityShift tells you where post-quantum migration will break your code.”

## MVP Goal
Provide a minimal viable scanner that identifies hardcoded limitations (like `maxLength: 256` or `VARCHAR(256)`) that might break when migrating to PQC algorithms with larger keys and signatures.

## Demo
Run the scanner on the vulnerable demo bank app:
```bash
agilityshift scan ./examples/vulnerable-bank-api --report html --fail-on critical
```

## Current Status
Phase 0 and Phase 1 setup.
Phase 2 scanner foundation is active.

## Phase 3: JavaScript/TypeScript Fixed-Limit Detector

Current detector supports:
- `Buffer.alloc(number)`
- `Buffer.allocUnsafe(number)`
- crypto-like length checks
- crypto-like truncation
- crypto-size constants

Example:
```bash
agilityshift scan ./examples/vulnerable-bank-api
```

## Phase 4: SQL Database Schema Scanner

Current SQL detector supports:
- `signature VARCHAR(number)`
- `public_key VARCHAR(number)`
- `certificate VARCHAR(number)`
- `jwt_token VARCHAR(number)`
- `attestation_proof VARCHAR(number)`
- crypto-related `CHAR` / `VARCHAR` / `NVARCHAR` / `VARBINARY` limits

Example:
```bash
agilityshift scan ./examples/vulnerable-bank-api
```

This helps detect database storage limits that may break when cryptographic signatures, keys, certificates, or proofs become larger during post-quantum migration.

## Phase 5: OpenAPI / YAML / JSON API Contract Scanner

Current API detector supports:
- `signature maxLength`
- `publicKey maxLength`
- `certificate maxLength`
- `token/jwt maxLength`
- `proof/attestation maxLength`
- basic small request body limits

Example:
```bash
agilityshift scan ./examples/vulnerable-bank-api
```

This helps detect API validation limits that may reject larger post-quantum signatures, keys, certificates, or proofs during migration.

## Phase 6: PQC Profile + Risk Scoring

Current features:
- Target PQC profile support
- Default profile: `ML-DSA-65`
- Required signature size comparison
- Overflow ratio calculation
- Severity scoring
- PQC migration readiness score

Example:
```bash
agilityshift scan ./examples/vulnerable-bank-api --target-profile ML-DSA-65
```

Example result:
- Current limit: 256 bytes
- Required size: 3309 bytes
- Overflow ratio: 12.93x
- Severity: CRITICAL

## Phase 7: Suggested Fix Engine

Current features:
- Safe fix suggestions for code limits
- Safe fix suggestions for SQL storage limits
- Safe fix suggestions for API maxLength limits
- Manual review required for all fixes
- No automatic production patching

Example command:
```bash
agilityshift scan ./examples/vulnerable-bank-api --show-fixes
```

AgilityShift does not auto-patch production code. It generates reviewable suggestions so developers and security teams can safely plan PQC migration changes.

## Phase 8: JSON + HTML Reports

Current report support:
- JSON report for tools and automation
- HTML report for security teams, judges, and developers
- Summary cards
- Severity breakdown
- PQC readiness score
- Exact file-line findings
- Suggested fixes

Example commands:
```bash
agilityshift scan ./examples/vulnerable-bank-api --report json
agilityshift scan ./examples/vulnerable-bank-api --report html
agilityshift scan ./examples/vulnerable-bank-api --report all
```

Expected generated files:
- `agilityshift-report.json`
- `agilityshift-report.html`

## Phase 9: CI/CD Failure Gate

Current CI/CD features:
- `--fail-on` threshold
- Supported thresholds: `none`, `low`, `medium`, `high`, `critical`
- Exit code 1 when matching findings exist
- GitHub Actions workflow
- Reports still generate before failure

Example:
```bash
agilityshift scan ./examples/vulnerable-bank-api --report all --fail-on critical
```

Expected result:
```text
CI/CD Gate Result: FAILED
Deployment blocked before production failure.
```
This makes AgilityShift useful in CI/CD because teams can block unsafe PQC migration changes before production deployment.

### GitHub Actions

See `.github/workflows/agilityshift.yml` for the standard integration workflow. The demo workflow intentionally fails because the example vulnerable API contains critical findings.
