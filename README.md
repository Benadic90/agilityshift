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

