# Vulnerable Bank API
**AgilityShift Test Target**

This is an intentionally vulnerable repository designed to demonstrate how legacy cryptography size assumptions will break during Post-Quantum Cryptography (PQC) migration.

## Vulnerabilities Showcased
- **JS/TS Layer**: `Buffer.alloc(256)`, `signature.substring(0, MAX_SIZE)`
- **SQL Layer**: `VARCHAR(256)`, `BLOB` constrictions.
- **API Layer**: OpenAPI YAML/JSON `maxLength: 256` bounds.

## How to Scan
From the root of the AgilityShift project, run:
```bash
agilityshift scan ./examples/vulnerable-bank-api --explain
```
