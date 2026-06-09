# CBOM-style Crypto Inventory Export

## What is a CBOM?
A Cryptography Bill of Materials (CBOM) is an extension of the SBOM concept. It provides a machine-readable inventory of cryptographic assets (algorithms, keys, certificates, protocols) used within a software system. This is crucial for planning Post-Quantum Cryptography (PQC) migrations.

## Why AgilityShift uses a CBOM-style export
While AgilityShift's core focus is on structural constraints (like hardcoded size limits), these constraints are intimately tied to cryptographic usage. Emitting a CBOM allows organizations to map these breakage risks directly to their cryptographic inventory, providing a holistic view of what needs updating.

## What data is included
The `agilityshift-cbom.json` includes:
- **Tool and Target Metadata**: Identifies AgilityShift and the target PQC profile.
- **Crypto Assets**: Extracted entities representing digital signatures, keys, certificates, tokens, or proofs.
- **Inferred Algorithms**: Where detectable (e.g., `RS256`, `ECDSA`, `ML-DSA`).
- **Location Context**: File and line number linking the asset back to the source code.
- **Migration Risk**: Detail on the PQC required sizing and the overflow severity.

## How to generate the file
Pass the `--report cbom` or `--report all` flag to the CLI.

## Example command
```bash
agilityshift scan ./examples/vulnerable-bank-api --report cbom
```

## Current limitations
The current export relies on inference rather than deep formal cryptographic control-flow analysis. It is "CycloneDX-inspired" meaning it captures the spirit and schema shape of the standard but is intentionally labeled as experimental to avoid false compliance claims.

## Future upgrade to full CycloneDX CBOM compatibility
In future releases, we plan to conform strictly to the CycloneDX v1.6+ specifications for native integration into enterprise SBOM management platforms.
