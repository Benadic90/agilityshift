# Judge Q&A

**Q1. Why is this problem real?**
**A.** PQC migration is becoming necessary as organizations prepare for quantum-safe cryptography. Larger cryptographic artifacts can easily break old app limits built around tiny RSA and ECDSA models.

**Q2. How is this different from normal crypto scanners?**
**A.** Normal scanners show where crypto is used (e.g., "AES-256 used here"). AgilityShift shows where migration will *break* the code, database, and API layers (e.g., "Your auth validation maxLength will reject ML-DSA keys").

**Q3. Does this implement PQC?**
**A.** No. It is a pre-migration safety scanner. It helps teams structurally prepare their apps *before* changing algorithms.

**Q4. Why local-first?**
**A.** Enterprises and banks cannot upload private source code to cloud tools due to compliance.

**Q5. What is the MVP?**
**A.** CLI scanner, 3-layer detection (JS, SQL, OpenAPI), risk scoring, remediation suggestions, explanations, reports, dashboard, and CI/CD gate.

**Q6. What are the limitations?**
**A.** MVP uses pattern-based detection and supports limited languages. Future versions will add deeper AST inspection, SARIF, CBOM, and more languages.

**Q7. Why can this become a startup?**
**A.** PQC migration will affect almost every digitized organization over the next decade. Standard crypto-inventory tooling doesn't fix structural breakage, creating a massive need for dedicated migration-readiness tooling.
