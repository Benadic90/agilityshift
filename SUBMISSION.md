# SUBMISSION

**Project Name**: AgilityShift

**Category**: Cybersecurity / Developer Productivity / AI-assisted security / Post-quantum readiness

**Short Description**: AgilityShift is a local-first PQC migration breakage scanner that finds exact code, database, and API limits that may fail when companies migrate to post-quantum cryptography.

**Problem**: Organizations migrating to PQC may silently break applications because larger signatures, keys, certificates, or proofs exceed old fixed limits (e.g., `VARCHAR(256)`).

**Solution**: AgilityShift scans repositories, finds exact breakage points, calculates overflow ratios against target PQC algorithms (like ML-DSA), suggests fixes, explains the issue to management, generates standalone reports, and blocks unsafe CI/CD deployment.

**Impact**: Banks, fintech platforms, SaaS companies, and digital public infrastructure can prepare for PQC migration safely and transparently.

**What we built**:
- CLI scanner
- vulnerable bank demo app
- JS/TS detector
- SQL detector
- API schema detector
- PQC risk scoring
- suggested fixes
- template-based explanation
- JSON/HTML report
- CI/CD gate
- dashboard

**Final Pitch**: Existing tools tell you where crypto is. AgilityShift tells you where post-quantum migration will break your code.
