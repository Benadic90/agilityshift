# Security and Privacy Model

## Principles
- **Local-first scanning**: Source code never leaves the developer's machine or CI/CD runner.
- **No source code upload required**: We do not rely on a SaaS backend to parse ASTs.
- **Works offline for core scan**: Once installed, the CLI operates completely offline.
- **Reports generated locally**: HTML and JSON artifacts are built dynamically in the user's filesystem.
- **AI explanation is template-based by default**: Generates robust explanations without sending snippets to OpenAI/Gemini.
- **CI/CD gate runs inside customer pipeline**: `--fail-on` operates securely within the enterprise boundary.

## Enterprise Future
- **On-prem deployment**: Containerized local deployments.
- **SSO/RBAC**: Role-based access for multi-tenant enterprise maps.
- **Audit logs**: Record of all accepted/ignored risks.
- **Encrypted reports**: At-rest protection for migration roadmaps.
- **Signed scanner releases**: Verification of CLI supply chain.
- **SBOM/SLSA**: Compliance for the scanner itself.
- **CBOM/SARIF**: Cryptographic export standard compliance.
