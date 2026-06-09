# Limitations and Future Roadmap

## Limitations
- **Pattern-based detection:** The current iteration relies on Regex/AST-lite pattern matching, which may yield false positives on extremely customized abstractions.
- **Limited language support:** The current MVP strictly targets JavaScript/TypeScript, SQL, and OpenAPI contracts.
- **Does not perform real PQC migration:** The scanner flags issues; it does not auto-refactor the repository to use new PQC libraries.
- **Does not prove exploitability:** This is a breakage/resiliency scanner, not an exploitation tool.
- **Template explanation only:** Real local LLMs (like Ollama) are planned but currently mocked with a high-fidelity template engine.
- **Dashboard uses local data:** The React dashboard reads from a statically generated file rather than a persistent backend.

## Future Roadmap
- **Tree-sitter AST scanner:** Complete control flow graph integration.
- **Python/Java/Go/C# support:** Broaden language parsing.
- **SARIF export:** Native CI integration for GitHub Advanced Security.
- **CBOM export:** Cryptography Bill of Materials generation.
- **GitHub/GitLab/Jenkins integrations:** Full suite of plugins.
- **Enterprise dashboard:** Hosted or self-hosted multi-repo views.
- **On-prem deployment:** Containerized Kubernetes delivery.
- **Local LLM explanation:** `explain_llm.py` execution via Ollama/Llama3.
- **Generated PQC simulation tests:** Automatically inject massive payloads into test suites to break running applications.
- **Pull request comments:** Native bot integrations.
- **Multi-repo migration readiness map:** Global dependency graph mapping.
