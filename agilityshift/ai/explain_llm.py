import logging
import requests
from agilityshift.models import Finding
from agilityshift.ai.explain_template import TemplateExplanationEngine

logger = logging.getLogger(__name__)

class LLMExplanationEngine:
    def __init__(self, provider: str = "none", ollama_model: str = "llama3", ollama_url: str = "http://localhost:11434"):
        self.provider = provider
        self.ollama_model = ollama_model
        self.ollama_url = ollama_url.rstrip('/')
        self.template_engine = TemplateExplanationEngine()

    def _generate_prompt(self, finding: Finding) -> str:
        return f"""You are a senior DevSecOps engineer. Explain the following security finding in 2-3 sentences.
Focus on why this specific code pattern will fail during a Post-Quantum Cryptography migration.

Rule: {finding.rule_id}
Title: {finding.title}
File: {finding.file_path}:{finding.line_number}
Code snippet: {finding.line_text}
Suggested Fix: {finding.suggestion}
"""

    def explain_finding(self, finding: Finding) -> Finding:
        if self.provider == "none":
            # Fallback to the safe, offline template engine
            return self.template_engine.explain_finding(finding)
            
        if self.provider == "ollama":
            try:
                response = requests.post(
                    f"{self.ollama_url}/api/generate",
                    json={
                        "model": self.ollama_model,
                        "prompt": self._generate_prompt(finding),
                        "stream": False
                    },
                    timeout=10
                )
                response.raise_for_status()
                data = response.json()
                
                finding.explanation = data.get("response", "").strip()
                finding.explanation_source = "ollama_local"
            except Exception as e:
                logger.warning(f"Failed to generate explanation with Ollama ({e}). Falling back to template.")
                return self.template_engine.explain_finding(finding)

        return finding

    def explain_findings(self, findings: list[Finding]) -> list[Finding]:
        for finding in findings:
            self.explain_finding(finding)
        return findings
