from agilityshift.models import Finding
from agilityshift.ai.explain_template import TemplateExplanationEngine

class LLMExplanationEngine:
    # AI explanation is optional. LLM integration can be added later by extending this wrapper class
    # to hit local models like Ollama, keeping data completely offline.
    
    def __init__(self, provider: str = "none"):
        self.provider = provider
        self.template_engine = TemplateExplanationEngine()

    def explain_finding(self, finding: Finding) -> Finding:
        if self.provider == "none":
            # Fallback to the safe, offline template engine
            return self.template_engine.explain_finding(finding)
            
        # TODO: Implement local Ollama API call here in the future
        # e.g. response = requests.post("http://localhost:11434/api/generate", json={"prompt": ...})
        # finding.explanation = response.json()["response"]
        # finding.explanation_source = "ollama"
        
        return finding

    def explain_findings(self, findings: list[Finding]) -> list[Finding]:
        for finding in findings:
            self.explain_finding(finding)
        return findings
