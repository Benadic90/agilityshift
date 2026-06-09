from agilityshift.models import Finding, PQCProfile

class RiskScorer:
    def __init__(self, profile: PQCProfile):
        self.profile = profile
        
    def score_findings(self, findings: list[Finding]) -> list[Finding]:
        return [self.score_finding(f) for f in findings]
        
    def score_finding(self, finding: Finding) -> Finding:
        finding.pqc_profile = self.profile.name
        
        # If the limit isn't a direct number, we can't mathematically calculate an overflow ratio.
        # Assign a default review severity.
        if finding.current_limit is None:
            finding.overflow_ratio = None
            finding.readiness_penalty = 5
            finding.risk_message = "This finding uses a non-numeric or indirect limit. Manual review is required."
            return finding
            
        finding.required_size = self.profile.signature_bytes
        
        # Calculate how many times larger the required PQC size is compared to the current limit
        ratio = finding.required_size / finding.current_limit
        finding.overflow_ratio = round(ratio, 2)
        
        # Severity is assigned based on the overflow ratio to distinguish between minor size bumps and catastrophic breakage
        if finding.overflow_ratio <= 1.0:
            finding.severity = "LOW"
            finding.readiness_penalty = 2
            finding.risk_message = "Current limit appears large enough for this target profile, but manual review is still recommended."
        elif finding.overflow_ratio <= 3.0:
            finding.severity = "MEDIUM"
            finding.readiness_penalty = 5
            finding.risk_message = "Target PQC size is larger than the current limit. Review and increase this limit."
        elif finding.overflow_ratio <= 8.0:
            finding.severity = "HIGH"
            finding.readiness_penalty = 10
            finding.risk_message = f"{self.profile.name} requires {self.profile.signature_bytes} bytes, which is {finding.overflow_ratio}x larger than the current {finding.current_limit} {finding.limit_unit} limit. This is a high migration breakage risk."
        else:
            finding.severity = "CRITICAL"
            finding.readiness_penalty = 20
            finding.risk_message = f"{self.profile.name} requires {self.profile.signature_bytes} bytes, which is {finding.overflow_ratio}x larger than the current {finding.current_limit} {finding.limit_unit} limit. This may break during PQC migration."
            
        if finding.limit_unit == "characters":
            finding.risk_message += " Note: Character limits may differ from byte limits depending on encoding."
            
        return finding
        
    def calculate_readiness_score(self, findings: list[Finding]) -> int:
        # A readiness score provides a high-level KPI indicating how close the system is to being PQC-ready.
        total_penalty = sum(f.readiness_penalty for f in findings)
        score = 100 - total_penalty
        return max(0, min(100, score))
        
    def summarize_severity(self, findings: list[Finding]) -> dict[str, int]:
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            if f.severity in summary:
                summary[f.severity] += 1
            else:
                summary[f.severity] = 1
        return summary
