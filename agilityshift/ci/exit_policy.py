from agilityshift.models import Finding

class ExitPolicy:
    def __init__(self, fail_on: str | None = None):
        # CI/CD gates matter because they prevent unsafe PQC migration code from ever reaching production.
        # By evaluating severity before deployment, we enforce a shift-left security posture.
        self.fail_on = (fail_on or "none").lower()
        self.valid_severities = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        
        if self.fail_on not in self.valid_severities:
            raise ValueError(f"Invalid fail-on threshold: {self.fail_on}. Allowed values: none, low, medium, high, critical")
        
        self.threshold = self.valid_severities[self.fail_on]

    def _get_severity_value(self, severity_str: str) -> int:
        return self.valid_severities.get(severity_str.lower(), 0)

    def matching_findings(self, findings: list[Finding]) -> list[Finding]:
        if self.threshold == 0:
            return []
            
        # The severity threshold works by checking if a finding's severity integer mapped value
        # meets or exceeds the configured failure threshold level.
        return [f for f in findings if self._get_severity_value(f.severity) >= self.threshold]

    def should_fail(self, findings: list[Finding]) -> bool:
        return len(self.matching_findings(findings)) > 0

    def exit_code(self, findings: list[Finding]) -> int:
        # Exit code 1 is used to signal a failure to the CI/CD pipeline (e.g., GitHub Actions, Jenkins),
        # automatically terminating the workflow and blocking unsafe deployment.
        return 1 if self.should_fail(findings) else 0

    def summary_message(self, findings: list[Finding]) -> str:
        if self.threshold == 0:
            return "CI/CD Gate Result: PASSED\nFail-on threshold: NONE\nNo findings matched the failure threshold."
            
        matches = len(self.matching_findings(findings))
        
        if self.should_fail(findings):
            return (
                f"CI/CD Gate Result: FAILED\n"
                f"Fail-on threshold: {self.fail_on.upper()}\n"
                f"Matching findings: {matches}\n"
                f"Deployment blocked before production failure."
            )
        else:
            return (
                f"CI/CD Gate Result: PASSED\n"
                f"Fail-on threshold: {self.fail_on.upper()}\n"
                f"No findings matched the failure threshold."
            )
