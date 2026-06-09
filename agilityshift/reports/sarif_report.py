import json
from pathlib import Path
from agilityshift.models import Finding

class SARIFReportWriter:
    def _severity_to_level(self, severity: str) -> str:
        s = severity.upper()
        if s in ["CRITICAL", "HIGH"]:
            return "error"
        elif s == "MEDIUM":
            return "warning"
        elif s == "LOW":
            return "note"
        return "warning"

    def _build_rules(self, findings: list[Finding]) -> list[dict]:
        rules_dict = {}
        for finding in findings:
            if finding.rule_id not in rules_dict:
                rules_dict[finding.rule_id] = {
                    "id": finding.rule_id,
                    "name": finding.title,
                    "shortDescription": {
                        "text": finding.title
                    },
                    "fullDescription": {
                        "text": finding.description
                    },
                    "help": {
                        "text": finding.suggested_fix if finding.suggested_fix else finding.description
                    }
                }
        return list(rules_dict.values())

    def _finding_to_result(self, finding: Finding) -> dict:
        msg_parts = [finding.title]
        if finding.risk_message:
            msg_parts.append(finding.risk_message)
        if finding.suggested_fix:
            msg_parts.append(f"Suggested fix: {finding.suggested_fix}")
        
        message_text = " ".join(msg_parts)
        
        return {
            "ruleId": finding.rule_id,
            "level": self._severity_to_level(finding.severity),
            "message": {
                "text": message_text
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path
                        },
                        "region": {
                            "startLine": finding.line_number
                        }
                    }
                }
            ]
        }

    def build_sarif(self, findings: list[Finding]) -> dict:
        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AgilityShift",
                            "informationUri": "https://github.com/Benadic90/agilityshift",
                            "rules": self._build_rules(findings)
                        }
                    },
                    "results": [self._finding_to_result(f) for f in findings]
                }
            ]
        }

    def write_report(self, output_path: Path, findings: list[Finding]) -> Path:
        sarif_data = self.build_sarif(findings)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif_data, f, indent=2)
        return output_path
