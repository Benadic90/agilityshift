from agilityshift.models import Finding

class TemplateExplanationEngine:
    # Cloud AI should not receive private source code by default because of corporate security policies.
    # A template-first explanation is safer since it guarantees offline, fast, and compliant insights.
    
    def _format_size_context(self, finding: Finding) -> str:
        parts = []
        if finding.required_size is not None:
            parts.append(f"During migration to {finding.pqc_profile}, cryptographic material may require around {finding.required_size} {finding.limit_unit}.")
        else:
            parts.append("The target PQC size was not available for this finding.")
            
        if finding.current_limit is not None:
            parts.append(f"The current limit is {finding.current_limit} {finding.limit_unit}.")
            
        if finding.overflow_ratio is not None:
            parts.append(f"This is {finding.overflow_ratio}x larger than the current limit.")
        else:
            parts.append("The exact overflow ratio could not be calculated because the limit is indirect or non-numeric.")
            
        return " ".join(parts)

    def _get_char_warning(self, finding: Finding) -> str:
        if finding.limit_unit and "char" in finding.limit_unit.lower():
            return " Character limits may not equal byte limits depending on encoding, so this should be validated with real payloads."
        return ""

    def explain_finding(self, finding: Finding) -> Finding:
        # Explanation templates are selected based on finding_type, ensuring relevant and context-aware guidance.
        size_context = self._format_size_context(finding)
        char_warning = self._get_char_warning(finding)
        
        if finding.finding_type == "code_limit":
            finding.explanation = (
                f"This line contains a fixed code-level size assumption for cryptographic material. "
                f"{size_context} This can cause verification failure, truncation, or runtime errors.{char_warning}"
            )
            finding.developer_guidance = "Remove hardcoded fixed limits. Use dynamic decoding and validate against a configurable PQC policy. Review with the security team."
            finding.manager_summary = "This code path may break during PQC migration because it assumes cryptographic material stays small."
            
        elif finding.finding_type == "database_schema":
            finding.explanation = (
                f"This database column may be too small for post-quantum algorithms. "
                f"{size_context} This can cause insert failure, truncation, storage rejection, or data corruption.{char_warning}"
            )
            finding.developer_guidance = "Migrate column to TEXT, BYTEA, VARBINARY, BLOB, or a larger size. Plan database migration carefully, test with PQC-sized payloads, and avoid silent truncation."
            finding.manager_summary = "This database schema may block PQC migration because it stores cryptographic material in a small fixed-size field."
            
        elif finding.finding_type == "api_contract":
            finding.explanation = (
                f"This API validation rule may reject larger PQC signatures, keys, or certificates because the maxLength is too small. "
                f"{size_context} This can cause valid requests to be rejected before reaching business logic.{char_warning}"
            )
            finding.developer_guidance = "Increase maxLength based on the target PQC profile. Make the limit configurable, validate explicitly and safely, and update API docs and client SDKs."
            finding.manager_summary = "This API contract may reject valid PQC-era requests because its validation limit is too small."
            
        else:
            finding.explanation = (
                f"This finding may represent a PQC migration breakage risk and should be reviewed against the selected target PQC profile. "
                f"{size_context}{char_warning}"
            )
            finding.developer_guidance = "Review the line, its current limit, and its relationship to cryptographic signatures, keys, certificates, tokens, or proofs."
            finding.manager_summary = "Manual review is required to confirm this migration risk."

        finding.explanation_source = "template"
        return finding

    def explain_findings(self, findings: list[Finding]) -> list[Finding]:
        for finding in findings:
            self.explain_finding(finding)
        return findings
