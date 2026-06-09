import json
from pathlib import Path
from dataclasses import asdict
from agilityshift.models import PQCProfile, ScanSummary, Finding

class JSONReportWriter:
    def build_report_data(
        self,
        target_path: Path,
        profile: PQCProfile,
        scan_summary: ScanSummary,
        findings: list[Finding],
        readiness_score: int,
        severity_summary: dict[str, int]
    ) -> dict:
        # Structured reports matter for integrating with CI/CD, SIEMs, or other automated security tooling.
        # JSON is universally useful for tools because it maps naturally to structured objects without parsing regex.
        # Findings are safely serialized via dataclass mapping into native dict representations.
        return {
            "tool": {
                "name": "AgilityShift",
                "version": "0.1.0",
                "description": "PQC migration breakage scanner"
            },
            "scan": {
                "target_path": str(target_path),
                "target_profile": profile.name,
                "required_signature_size": profile.signature_bytes,
                "files_scanned": scan_summary.files_scanned,
                "skipped_files": scan_summary.skipped_files,
                "readiness_score": readiness_score
            },
            "severity_summary": severity_summary,
            "findings": [asdict(f) for f in findings]
        }

    def write_report(
        self,
        output_path: Path,
        target_path: Path,
        profile: PQCProfile,
        scan_summary: ScanSummary,
        findings: list[Finding],
        readiness_score: int,
        severity_summary: dict[str, int]
    ) -> Path:
        data = self.build_report_data(
            target_path=target_path,
            profile=profile,
            scan_summary=scan_summary,
            findings=findings,
            readiness_score=readiness_score,
            severity_summary=severity_summary
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return output_path
