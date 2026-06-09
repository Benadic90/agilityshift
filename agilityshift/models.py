from dataclasses import dataclass
from pathlib import Path

@dataclass
class ScannedFile:
    path: Path
    relative_path: str
    extension: str
    line_count: int
    content: str
    lines: list[str]

@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    file_path: str
    line_number: int
    line_text: str
    current_limit: int | None
    limit_unit: str
    finding_type: str
    severity: str
    confidence: str
    suggestion: str
    pqc_profile: str | None = None
    required_size: int | None = None
    overflow_ratio: float | None = None
    readiness_penalty: int = 0
    risk_message: str | None = None
    fix_title: str | None = None
    fix_description: str | None = None
    suggested_fix: str | None = None
    safe_example: str | None = None
    manual_review_required: bool = True
    fix_confidence: str | None = None

@dataclass
class ScanSummary:
    target_path: Path
    files_scanned: int
    supported_files: list[ScannedFile]
    skipped_files: int

@dataclass
class PQCProfile:
    name: str
    signature_bytes: int
    level: int
    type: str
    description: str

@dataclass
class ReportSummary:
    target_path: str
    target_profile: str
    required_size: int
    files_scanned: int
    skipped_files: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    readiness_score: int
