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

@dataclass
class ScanSummary:
    target_path: Path
    files_scanned: int
    supported_files: list[ScannedFile]
    skipped_files: int
