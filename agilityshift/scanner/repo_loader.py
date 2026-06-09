from pathlib import Path
from agilityshift.models import ScannedFile, ScanSummary

class RepoLoader:
    SUPPORTED_EXTENSIONS = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
        ".sql", ".yaml", ".yml", ".json", ".toml", ".prisma"
    }

    IGNORED_DIRS = {
        ".git", "node_modules", "venv", ".venv", "env",
        "__pycache__", "dist", "build", "coverage", ".next",
        ".cache", ".idea", ".vscode"
    }

    IGNORED_FILES = {
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "poetry.lock", "Pipfile.lock"
    }

    def __init__(self, target_path: Path):
        self.target_path = target_path

    def validate_path(self):
        if not self.target_path.exists():
            raise FileNotFoundError(f"Target path does not exist: {self.target_path}")

    def should_ignore_path(self, path: Path) -> bool:
        if path.name in self.IGNORED_DIRS and path.is_dir():
            return True
        if path.name in self.IGNORED_FILES and path.is_file():
            return True
        # Also check if any parent is an ignored directory
        for part in path.parts:
            if part in self.IGNORED_DIRS:
                return True
        return False

    def is_supported_file(self, path: Path) -> bool:
        return path.suffix.lower() in self.SUPPORTED_EXTENSIONS

    def load_files(self) -> ScanSummary:
        self.validate_path()
        
        supported_files = []
        skipped_files = 0
        total_scanned = 0

        paths_to_scan = []
        if self.target_path.is_file():
            paths_to_scan.append(self.target_path)
        else:
            paths_to_scan = list(self.target_path.rglob("*"))

        for path in paths_to_scan:
            if not path.is_file():
                continue
                
            if self.should_ignore_path(path):
                continue
                
            total_scanned += 1
            
            if not self.is_supported_file(path):
                skipped_files += 1
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()
                
                try:
                    # Attempt to get relative path to target_path, if target_path is a dir
                    if self.target_path.is_dir():
                        relative_path = str(path.relative_to(self.target_path))
                    else:
                        relative_path = path.name
                except ValueError:
                    relative_path = str(path)
                
                scanned_file = ScannedFile(
                    path=path,
                    relative_path=relative_path,
                    extension=path.suffix.lower(),
                    line_count=len(lines),
                    content=content,
                    lines=lines
                )
                supported_files.append(scanned_file)
            except Exception:
                skipped_files += 1

        return ScanSummary(
            target_path=self.target_path,
            files_scanned=total_scanned,
            supported_files=supported_files,
            skipped_files=skipped_files
        )
