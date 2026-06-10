import subprocess
import os
from pathlib import Path
from datetime import datetime
from rich.console import Console

from agilityshift.models import Finding

console = Console()

class PRGenerator:
    def __init__(self, target_repo: Path):
        self.target_repo = target_repo

    def run_cmd(self, cmd: list[str]) -> str:
        result = subprocess.run(cmd, cwd=self.target_repo, capture_output=True, text=True)
        if result.returncode != 0:
            console.print(f"[red]Command failed: {' '.join(cmd)}[/red]\n{result.stderr}")
        return result.stdout.strip()

    def generate_pr(self, findings: list[Finding]):
        if not findings:
            console.print("[yellow]No findings to auto-fix.[/yellow]")
            return

        branch_name = f"pqc-autofix-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        console.print(f"[cyan]Creating new branch {branch_name}...[/cyan]")
        self.run_cmd(["git", "checkout", "-b", branch_name])

        files_changed = False

        for finding in findings:
            if not finding.file_path:
                continue

            file_full_path = self.target_repo / finding.file_path
            if not file_full_path.exists():
                continue

            try:
                lines = file_full_path.read_text(encoding="utf-8").splitlines()
                idx = finding.line_number - 1

                if 0 <= idx < len(lines):
                    original_line = lines[idx]
                    
                    # Very simple string-replacement logic for a hackathon demo
                    # Ideally, this would use Ollama or an AST unparser.
                    new_line = original_line
                    if "MAX_SIGNATURE_SIZE" in original_line:
                        new_line = original_line.replace(str(finding.current_limit), "config.crypto.maxSignatureBytes")
                    elif "MAX_PUBLIC_KEY_SIZE" in original_line:
                        new_line = original_line.replace(str(finding.current_limit), "config.crypto.maxPublicKeyBytes")
                    elif "len(signature) >" in original_line or "len(public_key) >=" in original_line:
                        new_line = original_line.replace(str(finding.current_limit), "config.crypto.maxSignatureBytes")
                    elif "signature[:" in original_line or "token[:" in original_line:
                        # Don't truncate
                        new_line = original_line.replace(f"[:{finding.current_limit}]", "")
                    elif "TOKEN_MAX_LEN" in original_line:
                        new_line = original_line.replace(str(finding.current_limit), "config.crypto.maxTokenBytes")

                    if new_line != original_line:
                        # Prepend a config import if it's the first time
                        if not hasattr(self, 'config_injected'):
                            lines.insert(0, "import agilityshift_config as config # Auto-injected PQC policy")
                            self.config_injected = True
                            idx += 1 # Shift index since we inserted at top

                        lines[idx] = new_line
                        file_full_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                        files_changed = True
                        console.print(f"[green]Applied auto-fix to {finding.file_path}:{finding.line_number}[/green]")
            except Exception as e:
                console.print(f"[red]Failed to modify {finding.file_path}: {str(e)}[/red]")

        if not files_changed:
            console.print("[yellow]Could not automatically apply any fixes. PR aborted.[/yellow]")
            self.run_cmd(["git", "checkout", "-"])
            self.run_cmd(["git", "branch", "-D", branch_name])
            return

        console.print("[cyan]Committing changes...[/cyan]")
        self.run_cmd(["git", "add", "."])
        self.run_cmd(["git", "commit", "-m", "Auto-fix PQC cryptographic limits for migration readiness"])

        console.print("[cyan]Generating Pull Request summary...[/cyan]")
        pr_title = "Security: Auto-fix PQC Cryptographic Limits"
        pr_body = (
            "## AgilityShift Automated PQC Fixes\n\n"
            "This PR automatically replaces hardcoded cryptographic limits with dynamic policies based on the `ML-DSA-65` target profile.\n\n"
            "### Findings Addressed:\n"
        )
        for f in findings:
            pr_body += f"- `{f.rule_id}` in `{f.file_path}:{f.line_number}`\n"
            
        pr_body += "\n*Powered by AgilityShift Auto-Fix Engine.*"

        # Attempt to push and create PR using gh cli if available, otherwise just leave the branch ready.
        try:
            console.print("[cyan]Attempting to create PR using 'gh' CLI...[/cyan]")
            # In a real environment, this pushes to origin. Since this is a local hackathon demo,
            # we might just simulate it or do a local commit. We will try gh, but fail gracefully.
            self.run_cmd(["git", "push", "-u", "origin", branch_name])
            res = subprocess.run(["gh", "pr", "create", "--title", pr_title, "--body", pr_body], cwd=self.target_repo, capture_output=True, text=True)
            if res.returncode == 0:
                console.print(f"[bold green]PR Created Successfully![/bold green]\n{res.stdout.strip()}")
            else:
                console.print("[yellow]gh CLI not configured or no remote. Changes committed locally.[/yellow]")
                console.print(f"Branch: {branch_name}")
        except Exception as e:
            console.print(f"[yellow]Could not run gh CLI: {str(e)}. Changes are on local branch {branch_name}.[/yellow]")

