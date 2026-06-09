import typer
from pathlib import Path
from rich.console import Console
from rich.table import Table

from agilityshift.pqc.profile_loader import PQCProfileLoader
from agilityshift.risk.scorer import RiskScorer
from agilityshift.fixes.suggestions import SuggestionEngine

app = typer.Typer(add_completion=False)
console = Console()

@app.callback()
def callback():
    pass

@app.command()
def scan(
    path: Path = typer.Argument(None, help="Path to repository to scan"),
    target_profile: str = typer.Option("ML-DSA-65", "--target-profile", help="Target PQC profile"),
    list_profiles: bool = typer.Option(False, "--list-profiles", help="List available PQC profiles"),
    show_fixes: bool = typer.Option(True, "--show-fixes/--no-show-fixes", help="Show fix suggestions")
):
    """
    AgilityShift local-first PQC migration breakage scanner.
    """
    try:
        loader = PQCProfileLoader()
        if list_profiles:
            profiles = loader.list_profile_names()
            console.print("Available PQC profiles:")
            for p in profiles:
                console.print(f"- {p}")
            raise typer.Exit()
            
        if not path:
            console.print("[bold red]Error:[/bold red] Missing argument 'PATH'.")
            raise typer.Exit(1)
            
        profile = loader.get_profile(target_profile)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        raise typer.Exit(1)

    console.print("[bold cyan]AgilityShift scanner starting...[/bold cyan]")
    console.print(f"Target path: {path}")
    console.print(f"Target PQC profile: {profile.name}")
    console.print(f"Required signature size: {profile.signature_bytes} bytes\n")

    from agilityshift.scanner.repo_loader import RepoLoader
    repo = RepoLoader(path)
    try:
        repo.validate_path()
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/bold red] Target path does not exist: {path}")
        raise typer.Exit(code=1)
        
    summary = repo.load_files()

    console.print("[bold]Scan Summary[/bold]")
    console.print(f"Files scanned: {summary.files_scanned}")
    if summary.skipped_files > 0:
        console.print(f"Skipped files: {summary.skipped_files}")

    console.print("\n[bold]Supported files[/bold]")
    table = Table(show_header=False, box=None)
    for idx, f in enumerate(summary.supported_files):
        table.add_row(str(idx + 1), f.relative_path, f.extension, str(f.line_count))
    console.print(table)
    console.print()

    from agilityshift.scanner.limit_detector import JavaScriptLimitDetector
    from agilityshift.scanner.db_schema_detector import SQLSchemaDetector
    from agilityshift.scanner.api_schema_detector import APISchemaDetector
    
    js_detector = JavaScriptLimitDetector()
    sql_detector = SQLSchemaDetector()
    api_detector = APISchemaDetector()
    
    findings = js_detector.detect(summary.supported_files)
    findings.extend(sql_detector.detect(summary.supported_files))
    findings.extend(api_detector.detect(summary.supported_files))

    scorer = RiskScorer(profile)
    findings = scorer.score_findings(findings)
    
    suggester = SuggestionEngine()
    findings = suggester.suggest_for_findings(findings)

    console.print(f"Findings found: {len(findings)}\n")

    if not findings:
        console.print("[bold green]No JavaScript, SQL, or API fixed-limit findings detected.[/bold green]")
    else:
        sev_summary = scorer.summarize_severity(findings)
        console.print("[bold]Severity Summary[/bold]")
        for sev, count in sev_summary.items():
            if count > 0:
                color = "bold red" if sev == "CRITICAL" else "red" if sev == "HIGH" else "yellow" if sev == "MEDIUM" else "cyan"
                console.print(f"[{color}]{sev}: {count}[/{color}]")
                
        readiness = scorer.calculate_readiness_score(findings)
        r_color = "bold red" if readiness < 50 else "yellow" if readiness < 80 else "bold green"
        console.print(f"\n[bold]PQC Migration Readiness Score:[/bold] [{r_color}]{readiness}/100[/{r_color}]\n")

        console.print("[bold]Findings table:[/bold]")
        ftable = Table(show_header=True, box=None)
        ftable.add_column("Severity")
        ftable.add_column("Type")
        ftable.add_column("Rule")
        ftable.add_column("File")
        ftable.add_column("Line")
        ftable.add_column("Limit")
        ftable.add_column("Required")
        ftable.add_column("Ratio")
        ftable.add_column("Code")
        
        for f in findings:
            sev_color = "bold red" if f.severity == "CRITICAL" else "red" if f.severity == "HIGH" else "yellow" if f.severity == "MEDIUM" else "cyan"
            lim_str = f"{f.current_limit} {f.limit_unit}" if f.current_limit is not None else "N/A"
            req_str = str(f.required_size) if f.required_size is not None else "N/A"
            ratio_str = f"{f.overflow_ratio}x" if f.overflow_ratio is not None else "N/A"
            
            ftable.add_row(
                f"[{sev_color}]{f.severity}[/{sev_color}]",
                f.finding_type,
                f.rule_id,
                f.file_path,
                str(f.line_number),
                lim_str,
                req_str,
                ratio_str,
                f.line_text
            )
        console.print(ftable)
        
        if show_fixes:
            console.print("\n[bold]Suggested Fixes[/bold]\n")
            for f in findings:
                sev_color = "bold red" if f.severity == "CRITICAL" else "red" if f.severity == "HIGH" else "yellow" if f.severity == "MEDIUM" else "cyan"
                console.print(f"[{sev_color}][{f.severity}][/{sev_color}] {f.file_path}:{f.line_number}")
                console.print(f"Rule: {f.rule_id}")
                console.print(f"Fix: {f.fix_title}")
                console.print(f"Suggestion: {f.suggested_fix}")
                mr = "yes" if f.manual_review_required else "no"
                console.print(f"Manual review required: {mr}\n")

    console.print()
    console.print("Phase 7 complete:")
    console.print("Suggested fix engine is active.")
    console.print("Reports will be added in Phase 8.")

if __name__ == "__main__":
    app()
