import typer
from pathlib import Path
from rich.console import Console
from rich.table import Table
from typing import Any

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
    show_fixes: bool = typer.Option(True, "--show-fixes/--no-show-fixes", help="Show fix suggestions"),
    report: str = typer.Option("none", "--report", help="Report format to generate (none, json, html, sarif, cbom, all)"),
    output_dir: Path | None = typer.Option(None, "--output-dir", help="Directory to save reports in"),
    fail_on: str = typer.Option("none", "--fail-on", help="CI/CD failure threshold (none, low, medium, high, critical)"),
    explain: bool = typer.Option(True, "--explain/--no-explain", help="Generate AI/template explanations for findings"),
    explain_mode: str = typer.Option("template", "--explain-mode", help="Explanation engine to use (template, none)"),
    use_ollama: bool = typer.Option(True, "--use-ollama", help="Use local Ollama for AI explanations"),
    ollama_model: str = typer.Option("qwen2.5-coder:0.5b", "--ollama-model", help="Ollama model to use"),
    ollama_url: str = typer.Option("http://localhost:11434", "--ollama-url", help="Ollama API URL")
):
    """
    AgilityShift local-first PQC migration breakage scanner.
    """
    try:
        from agilityshift.ci.exit_policy import ExitPolicy
        exit_policy = ExitPolicy(fail_on)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        raise typer.Exit(1)

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
    from agilityshift.scanner.python_limit_detector import PythonLimitDetector
    from agilityshift.scanner.db_schema_detector import SQLSchemaDetector
    from agilityshift.scanner.api_schema_detector import APISchemaDetector
    
    js_detector = JavaScriptLimitDetector()
    py_detector = PythonLimitDetector()
    sql_detector = SQLSchemaDetector()
    api_detector = APISchemaDetector()
    
    findings = js_detector.detect(summary.supported_files)
    findings.extend(py_detector.detect(summary.supported_files))
    findings.extend(sql_detector.detect(summary.supported_files))
    findings.extend(api_detector.detect(summary.supported_files))

    scorer = RiskScorer(profile)
    findings = scorer.score_findings(findings)
    
    suggester = SuggestionEngine()
    findings = suggester.suggest_for_findings(findings)

    if explain and (explain_mode in ["template", "none"] or use_ollama):
        from agilityshift.ai.explain_template import TemplateExplanationEngine
        from agilityshift.ai.explain_llm import LLMExplanationEngine
        
        engine: Any = None
        if use_ollama:
            engine = LLMExplanationEngine(provider="ollama", ollama_model=ollama_model, ollama_url=ollama_url)
        elif explain_mode == "none":
            engine = LLMExplanationEngine(provider="none")
        else:
            engine = TemplateExplanationEngine()
            
        findings = engine.explain_findings(findings)

    console.print(f"Findings found: {len(findings)}\n")

    if not findings:
        console.print("[bold green]No JavaScript, Python, SQL, or API fixed-limit findings detected.[/bold green]")
        readiness = 100
        sev_summary = {}
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
        
        for finding in findings:
            sev_color = "bold red" if finding.severity == "CRITICAL" else "red" if finding.severity == "HIGH" else "yellow" if finding.severity == "MEDIUM" else "cyan"
            lim_str = f"{finding.current_limit} {finding.limit_unit}" if finding.current_limit is not None else "N/A"
            req_str = str(finding.required_size) if finding.required_size is not None else "N/A"
            ratio_str = f"{finding.overflow_ratio}x" if finding.overflow_ratio is not None else "N/A"
            
            ftable.add_row(
                f"[{sev_color}]{finding.severity}[/{sev_color}]",
                finding.finding_type,
                finding.rule_id,
                finding.file_path,
                str(finding.line_number),
                lim_str,
                req_str,
                ratio_str,
                finding.line_text
            )
        console.print(ftable)
        
        if show_fixes:
            console.print("\n[bold]Suggested Fixes[/bold]\n")
            for finding in findings:
                sev_color = "bold red" if finding.severity == "CRITICAL" else "red" if finding.severity == "HIGH" else "yellow" if finding.severity == "MEDIUM" else "cyan"
                console.print(f"[{sev_color}][{finding.severity}][/{sev_color}] {finding.file_path}:{finding.line_number}")
                console.print(f"Rule: {finding.rule_id}")
                console.print(f"Fix: {finding.fix_title}")
                console.print(f"Suggestion: {finding.suggested_fix}")
                mr = "yes" if finding.manual_review_required else "no"
                console.print(f"Manual review required: {mr}\n")
                
        if explain:
            console.print("\n[bold]Explanations[/bold]\n")
            for finding in findings:
                if finding.explanation:
                    sev_color = "bold red" if finding.severity == "CRITICAL" else "red" if finding.severity == "HIGH" else "yellow" if finding.severity == "MEDIUM" else "cyan"
                    console.print(f"[{sev_color}][{finding.severity}][/{sev_color}] {finding.file_path}:{finding.line_number}")
                    console.print(finding.explanation)
                    console.print(f"Manager summary: {finding.manager_summary}\n")

    report_files = []
    out_dir = Path(output_dir) if output_dir else Path.cwd()
    
    if report in ["json", "all"]:
        from agilityshift.reports.json_report import JSONReportWriter
        j_writer = JSONReportWriter()
        out_path = out_dir / "agilityshift-report.json"
        j_writer.write_report(
            out_path, path, profile, summary, findings, readiness, sev_summary
        )
        report_files.append("agilityshift-report.json")
        
    if report in ["html", "all"]:
        from agilityshift.reports.html_report import HTMLReportWriter
        h_writer = HTMLReportWriter()
        out_path = out_dir / "agilityshift-report.html"
        h_writer.write_report(
            out_path, path, profile, summary, findings, readiness, sev_summary
        )
        report_files.append("agilityshift-report.html")

    if report in ["sarif", "all"]:
        from agilityshift.reports.sarif_report import SARIFReportWriter
        s_writer = SARIFReportWriter()
        out_path = out_dir / "agilityshift-report.sarif"
        s_writer.write_report(out_path, findings)
        report_files.append("agilityshift-report.sarif")

    if report in ["cbom", "all"]:
        from agilityshift.reports.cbom_report import CBOMReportWriter
        c_writer = CBOMReportWriter()
        out_path = out_dir / "agilityshift-cbom.json"
        c_writer.write_report(out_path, path, profile, findings)
        report_files.append("agilityshift-cbom.json")

    if report_files:
        console.print("\n[bold]Reports generated:[/bold]")
        for report_file in report_files:
            console.print(f"- {report_file}")

    console.print()
    console.print("Phase 11 complete:")
    console.print("Template-based AI explanation layer is active.")
    console.print("Final demo polish will be added in Phase 12.")
    
    # Process CI/CD exit policy at the very end
    if fail_on != "none":
        console.print("\n" + exit_policy.summary_message(findings))
        
    if exit_policy.should_fail(findings):
        raise typer.Exit(code=1)
        
    raise typer.Exit(code=0)

if __name__ == "__main__":
    app()
