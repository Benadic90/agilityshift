import typer
from pathlib import Path
from rich.console import Console
from rich.table import Table
from agilityshift.scanner.repo_loader import RepoLoader

app = typer.Typer(help="AgilityShift PQC Migration Breakage Scanner")
console = Console()

@app.callback()
def callback():
    pass

@app.command()
def scan(
    target_path: Path = typer.Argument(..., help="Path to the target codebase"),
    show_files: bool = typer.Option(True, "--show-files/--no-show-files", help="Show supported files"),
    report: str = typer.Option("json", help="Report format"),
    fail_on: str = typer.Option("none", help="Fail level")
):
    console.print("AgilityShift scanner starting...")
    console.print(f"Target path: {target_path}")
    console.print()

    loader = RepoLoader(target_path)
    
    try:
        loader.validate_path()
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/bold red] Target path does not exist: {target_path}")
        raise typer.Exit(code=1)

    summary = loader.load_files()

    console.print("[bold]Scan Summary[/bold]")
    console.print(f"Files scanned: {summary.files_scanned}")
    console.print(f"Skipped files: {summary.skipped_files}")
    console.print()

    if not summary.supported_files:
        console.print("[bold yellow]Warning:[/bold yellow] No supported files found.")
    elif show_files:
        console.print("[bold]Supported files[/bold]")
        table = Table(show_header=False, box=None)
        
        # Sort files to ensure deterministic output (optional but good for expected output)
        for i, file in enumerate(sorted(summary.supported_files, key=lambda f: str(f.path)), start=1):
            table.add_row(
                str(i),
                file.relative_path,
                file.extension,
                str(file.line_count)
            )
        console.print(table)
        console.print()

    from agilityshift.scanner.limit_detector import JavaScriptLimitDetector
    from agilityshift.scanner.db_schema_detector import SQLSchemaDetector
    
    js_detector = JavaScriptLimitDetector()
    sql_detector = SQLSchemaDetector()
    
    findings = js_detector.detect(summary.supported_files)
    findings.extend(sql_detector.detect(summary.supported_files))

    if not findings:
        console.print("[bold green]No JavaScript or SQL fixed-limit findings detected.[/bold green]")
    else:
        console.print("[bold]Findings[/bold]")
        ftable = Table(show_header=True, box=None)
        ftable.add_column("Severity")
        ftable.add_column("Type")
        ftable.add_column("Rule")
        ftable.add_column("File")
        ftable.add_column("Line")
        ftable.add_column("Limit")
        ftable.add_column("Code")
        
        for f in findings:
            sev_color = "bold red" if f.severity == "CRITICAL" else "red" if f.severity == "HIGH" else "yellow"
            lim_str = f"{f.current_limit} {f.limit_unit}" if f.current_limit is not None else "N/A"
            ftable.add_row(
                f"[{sev_color}]{f.severity}[/{sev_color}]",
                f.finding_type,
                f.rule_id,
                f.file_path,
                str(f.line_number),
                lim_str,
                f.line_text
            )
        console.print(ftable)

    console.print()
    console.print("Phase 4 complete:")
    console.print("JavaScript and SQL database limit detectors are active.")
    console.print("OpenAPI/YAML detector will be added in Phase 5.")

if __name__ == "__main__":
    app()
