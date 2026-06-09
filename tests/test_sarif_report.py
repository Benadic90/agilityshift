import pytest
from pathlib import Path
from agilityshift.models import Finding
from agilityshift.reports.sarif_report import SARIFReportWriter

def test_sarif_file_created(tmp_path: Path):
    writer = SARIFReportWriter()
    out_path = tmp_path / "agilityshift-report.sarif"
    writer.write_report(out_path, [])
    assert out_path.exists()

def test_sarif_version_and_tool():
    writer = SARIFReportWriter()
    sarif = writer.build_sarif([])
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "AgilityShift"

def test_sarif_empty_findings():
    writer = SARIFReportWriter()
    sarif = writer.build_sarif([])
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 0
    assert len(sarif["runs"][0]["results"]) == 0

def test_sarif_finding_mapping():
    writer = SARIFReportWriter()
    finding = Finding(
        rule_id="JS_CRYPTO",
        title="Test title",
        description="Test desc",
        file_path="src/index.js",
        line_number=42,
        line_text="Buffer.alloc",
        finding_type="code_limit",
        severity="CRITICAL",
        confidence="HIGH",
        current_limit=256,
        limit_unit="bytes",
        suggestion="",
        risk_message="Risk message test.",
        suggested_fix="Do this fix."
    )
    
    sarif = writer.build_sarif([finding])
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    results = sarif["runs"][0]["results"]
    
    assert len(rules) == 1
    assert rules[0]["id"] == "JS_CRYPTO"
    
    assert len(results) == 1
    result = results[0]
    assert result["ruleId"] == "JS_CRYPTO"
    assert result["level"] == "error"
    
    msg = result["message"]["text"]
    assert "Test title" in msg
    assert "Risk message test." in msg
    assert "Suggested fix: Do this fix." in msg
    
    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "src/index.js"
    assert location["region"]["startLine"] == 42

def test_severity_mapping():
    writer = SARIFReportWriter()
    assert writer._severity_to_level("CRITICAL") == "error"
    assert writer._severity_to_level("HIGH") == "error"
    assert writer._severity_to_level("MEDIUM") == "warning"
    assert writer._severity_to_level("LOW") == "note"
    assert writer._severity_to_level("UNKNOWN") == "warning"
