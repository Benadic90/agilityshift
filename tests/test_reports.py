import json
from pathlib import Path
from agilityshift.models import Finding, ScanSummary, PQCProfile
from agilityshift.reports.json_report import JSONReportWriter
from agilityshift.reports.html_report import HTMLReportWriter

def test_json_report_writer(tmp_path):
    writer = JSONReportWriter()
    out_path = tmp_path / "agilityshift-report.json"
    
    profile = PQCProfile(name="ML-DSA-65", signature_bytes=3309, level=3, type="digital_signature", description="")
    summary = ScanSummary(target_path=tmp_path, files_scanned=1, skipped_files=0, supported_files=[])
    finding = Finding(rule_id="TEST", title="T", description="D", file_path="a.js", line_number=1, line_text="alloc", finding_type="code_limit", severity="CRITICAL", confidence="HIGH", suggestion="", current_limit=256, limit_unit="bytes", pqc_profile="ML-DSA-65", required_size=3309, overflow_ratio=12.9, readiness_penalty=20, risk_message="", fix_title="F", fix_description="D", suggested_fix="S", safe_example="E", manual_review_required=True, fix_confidence="HIGH")
    
    res_path = writer.write_report(out_path, tmp_path, profile, summary, [finding], 80, {"CRITICAL": 1})
    
    assert res_path.exists()
    
    with open(res_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    assert data["tool"]["name"] == "AgilityShift"
    assert data["scan"]["target_profile"] == "ML-DSA-65"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["rule_id"] == "TEST"
    assert data["findings"][0]["fix_title"] == "F"
    assert data["findings"][0]["manual_review_required"] is True

def test_html_report_writer(tmp_path):
    writer = HTMLReportWriter()
    out_path = tmp_path / "agilityshift-report.html"
    
    profile = PQCProfile(name="ML-DSA-65", signature_bytes=3309, level=3, type="digital_signature", description="")
    summary = ScanSummary(target_path=tmp_path, files_scanned=1, skipped_files=0, supported_files=[])
    finding = Finding(rule_id="TEST", title="T", description="D", file_path="a.js", line_number=1, line_text="alloc", finding_type="code_limit", severity="CRITICAL", confidence="HIGH", suggestion="", current_limit=256, limit_unit="bytes", pqc_profile="ML-DSA-65", required_size=3309, overflow_ratio=12.9, readiness_penalty=20, risk_message="", fix_title="F", fix_description="D", suggested_fix="S", safe_example="E", manual_review_required=True, fix_confidence="HIGH")
    
    res_path = writer.write_report(out_path, tmp_path, profile, summary, [finding], 80, {"CRITICAL": 1})
    
    assert res_path.exists()
    
    with open(res_path, "r", encoding="utf-8") as f:
        content = f.read()
        
    assert "AgilityShift PQC Migration Readiness Report" in content
    assert "80/100" in content
    assert "TEST" in content
    assert "Suggested Fixes" in content
    assert "CRITICAL: 1" in content
    
def test_writers_handle_empty_findings(tmp_path):
    j_writer = JSONReportWriter()
    h_writer = HTMLReportWriter()
    
    profile = PQCProfile(name="ML-DSA-65", signature_bytes=3309, level=3, type="digital_signature", description="")
    summary = ScanSummary(target_path=tmp_path, files_scanned=0, skipped_files=0, supported_files=[])
    
    j_path = j_writer.write_report(tmp_path / "out.json", tmp_path, profile, summary, [], 100, {})
    h_path = h_writer.write_report(tmp_path / "out.html", tmp_path, profile, summary, [], 100, {})
    
    assert j_path.exists()
    assert h_path.exists()
    
    with open(h_path, "r", encoding="utf-8") as f:
        content = f.read()
    assert "No Critical PQC Breakage Detected" in content
