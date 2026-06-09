import pytest
from pathlib import Path
from agilityshift.models import Finding, PQCProfile
from agilityshift.reports.cbom_report import CBOMReportWriter

def _mock_finding(line_text="Buffer.alloc", file_path="src/index.js", severity="CRITICAL", finding_type="code_limit") -> Finding:
    return Finding(
        rule_id="JS_CRYPTO",
        title="Test title",
        description="Test desc",
        file_path=file_path,
        line_number=42,
        line_text=line_text,
        finding_type=finding_type,
        severity=severity,
        confidence="HIGH",
        current_limit=256,
        limit_unit="bytes",
        suggestion="",
        risk_message="Risk message test.",
        suggested_fix="Do this fix.",
        developer_guidance="Dev guide"
    )

def test_cbom_file_created(tmp_path: Path):
    writer = CBOMReportWriter()
    out_path = tmp_path / "agilityshift-cbom.json"
    writer.write_report(out_path, tmp_path, PQCProfile(name="ML-DSA", signature_bytes=3309, level=1, type="sig", description="desc"), [])
    assert out_path.exists()

def test_cbom_tool_and_target_profile():
    writer = CBOMReportWriter()
    cbom = writer.build_cbom_data(Path("test/path"), PQCProfile(name="ML-DSA-65", signature_bytes=3309, level=3, type="sig", description=""), [])
    assert cbom["metadata"]["tools"]["components"][0]["name"] == "AgilityShift"
    
    profile_prop = next(p for p in cbom["metadata"]["component"]["properties"] if p["name"] == "agilityshift:pqcProfile")
    assert profile_prop["value"] == "ML-DSA-65"

def test_cbom_crypto_assets_list():
    writer = CBOMReportWriter()
    cbom = writer.build_cbom_data(Path("test/path"), None, [_mock_finding()])
    assert len(cbom["components"]) == 1
    assert cbom["components"][0]["bom-ref"] == "crypto-asset-1"

def test_cbom_inference_signature():
    writer = CBOMReportWriter()
    f = _mock_finding(line_text="const sig = sign(data)")
    cbom = writer.build_cbom_data(Path("test/path"), None, [f])
    assert cbom["components"][0]["cryptoProperties"]["assetType"] == "related-crypto-material"

def test_cbom_inference_public_key():
    writer = CBOMReportWriter()
    f = _mock_finding(line_text="publicKey VARCHAR")
    cbom = writer.build_cbom_data(Path("test/path"), None, [f])
    assert cbom["components"][0]["cryptoProperties"]["assetType"] == "related-crypto-material"

def test_cbom_inference_certificate():
    writer = CBOMReportWriter()
    f = _mock_finding(line_text="read certificate file")
    cbom = writer.build_cbom_data(Path("test/path"), None, [f])
    assert cbom["components"][0]["cryptoProperties"]["assetType"] == "certificate"

def test_cbom_inference_token():
    writer = CBOMReportWriter()
    f = _mock_finding(line_text="jwt_token validation")
    cbom = writer.build_cbom_data(Path("test/path"), None, [f])
    assert cbom["components"][0]["cryptoProperties"]["assetType"] == "related-crypto-material"

def test_cbom_inference_proof():
    writer = CBOMReportWriter()
    f = _mock_finding(line_text="attestation proof length")
    cbom = writer.build_cbom_data(Path("test/path"), None, [f])
    assert cbom["components"][0]["cryptoProperties"]["assetType"] == "related-crypto-material"

def test_cbom_algorithm_rs256():
    writer = CBOMReportWriter()
    f = _mock_finding(line_text="algo: 'RS256'")
    cbom = writer.build_cbom_data(Path("test/path"), None, [f])
    assert cbom["components"][0]["cryptoProperties"]["algorithmProperties"]["name"] == "RS256"

def test_cbom_no_algorithm():
    writer = CBOMReportWriter()
    f = _mock_finding(line_text="something else")
    cbom = writer.build_cbom_data(Path("test/path"), None, [f])
    assert "algorithmProperties" not in cbom["components"][0]["cryptoProperties"]

def test_cbom_summary_counts():
    writer = CBOMReportWriter()
    findings = [
        _mock_finding(severity="CRITICAL"),
        _mock_finding(severity="CRITICAL"),
        _mock_finding(severity="HIGH"),
        _mock_finding(severity="MEDIUM"),
    ]
    cbom = writer.build_cbom_data(Path("test/path"), None, findings)
    
    props = cbom["metadata"]["properties"]
    tot = next(p for p in props if p["name"] == "agilityshift:summary:totalCryptoAssets")["value"]
    crit = next(p for p in props if p["name"] == "agilityshift:summary:criticalAssets")["value"]
    hi = next(p for p in props if p["name"] == "agilityshift:summary:highAssets")["value"]
    
    assert tot == "4"
    assert crit == "2"
    assert hi == "1"

def test_cbom_empty_findings():
    writer = CBOMReportWriter()
    cbom = writer.build_cbom_data(Path("test/path"), None, [])
    
    props = cbom["metadata"]["properties"]
    tot = next(p for p in props if p["name"] == "agilityshift:summary:totalCryptoAssets")["value"]
    crit = next(p for p in props if p["name"] == "agilityshift:summary:criticalAssets")["value"]
    conc = next(p for p in props if p["name"] == "agilityshift:summary:pqcReadinessConcern")["value"]
    
    assert tot == "0"
    assert crit == "0"
    assert conc == "false"
