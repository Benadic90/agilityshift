import pytest
from pathlib import Path
from agilityshift.models import Finding
from agilityshift.pqc.profile_loader import PQCProfileLoader
from agilityshift.risk.scorer import RiskScorer

def test_load_default_profile():
    loader = PQCProfileLoader()
    p = loader.get_default_profile()
    assert p.name == "ML-DSA-65"
    assert p.signature_bytes == 3309

def test_list_profiles():
    loader = PQCProfileLoader()
    profiles = loader.list_profile_names()
    assert "ML-DSA-65" in profiles
    assert "ML-DSA-44" in profiles

def test_missing_profile():
    loader = PQCProfileLoader()
    with pytest.raises(ValueError):
        loader.get_profile("UNKNOWN-123")

def test_score_critical_finding():
    loader = PQCProfileLoader()
    scorer = RiskScorer(loader.get_default_profile())
    f = Finding(
        rule_id="TEST", title="Test", description="Test", file_path="test.js",
        line_number=1, line_text="alloc(256)", finding_type="code",
        severity="MEDIUM", confidence="HIGH", suggestion="Fix",
        current_limit=256, limit_unit="bytes"
    )
    res = scorer.score_finding(f)
    assert res.overflow_ratio == 12.93
    assert res.severity == "CRITICAL"
    assert res.readiness_penalty == 20
    assert "12.93x larger" in res.risk_message

def test_score_medium_finding():
    loader = PQCProfileLoader()
    scorer = RiskScorer(loader.get_default_profile())
    f = Finding(
        rule_id="TEST", title="Test", description="Test", file_path="test.js",
        line_number=1, line_text="alloc(2048)", finding_type="code",
        severity="MEDIUM", confidence="HIGH", suggestion="Fix",
        current_limit=2000, limit_unit="bytes"
    )
    res = scorer.score_finding(f)
    assert res.overflow_ratio == 1.65
    assert res.severity == "MEDIUM"
    assert res.readiness_penalty == 5

def test_current_limit_none():
    loader = PQCProfileLoader()
    scorer = RiskScorer(loader.get_default_profile())
    f = Finding(
        rule_id="TEST", title="Test", description="Test", file_path="test.js",
        line_number=1, line_text="alloc", finding_type="code",
        severity="HIGH", confidence="HIGH", suggestion="Fix",
        current_limit=None, limit_unit=""
    )
    res = scorer.score_finding(f)
    assert res.overflow_ratio is None
    assert res.severity == "HIGH"
    assert res.readiness_penalty == 5

def test_calculate_readiness_score_clamped():
    loader = PQCProfileLoader()
    scorer = RiskScorer(loader.get_default_profile())
    f = Finding(rule_id="TEST", title="", description="", file_path="", line_number=1, line_text="", finding_type="", severity="", confidence="", suggestion="", current_limit=256, limit_unit="bytes")
    
    findings = scorer.score_findings([f] * 6) # 6 * 20 = 120 penalty
    score = scorer.calculate_readiness_score(findings)
    assert score == 0 # Should clamp at 0

def test_severity_summary():
    loader = PQCProfileLoader()
    scorer = RiskScorer(loader.get_default_profile())
    f1 = Finding(rule_id="TEST", title="", description="", file_path="", line_number=1, line_text="", finding_type="", severity="", confidence="", suggestion="", current_limit=256, limit_unit="bytes")
    findings = scorer.score_findings([f1])
    summary = scorer.summarize_severity(findings)
    assert summary["CRITICAL"] == 1
    assert summary["HIGH"] == 0

def test_vulnerable_bank_api_scorer():
    from agilityshift.scanner.repo_loader import RepoLoader
    from agilityshift.scanner.limit_detector import JavaScriptLimitDetector
    from pathlib import Path
    
    loader = RepoLoader(Path("examples/vulnerable-bank-api"))
    if not loader.target_path.exists():
        pytest.skip("examples dir missing")
    summary = loader.load_files()
    
    detector = JavaScriptLimitDetector()
    findings = detector.detect(summary.supported_files)
    
    pqc_loader = PQCProfileLoader()
    scorer = RiskScorer(pqc_loader.get_default_profile())
    scored = scorer.score_findings(findings)
    assert len(scored) > 0
    assert scored[0].readiness_penalty > 0
