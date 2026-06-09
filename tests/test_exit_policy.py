import pytest
from agilityshift.ci.exit_policy import ExitPolicy
from agilityshift.models import Finding

def _mock_finding(severity: str) -> Finding:
    return Finding(
        rule_id="TEST",
        title="T",
        description="D",
        file_path="f",
        line_number=1,
        line_text="t",
        current_limit=256,
        limit_unit="bytes",
        finding_type="code",
        severity=severity,
        confidence="HIGH",
        suggestion=""
    )

def test_fail_on_none():
    policy = ExitPolicy("none")
    findings = [_mock_finding("CRITICAL")]
    assert policy.should_fail(findings) is False
    assert policy.exit_code(findings) == 0
    assert len(policy.matching_findings(findings)) == 0

def test_fail_on_critical_fails_on_critical():
    policy = ExitPolicy("critical")
    findings = [_mock_finding("CRITICAL"), _mock_finding("HIGH")]
    assert policy.should_fail(findings) is True
    assert policy.exit_code(findings) == 1
    assert len(policy.matching_findings(findings)) == 1

def test_fail_on_critical_passes_on_high():
    policy = ExitPolicy("critical")
    findings = [_mock_finding("HIGH"), _mock_finding("MEDIUM")]
    assert policy.should_fail(findings) is False
    assert policy.exit_code(findings) == 0
    assert len(policy.matching_findings(findings)) == 0

def test_fail_on_high_fails_on_high():
    policy = ExitPolicy("high")
    findings = [_mock_finding("HIGH"), _mock_finding("MEDIUM")]
    assert policy.should_fail(findings) is True
    assert len(policy.matching_findings(findings)) == 1

def test_fail_on_high_fails_on_critical():
    policy = ExitPolicy("high")
    findings = [_mock_finding("CRITICAL")]
    assert policy.should_fail(findings) is True
    assert len(policy.matching_findings(findings)) == 1

def test_fail_on_medium_fails_on_medium_high_critical():
    policy = ExitPolicy("medium")
    findings = [_mock_finding("MEDIUM"), _mock_finding("HIGH"), _mock_finding("CRITICAL"), _mock_finding("LOW")]
    assert policy.should_fail(findings) is True
    assert len(policy.matching_findings(findings)) == 3

def test_fail_on_low_fails_on_any():
    policy = ExitPolicy("low")
    findings = [_mock_finding("LOW")]
    assert policy.should_fail(findings) is True

def test_invalid_fail_on_raises_value_error():
    with pytest.raises(ValueError, match="Invalid fail-on threshold"):
        ExitPolicy("invalid_value")

def test_summary_message():
    policy = ExitPolicy("critical")
    
    # Passing case
    msg_pass = policy.summary_message([_mock_finding("HIGH")])
    assert "PASSED" in msg_pass
    assert "CRITICAL" in msg_pass
    
    # Failing case
    msg_fail = policy.summary_message([_mock_finding("CRITICAL")])
    assert "FAILED" in msg_fail
    assert "CRITICAL" in msg_fail
    assert "Deployment blocked before production failure" in msg_fail
