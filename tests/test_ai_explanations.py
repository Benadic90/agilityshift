import pytest
from agilityshift.models import Finding
from agilityshift.ai.explain_template import TemplateExplanationEngine
from agilityshift.ai.explain_llm import LLMExplanationEngine

def _mock_finding(finding_type: str, limit_unit: str = "bytes", limit: int = 256) -> Finding:
    return Finding(
        rule_id="TEST_RULE",
        title="Test finding",
        description="D",
        file_path="f.js",
        line_number=1,
        line_text="limit=256",
        current_limit=limit,
        limit_unit=limit_unit,
        finding_type=finding_type,
        severity="CRITICAL",
        confidence="HIGH",
        pqc_profile="ML-DSA-65",
        required_size=3309,
        overflow_ratio=12.93,
        suggestion=""
    )

def test_template_engine_code_limit():
    engine = TemplateExplanationEngine()
    finding = _mock_finding("code_limit")
    engine.explain_finding(finding)
    
    assert finding.explanation is not None
    assert "fixed code-level size assumption" in finding.explanation
    assert "3309 bytes" in finding.explanation
    assert "256 bytes" in finding.explanation
    assert "12.93x" in finding.explanation
    assert "Remove hardcoded fixed limits" in finding.developer_guidance
    assert "code path may break" in finding.manager_summary
    assert finding.explanation_source == "template"

def test_template_engine_database_limit():
    engine = TemplateExplanationEngine()
    finding = _mock_finding("database_schema")
    engine.explain_finding(finding)
    
    assert finding.explanation is not None
    assert "database column may be too small" in finding.explanation
    assert "TEXT, BYTEA" in finding.developer_guidance
    assert "database schema may block" in finding.manager_summary

def test_template_engine_api_contract_limit():
    engine = TemplateExplanationEngine()
    finding = _mock_finding("api_contract")
    engine.explain_finding(finding)
    
    assert finding.explanation is not None
    assert "API validation rule may reject" in finding.explanation
    assert "Increase maxLength" in finding.developer_guidance
    assert "API contract may reject" in finding.manager_summary

def test_template_engine_unknown_type():
    engine = TemplateExplanationEngine()
    finding = _mock_finding("unknown_type")
    engine.explain_finding(finding)
    
    assert finding.explanation is not None
    assert "represent a PQC migration breakage risk" in finding.explanation
    assert "Manual review is required" in finding.manager_summary

def test_template_engine_missing_fields():
    engine = TemplateExplanationEngine()
    finding = _mock_finding("code_limit")
    finding.required_size = None
    finding.overflow_ratio = None
    
    engine.explain_finding(finding)
    assert "target PQC size was not available" in finding.explanation
    assert "exact overflow ratio could not be calculated" in finding.explanation

def test_template_engine_characters_unit():
    engine = TemplateExplanationEngine()
    finding = _mock_finding("database_schema", limit_unit="characters")
    engine.explain_finding(finding)
    
    assert "Character limits may not equal byte limits" in finding.explanation

def test_template_explain_findings_list():
    engine = TemplateExplanationEngine()
    findings = [_mock_finding("code_limit"), _mock_finding("api_contract")]
    result = engine.explain_findings(findings)
    assert len(result) == 2
    assert result[0].explanation is not None
    assert result[1].explanation is not None

def test_llm_engine_provider_none():
    engine = LLMExplanationEngine(provider="none")
    finding = _mock_finding("code_limit")
    engine.explain_finding(finding)
    
    assert finding.explanation is not None
    assert finding.explanation_source == "template"
