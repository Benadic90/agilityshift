import pytest
from agilityshift.models import Finding
from agilityshift.fixes.suggestions import SuggestionEngine

def test_suggests_fix_buffer_alloc():
    engine = SuggestionEngine()
    f = Finding(rule_id="JS_BUFFER_ALLOC_FIXED_SIZE", title="", description="", file_path="", line_number=1, line_text="", finding_type="", severity="", confidence="", suggestion="", current_limit=None, limit_unit="")
    res = engine.suggest_for_finding(f)
    assert res.fix_title == "Use dynamic buffer decoding"
    assert "Buffer.from" in res.suggested_fix
    assert res.fix_confidence == "HIGH"
    assert res.manual_review_required is True

def test_suggests_fix_buffer_unsafe():
    engine = SuggestionEngine()
    f = Finding(rule_id="JS_BUFFER_ALLOC_UNSAFE_FIXED_SIZE", title="", description="", file_path="", line_number=1, line_text="", finding_type="", severity="", confidence="", suggestion="", current_limit=None, limit_unit="")
    res = engine.suggest_for_finding(f)
    assert res.fix_title == "Avoid unsafe fixed-size buffers"
    assert res.fix_confidence == "HIGH"

def test_suggests_fix_crypto_length():
    engine = SuggestionEngine()
    f = Finding(rule_id="JS_CRYPTO_LENGTH_LIMIT", title="", description="", file_path="", line_number=1, line_text="", finding_type="", severity="", confidence="", suggestion="", current_limit=None, limit_unit="")
    res = engine.suggest_for_finding(f)
    assert res.fix_title == "Replace hardcoded crypto length check"

def test_suggests_fix_truncation():
    engine = SuggestionEngine()
    f = Finding(rule_id="JS_CRYPTO_TRUNCATION_LIMIT", title="", description="", file_path="", line_number=1, line_text="", finding_type="", severity="", confidence="", suggestion="", current_limit=None, limit_unit="")
    res = engine.suggest_for_finding(f)
    assert res.fix_title == "Remove cryptographic material truncation"

def test_suggests_fix_crypto_constant():
    engine = SuggestionEngine()
    f = Finding(rule_id="JS_CRYPTO_LIMIT_CONSTANT", title="", description="", file_path="", line_number=1, line_text="", finding_type="", severity="", confidence="", suggestion="", current_limit=None, limit_unit="")
    res = engine.suggest_for_finding(f)
    assert res.fix_title == "Move crypto-size constant to PQC policy"

def test_suggests_fix_sql_varchar():
    engine = SuggestionEngine()
    f = Finding(rule_id="SQL_CRYPTO_VARCHAR_LIMIT", title="", description="", file_path="", line_number=1, line_text="", finding_type="", severity="", confidence="", suggestion="", current_limit=None, limit_unit="")
    res = engine.suggest_for_finding(f)
    assert res.fix_title == "Use migration-safe database storage"
    assert "TEXT, BYTEA" in res.suggested_fix

def test_suggests_fix_sql_char():
    engine = SuggestionEngine()
    f = Finding(rule_id="SQL_CRYPTO_CHAR_LIMIT", title="", description="", file_path="", line_number=1, line_text="", finding_type="", severity="", confidence="", suggestion="", current_limit=None, limit_unit="")
    res = engine.suggest_for_finding(f)
    assert res.fix_title == "Avoid fixed CHAR for cryptographic material"

def test_suggests_fix_sql_varbinary():
    engine = SuggestionEngine()
    f = Finding(rule_id="SQL_CRYPTO_VARBINARY_LIMIT", title="", description="", file_path="", line_number=1, line_text="", finding_type="", severity="", confidence="", suggestion="", current_limit=None, limit_unit="")
    res = engine.suggest_for_finding(f)
    assert res.fix_title == "Increase binary crypto storage size"

def test_suggests_fix_api_max_length():
    engine = SuggestionEngine()
    f = Finding(rule_id="API_CRYPTO_MAX_LENGTH_LIMIT", title="", description="", file_path="", line_number=1, line_text="", finding_type="", severity="", confidence="", suggestion="", current_limit=None, limit_unit="")
    res = engine.suggest_for_finding(f)
    assert res.fix_title == "Increase API maxLength for PQC migration"

def test_suggests_fix_api_json_max_length():
    engine = SuggestionEngine()
    f = Finding(rule_id="API_JSON_CRYPTO_MAX_LENGTH_LIMIT", title="", description="", file_path="", line_number=1, line_text="", finding_type="", severity="", confidence="", suggestion="", current_limit=None, limit_unit="")
    res = engine.suggest_for_finding(f)
    assert res.fix_title == "Increase JSON schema maxLength"

def test_unknown_rule_generic():
    engine = SuggestionEngine()
    f = Finding(rule_id="UNKNOWN_RANDOM_RULE_XYZ", title="", description="", file_path="", line_number=1, line_text="", finding_type="", severity="", confidence="", suggestion="", current_limit=None, limit_unit="")
    res = engine.suggest_for_finding(f)
    assert res.fix_title == "Manual review required"
    assert res.fix_confidence == "LOW"

def test_suggest_for_findings_list():
    engine = SuggestionEngine()
    f1 = Finding(rule_id="JS_BUFFER_ALLOC_FIXED_SIZE", title="", description="", file_path="", line_number=1, line_text="", finding_type="", severity="", confidence="", suggestion="", current_limit=None, limit_unit="")
    f2 = Finding(rule_id="UNKNOWN_RULE", title="", description="", file_path="", line_number=1, line_text="", finding_type="", severity="", confidence="", suggestion="", current_limit=None, limit_unit="")
    res = engine.suggest_for_findings([f1, f2])
    assert len(res) == 2
    assert res[0].fix_title == "Use dynamic buffer decoding"
    assert res[1].fix_title == "Manual review required"

def test_preserves_existing_risk_fields():
    engine = SuggestionEngine()
    f = Finding(rule_id="JS_BUFFER_ALLOC_FIXED_SIZE", title="", description="", file_path="", line_number=1, line_text="", finding_type="", severity="CRITICAL", confidence="", suggestion="", current_limit=None, limit_unit="", overflow_ratio=15.0)
    res = engine.suggest_for_finding(f)
    assert res.severity == "CRITICAL"
    assert res.overflow_ratio == 15.0
