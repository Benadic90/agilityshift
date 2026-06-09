import pytest
from pathlib import Path
from agilityshift.models import ScannedFile
from agilityshift.scanner.db_schema_detector import SQLSchemaDetector

def make_sql_file(content: str, filename="test.sql") -> ScannedFile:
    return ScannedFile(
        path=Path(filename),
        relative_path=filename,
        extension=".sql",
        line_count=len(content.splitlines()),
        content=content,
        lines=content.splitlines()
    )

def test_detect_signature_varchar():
    detector = SQLSchemaDetector()
    f = make_sql_file("signature VARCHAR(256)")
    findings = detector.detect([f])
    assert len(findings) == 1
    assert findings[0].rule_id == "SQL_CRYPTO_VARCHAR_LIMIT"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].current_limit == 256
    assert findings[0].finding_type == "database_limit"

def test_detect_public_key_varchar():
    detector = SQLSchemaDetector()
    f = make_sql_file("public_key VARCHAR(512)")
    findings = detector.detect([f])
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].current_limit == 512

def test_detect_certificate_varchar():
    detector = SQLSchemaDetector()
    f = make_sql_file("certificate VARCHAR(2048)")
    findings = detector.detect([f])
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].current_limit == 2048

def test_detect_jwt_token_varchar():
    detector = SQLSchemaDetector()
    f = make_sql_file("jwt_token VARCHAR(512)")
    findings = detector.detect([f])
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].current_limit == 512

def test_detect_attestation_proof_varchar():
    detector = SQLSchemaDetector()
    f = make_sql_file("attestation_proof VARCHAR(256)")
    findings = detector.detect([f])
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert findings[0].current_limit == 256

def test_detect_lowercase_varchar():
    detector = SQLSchemaDetector()
    f = make_sql_file("signature varchar(256)")
    findings = detector.detect([f])
    assert len(findings) == 1
    assert findings[0].current_limit == 256

def test_detect_quoted_identifiers():
    detector = SQLSchemaDetector()
    f = make_sql_file("`signature` VARCHAR(256)")
    findings = detector.detect([f])
    assert len(findings) == 1
    assert findings[0].current_limit == 256

def test_ignore_non_crypto_fields():
    detector = SQLSchemaDetector()
    f = make_sql_file("name VARCHAR(100)\nemail VARCHAR(150)\naddress VARCHAR(255)\ndescription VARCHAR(256)")
    findings = detector.detect([f])
    assert len(findings) == 0

def test_ignore_safe_fields():
    detector = SQLSchemaDetector()
    f = make_sql_file("signature TEXT\npublic_key BLOB\ncertificate BYTEA")
    findings = detector.detect([f])
    assert len(findings) == 0

def test_skip_non_sql_files():
    detector = SQLSchemaDetector()
    f = ScannedFile(Path("test.txt"), "test.txt", ".txt", 1, "signature VARCHAR(256)", ["signature VARCHAR(256)"])
    findings = detector.detect([f])
    assert len(findings) == 0

def test_handle_empty_sql_file():
    detector = SQLSchemaDetector()
    f = make_sql_file("")
    findings = detector.detect([f])
    assert len(findings) == 0

def test_vulnerable_bank_api_schema():
    from agilityshift.scanner.repo_loader import RepoLoader
    loader = RepoLoader(Path("examples/vulnerable-bank-api"))
    if not loader.target_path.exists():
        pytest.skip("examples dir missing")
    summary = loader.load_files()
    
    detector = SQLSchemaDetector()
    findings = detector.detect(summary.supported_files)
    
    assert len(findings) > 0
    # verify expected rules
    rule_ids = [f.rule_id for f in findings]
    assert "SQL_CRYPTO_VARCHAR_LIMIT" in rule_ids
