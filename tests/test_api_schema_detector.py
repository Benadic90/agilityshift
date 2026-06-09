import pytest
from pathlib import Path
from agilityshift.models import ScannedFile
from agilityshift.scanner.api_schema_detector import APISchemaDetector

def make_api_file(content: str, filename="test.yaml") -> ScannedFile:
    return ScannedFile(
        path=Path(filename),
        relative_path=filename,
        extension=Path(filename).suffix,
        line_count=len(content.splitlines()),
        content=content,
        lines=content.splitlines()
    )

def test_yaml_signature_maxlength():
    d = APISchemaDetector()
    f = make_api_file("signature:\n  type: string\n  maxLength: 256")
    findings = d.detect([f])
    assert len(findings) == 1
    assert findings[0].rule_id == "API_CRYPTO_MAX_LENGTH_LIMIT"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].current_limit == 256
    assert findings[0].line_number == 3

def test_yaml_publickey_maxlength():
    d = APISchemaDetector()
    f = make_api_file("publicKey:\n  type: string\n  maxLength: 512")
    findings = d.detect([f])
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].current_limit == 512

def test_yaml_certificate_maxlength():
    d = APISchemaDetector()
    f = make_api_file("certificate:\n  type: string\n  maxLength: 2048")
    findings = d.detect([f])
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].current_limit == 2048

def test_json_signature_maxlength():
    d = APISchemaDetector()
    f = make_api_file('{\n  "signature": {\n    "type": "string",\n    "maxLength": 256\n  }\n}', "test.json")
    findings = d.detect([f])
    assert len(findings) == 1
    assert findings[0].rule_id == "API_JSON_CRYPTO_MAX_LENGTH_LIMIT"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].line_number == 4

def test_ignore_non_crypto():
    d = APISchemaDetector()
    f = make_api_file("name:\n  type: string\n  maxLength: 100")
    findings = d.detect([f])
    assert len(findings) == 0

def test_attestation_proof():
    d = APISchemaDetector()
    f = make_api_file("attestationProof:\n  maxLength: 256")
    findings = d.detect([f])
    assert len(findings) == 1
    assert findings[0].current_limit == 256

def test_lowercase_snakecase():
    d = APISchemaDetector()
    f = make_api_file("signed_payload:\n  maxLength: 128")
    findings = d.detect([f])
    assert len(findings) == 1

def test_skip_non_api():
    d = APISchemaDetector()
    f = make_api_file("signature:\n maxLength: 256", "test.txt")
    findings = d.detect([f])
    assert len(findings) == 0

def test_invalid_yaml():
    d = APISchemaDetector()
    f = make_api_file("this is totally [ invalid yaml\n signature:\n  maxLength: 256")
    findings = d.detect([f])
    assert len(findings) == 1

def test_empty_file():
    d = APISchemaDetector()
    f = make_api_file("")
    findings = d.detect([f])
    assert len(findings) == 0

def test_request_body_limit():
    d = APISchemaDetector()
    # Need crypto context to trigger
    f = make_api_file("limit: '1kb'\nsignature: test")
    findings = d.detect([f])
    assert len(findings) == 1
    assert findings[0].rule_id == "API_SMALL_REQUEST_BODY_LIMIT"
    assert findings[0].current_limit == 1024
    assert findings[0].severity == "CRITICAL"

def test_vulnerable_bank_api():
    from agilityshift.scanner.repo_loader import RepoLoader
    loader = RepoLoader(Path("examples/vulnerable-bank-api"))
    if not loader.target_path.exists():
        pytest.skip("examples dir missing")
    summary = loader.load_files()
    
    detector = APISchemaDetector()
    findings = detector.detect(summary.supported_files)
    
    assert len(findings) >= 3
    rule_ids = [f.rule_id for f in findings]
    assert "API_CRYPTO_MAX_LENGTH_LIMIT" in rule_ids
