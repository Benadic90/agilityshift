import pytest
from pathlib import Path
from agilityshift.models import ScannedFile
from agilityshift.scanner.limit_detector import JavaScriptLimitDetector

def make_js_file(content: str, filename="test.js") -> ScannedFile:
    return ScannedFile(
        path=Path(filename),
        relative_path=filename,
        extension=".js",
        line_count=len(content.splitlines()),
        content=content,
        lines=content.splitlines()
    )

def test_detect_buffer_alloc():
    detector = JavaScriptLimitDetector()
    f = make_js_file("const sigBuffer = Buffer.alloc(256);")
    findings = detector.detect([f])
    assert len(findings) == 1
    assert findings[0].rule_id == "JS_BUFFER_ALLOC_FIXED_SIZE"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].current_limit == 256

def test_detect_buffer_alloc_unsafe():
    detector = JavaScriptLimitDetector()
    f = make_js_file("const sigBuffer = Buffer.allocUnsafe(512);")
    findings = detector.detect([f])
    assert len(findings) == 1
    assert findings[0].rule_id == "JS_BUFFER_ALLOC_UNSAFE_FIXED_SIZE"
    assert findings[0].severity == "HIGH"
    assert findings[0].current_limit == 512

def test_detect_crypto_length():
    detector = JavaScriptLimitDetector()
    f = make_js_file("if (signature.length > 256) { return false; }")
    findings = detector.detect([f])
    assert len(findings) == 1
    assert findings[0].rule_id == "JS_CRYPTO_LENGTH_LIMIT"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].current_limit == 256

def test_detect_crypto_truncation():
    detector = JavaScriptLimitDetector()
    f = make_js_file("const shortSig = signature.slice(0, 256);")
    findings = detector.detect([f])
    assert len(findings) == 1
    assert findings[0].rule_id == "JS_CRYPTO_TRUNCATION_LIMIT"
    assert findings[0].severity == "HIGH"
    assert findings[0].current_limit == 256

def test_detect_crypto_constant():
    detector = JavaScriptLimitDetector()
    f = make_js_file("const MAX_SIGNATURE_SIZE = 256;")
    findings = detector.detect([f])
    assert len(findings) == 1
    assert findings[0].rule_id == "JS_CRYPTO_LIMIT_CONSTANT"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].current_limit == 256

def test_skip_non_js():
    detector = JavaScriptLimitDetector()
    f = ScannedFile(Path("test.txt"), "test.txt", ".txt", 1, "Buffer.alloc(256)", ["Buffer.alloc(256)"])
    findings = detector.detect([f])
    assert len(findings) == 0

def test_no_duplicate_findings():
    detector = JavaScriptLimitDetector()
    f = make_js_file("Buffer.alloc(256); Buffer.alloc(256);")
    findings = detector.detect([f])
    assert len(findings) == 1

def test_exact_line_number():
    detector = JavaScriptLimitDetector()
    f = make_js_file("\n\nBuffer.alloc(256);")
    findings = detector.detect([f])
    assert findings[0].line_number == 3

def test_empty_file():
    detector = JavaScriptLimitDetector()
    f = make_js_file("")
    findings = detector.detect([f])
    assert len(findings) == 0

def test_vulnerable_bank_api():
    from agilityshift.scanner.repo_loader import RepoLoader
    loader = RepoLoader(Path("examples/vulnerable-bank-api"))
    if not loader.target_path.exists():
        pytest.skip("examples dir missing")
    summary = loader.load_files()
    
    detector = JavaScriptLimitDetector()
    findings = detector.detect(summary.supported_files)
    
    assert len(findings) > 0
    rule_ids = [f.rule_id for f in findings]
    assert "JS_BUFFER_ALLOC_FIXED_SIZE" in rule_ids
    assert "JS_CRYPTO_LENGTH_LIMIT" in rule_ids
    assert "JS_CRYPTO_TRUNCATION_LIMIT" in rule_ids
    assert "JS_CRYPTO_LIMIT_CONSTANT" in rule_ids
