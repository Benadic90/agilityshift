import ast
from agilityshift.models import ScannedFile, Finding

class PythonLimitDetector:
    def detect(self, scanned_files: list[ScannedFile]) -> list[Finding]:
        findings = []
        for file in scanned_files:
            if file.extension != ".py":
                continue
            
            try:
                tree = ast.parse(file.content)
                visitor = PythonASTVisitor(file, self)
                visitor.visit(tree)
                findings.extend(visitor.findings)
            except SyntaxError:
                # Skip files that have syntax errors
                continue
                
        return self._dedupe_findings(findings)

    def _severity_for_limit(self, limit: int | None, default: str = "MEDIUM") -> str:
        if limit is None:
            return default
        if limit <= 256:
            return "CRITICAL"
        if limit <= 512:
            return "HIGH"
        return default

    def _make_finding(self, rule_id: str, title: str, description: str, file_path: str,
                      line_number: int, line_text: str, current_limit: int | None,
                      limit_unit: str, severity: str, suggestion: str) -> Finding:
        return Finding(
            rule_id=rule_id,
            title=title,
            description=description,
            file_path=file_path,
            line_number=line_number,
            line_text=line_text,
            current_limit=current_limit,
            limit_unit=limit_unit,
            finding_type="code_limit",
            severity=severity,
            confidence="HIGH",
            suggestion=suggestion
        )

    def _dedupe_findings(self, findings: list[Finding]) -> list[Finding]:
        seen = set()
        deduped = []
        for f in findings:
            key = (f.rule_id, f.file_path, f.line_number)
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped

class PythonASTVisitor(ast.NodeVisitor):
    def __init__(self, file: ScannedFile, detector: PythonLimitDetector):
        self.file = file
        self.detector = detector
        self.findings = []

    def _get_line_text(self, node) -> str:
        line_num = node.lineno
        if line_num - 1 < len(self.file.lines):
            return self.file.lines[line_num - 1].strip()
        return ""

    def visit_Assign(self, node):
        # Detect crypto size constants e.g. MAX_SIGNATURE_SIZE = 256
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Constant):
            var_name = node.targets[0].id.upper()
            is_crypto_const = any(k in var_name for k in ["SIGNATURE", "SIG", "PUBLIC_KEY", "PRIVATE_KEY", "KEY", "TOKEN", "JWT", "CERT", "CERTIFICATE", "PROOF", "ATTESTATION"])
            
            if is_crypto_const and isinstance(node.value.value, (int, float)):
                limit = int(node.value.value)
                self.findings.append(self.detector._make_finding(
                    "PY_CRYPTO_LIMIT_CONSTANT", "Hardcoded cryptographic size constant",
                    "Hardcoded constants for crypto sizes will break during PQC migration.",
                    self.file.relative_path, node.lineno, self._get_line_text(node), limit, "bytes/chars",
                    self.detector._severity_for_limit(limit, "MEDIUM"),
                    "Move crypto-size limits into a configurable PQC migration policy."
                ))
        self.generic_visit(node)

    def visit_Compare(self, node):
        # Detect len(signature) > 256
        if isinstance(node.left, ast.Call) and isinstance(node.left.func, ast.Name) and node.left.func.id == "len":
            if node.left.args and isinstance(node.left.args[0], ast.Name):
                var_name = node.left.args[0].id.lower()
                is_crypto = any(k in var_name for k in ["signature", "sig", "publickey", "privatekey", "key", "cert", "token", "proof", "attestation"])
                
                if is_crypto and len(node.ops) == 1 and isinstance(node.ops[0], (ast.Gt, ast.GtE, ast.Lt, ast.LtE, ast.Eq)):
                    if len(node.comparators) == 1 and isinstance(node.comparators[0], ast.Constant) and isinstance(node.comparators[0].value, int):
                        limit = int(node.comparators[0].value)
                        
                        sev = "MEDIUM"
                        if "signature" in var_name or "sig" in var_name:
                            sev = "CRITICAL" if limit <= 512 else "MEDIUM"
                        elif any(k in var_name for k in ["publickey", "key", "cert", "token", "proof", "attestation"]):
                            sev = "HIGH" if limit <= 2048 else "MEDIUM"
                            
                        self.findings.append(self.detector._make_finding(
                            "PY_CRYPTO_LENGTH_LIMIT", "Hardcoded crypto length validation",
                            "Hardcoded length checks will fail when PQC keys and signatures are introduced.",
                            self.file.relative_path, node.lineno, self._get_line_text(node), limit, "chars/bytes", sev,
                            "Replace hardcoded length checks with configurable limits based on target PQC profiles."
                        ))
        self.generic_visit(node)

    def visit_Subscript(self, node):
        # Detect signature[:256]
        if isinstance(node.slice, ast.Slice):
            if isinstance(node.value, ast.Name):
                var_name = node.value.id.lower()
                is_crypto = any(k in var_name for k in ["signature", "sig", "token", "jwt", "publickey", "key", "cert", "proof", "attestation"])
                if is_crypto and isinstance(node.slice.upper, ast.Constant) and isinstance(node.slice.upper.value, int):
                    limit = int(node.slice.upper.value)
                    sev = "HIGH" if limit <= 512 else "MEDIUM"
                    self.findings.append(self.detector._make_finding(
                        "PY_CRYPTO_TRUNCATION_LIMIT", "Possible crypto material truncation",
                        "Truncating crypto material will silently destroy PQC keys and signatures.",
                        self.file.relative_path, node.lineno, self._get_line_text(node), limit, "chars/bytes", sev,
                        "Do not truncate signatures, keys, or tokens. Decode and validate complete cryptographic material."
                    ))
        self.generic_visit(node)
