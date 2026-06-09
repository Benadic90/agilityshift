import re
from agilityshift.models import ScannedFile, Finding

class JavaScriptLimitDetector:
    # Rule 1: Fixed Buffer allocations.
    # Why risky: Post-Quantum algorithms like ML-DSA require thousands of bytes.
    # Allocating a small, hardcoded buffer (like 256 bytes) will overflow or crash during migration.
    RE_BUFFER_ALLOC = re.compile(r"Buffer\.alloc\(\s*(\d+)\s*\)")
    
    # Rule 2: Fixed Unsafe Buffer allocations.
    # Same risk as above, but unsafe allocation introduces extra memory safety risks.
    RE_BUFFER_ALLOC_UNSAFE = re.compile(r"Buffer\.allocUnsafe\(\s*(\d+)\s*\)")
    
    # Rule 3: Crypto length limits.
    # Why risky: PQC material is much larger than classic RSA/ECC. Hardcoded validation checks
    # (e.g. signature.length > 256) will block legitimate PQC keys/signatures.
    RE_CRYPTO_LENGTH = re.compile(
        r"\b([a-zA-Z0-9_]*?(?:signature|sig|token|jwt|publickey|key|cert|proof|attestation)[a-zA-Z0-9_]*?)\.length\s*(?:>|>=)\s*(\d+)",
        re.IGNORECASE
    )
    
    # Rule 4: Crypto truncation.
    # Why risky: Truncating a PQC signature to a classic size (e.g. 256 bytes) silently destroys it.
    RE_CRYPTO_TRUNC = re.compile(
        r"\b([a-zA-Z0-9_]*?(?:signature|sig|token|jwt|publickey|key|cert|proof|attestation)[a-zA-Z0-9_]*?)\.(?:slice|substring|substr)\(\s*0\s*,\s*([A-Za-z0-9_]+)\s*\)",
        re.IGNORECASE
    )
    
    # Rule 5: Crypto size constants.
    # Why risky: Constants named like MAX_SIGNATURE_SIZE defined to classic limits will silently cap buffers across the app.
    RE_CRYPTO_CONST = re.compile(
        r"\bconst\s+([A-Za-z0-9_]*?(?:SIGNATURE|SIG|PUBLIC_KEY|PRIVATE_KEY|KEY|TOKEN|JWT|CERT|CERTIFICATE|PROOF|ATTESTATION)[A-Za-z0-9_]*?)\s*=\s*(\d+)\s*;?",
        re.IGNORECASE
    )

    def detect(self, scanned_files: list[ScannedFile]) -> list[Finding]:
        findings = []
        for file in scanned_files:
            if not self._is_js_file(file):
                continue
            
            for idx, line in enumerate(file.lines):
                line_number = idx + 1
                
                # Rule 1
                for match in self.RE_BUFFER_ALLOC.finditer(line):
                    limit = int(match.group(1))
                    findings.append(self._make_finding(
                        rule_id="JS_BUFFER_ALLOC_FIXED_SIZE",
                        title="Fixed-size Buffer allocation",
                        description="This buffer assumes signatures fit inside a fixed byte limit.",
                        file_path=file.relative_path,
                        line_number=line_number,
                        line_text=line.strip(),
                        current_limit=limit,
                        limit_unit="bytes",
                        severity=self._severity_for_limit(limit, default="MEDIUM"),
                        suggestion='Use dynamic Buffer.from(signature, "base64") and validate against a configurable PQC migration policy.'
                    ))

                # Rule 2
                for match in self.RE_BUFFER_ALLOC_UNSAFE.finditer(line):
                    limit = int(match.group(1))
                    findings.append(self._make_finding(
                        rule_id="JS_BUFFER_ALLOC_UNSAFE_FIXED_SIZE",
                        title="Fixed-size unsafe Buffer allocation",
                        description="This unsafe buffer assumes signatures fit inside a fixed byte limit.",
                        file_path=file.relative_path,
                        line_number=line_number,
                        line_text=line.strip(),
                        current_limit=limit,
                        limit_unit="bytes",
                        severity=self._severity_for_limit(limit, default="MEDIUM"),
                        suggestion='Avoid fixed unsafe buffers for cryptographic material. Use dynamic decoding and explicit validation.'
                    ))

                # Rule 3
                for match in self.RE_CRYPTO_LENGTH.finditer(line):
                    var_name = match.group(1).lower()
                    limit = int(match.group(2))
                    
                    if "signature" in var_name or "sig" in var_name:
                        sev = "CRITICAL" if limit <= 512 else "MEDIUM"
                    elif any(k in var_name for k in ["publickey", "key", "cert", "token"]):
                        sev = "HIGH" if limit <= 2048 else "MEDIUM"
                    else:
                        sev = "MEDIUM"

                    findings.append(self._make_finding(
                        rule_id="JS_CRYPTO_LENGTH_LIMIT",
                        title="Hardcoded crypto length validation",
                        description="Hardcoded length checks will fail when PQC keys and signatures are introduced.",
                        file_path=file.relative_path,
                        line_number=line_number,
                        line_text=line.strip(),
                        current_limit=limit,
                        limit_unit="chars/bytes",
                        severity=sev,
                        suggestion="Replace hardcoded length checks with configurable limits based on target PQC profiles."
                    ))

                # Rule 4
                for match in self.RE_CRYPTO_TRUNC.finditer(line):
                    val = match.group(2)
                    if val.isdigit():
                        limit = int(val)
                        sev = "HIGH" if limit <= 512 else "MEDIUM"
                    else:
                        limit = None
                        sev = "MEDIUM"

                    findings.append(self._make_finding(
                        rule_id="JS_CRYPTO_TRUNCATION_LIMIT",
                        title="Possible crypto material truncation",
                        description="Truncating crypto material will silently destroy PQC keys and signatures.",
                        file_path=file.relative_path,
                        line_number=line_number,
                        line_text=line.strip(),
                        current_limit=limit,
                        limit_unit="chars/bytes",
                        severity=sev,
                        suggestion="Do not truncate signatures, keys, or tokens. Decode and validate complete cryptographic material."
                    ))

                # Rule 5
                for match in self.RE_CRYPTO_CONST.finditer(line):
                    limit = int(match.group(2))
                    findings.append(self._make_finding(
                        rule_id="JS_CRYPTO_LIMIT_CONSTANT",
                        title="Hardcoded cryptographic size constant",
                        description="Hardcoded constants for crypto sizes will break during PQC migration.",
                        file_path=file.relative_path,
                        line_number=line_number,
                        line_text=line.strip(),
                        current_limit=limit,
                        limit_unit="bytes/chars",
                        severity=self._severity_for_limit(limit, default="MEDIUM"),
                        suggestion="Move crypto-size limits into a configurable PQC migration policy."
                    ))

        return self._dedupe_findings(findings)

    def _is_js_file(self, scanned_file: ScannedFile) -> bool:
        return scanned_file.extension in {".js", ".ts", ".jsx", ".tsx"}

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
