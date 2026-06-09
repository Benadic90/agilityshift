import re
from agilityshift.models import ScannedFile, Finding

class SQLSchemaDetector:
    # Match crypto-related fields with size limits like VARCHAR(256)
    # Group 1: field_name (optional quotes)
    # Group 2: type (VARCHAR, CHAR, NVARCHAR, STRING, VARBINARY)
    # Group 3: limit
    RE_SQL_LIMIT = re.compile(
        r"\b([a-zA-Z0-9_\"'`]+)\s+(VARCHAR|CHAR|NVARCHAR|STRING|VARBINARY)\s*\(\s*(\d+)\s*\)",
        re.IGNORECASE
    )

    def detect(self, scanned_files: list[ScannedFile]) -> list[Finding]:
        findings = []
        for file in scanned_files:
            if not self._is_sql_file(file):
                continue
                
            for idx, line in enumerate(file.lines):
                line_number = idx + 1
                
                for match in self.RE_SQL_LIMIT.finditer(line):
                    raw_field_name = match.group(1)
                    col_type = match.group(2).upper()
                    limit = int(match.group(3))
                    
                    if not self._is_crypto_field(raw_field_name):
                        continue
                        
                    norm_field_name = self._normalize_identifier(raw_field_name)
                    
                    severity = self._severity_for_sql_limit(norm_field_name, limit, col_type)
                    
                    # Determine rule ID and properties based on column type
                    if col_type == "VARCHAR":
                        rule_id = "SQL_CRYPTO_VARCHAR_LIMIT"
                        title = "Crypto-related VARCHAR column limit"
                        desc = "This database column may be too small for larger post-quantum signatures, keys, certificates, or proofs."
                        sugg = "Use TEXT, BYTEA, VARBINARY, BLOB, or a larger column size based on the target PQC migration profile."
                        limit_unit = "characters"
                    elif col_type == "CHAR":
                        rule_id = "SQL_CRYPTO_CHAR_LIMIT"
                        title = "Crypto-related fixed CHAR column limit"
                        desc = "Fixed CHAR columns can be risky for variable-size post-quantum cryptographic material."
                        sugg = "Avoid fixed CHAR for cryptographic material. Use TEXT, BYTEA, VARBINARY, BLOB, or a migration-safe size."
                        limit_unit = "characters"
                    elif col_type == "VARBINARY":
                        rule_id = "SQL_CRYPTO_VARBINARY_LIMIT"
                        title = "Crypto-related VARBINARY column limit"
                        desc = "This binary column may be too small for larger PQC signatures, keys, ciphertexts, or proofs."
                        sugg = "Increase binary storage size according to the target PQC profile or use BLOB/BYTEA."
                        limit_unit = "bytes"
                    else: # NVARCHAR or STRING
                        rule_id = "SQL_CRYPTO_NVARCHAR_LIMIT"
                        title = "Crypto-related NVARCHAR column limit"
                        desc = "This database column may be too small for larger post-quantum signatures, keys, certificates, or proofs."
                        sugg = "Use TEXT, BYTEA, VARBINARY, BLOB, or increase the limit according to PQC profile."
                        limit_unit = "characters"

                    findings.append(self._make_finding(
                        rule_id=rule_id,
                        title=title,
                        description=desc,
                        file_path=file.relative_path,
                        line_number=line_number,
                        line_text=line.strip(),
                        current_limit=limit,
                        limit_unit=limit_unit,
                        severity=severity,
                        suggestion=sugg
                    ))
                    
        return self._dedupe_findings(findings)

    def _is_sql_file(self, file: ScannedFile) -> bool:
        return file.extension in {".sql", ".prisma"}

    def _normalize_identifier(self, identifier: str) -> str:
        return identifier.replace('"', '').replace("'", "").replace("`", "").lower()

    def _is_crypto_field(self, field_name: str) -> bool:
        # Check if the field name implies cryptographic material.
        # We avoid over-matching common words (e.g., 'design' contains 'sig') by using word boundaries or exact substring matches.
        name = self._normalize_identifier(field_name)
        
        words = re.split(r'[^a-z0-9]', name)
        strict_words = {"sig", "key", "jwt", "cert", "proof"}
        if any(w in strict_words for w in words):
            return True
            
        unambiguous = [
            "signature", "public_key", "private_key", "token", 
            "certificate", "attestation", "signed_payload", 
            "signed_data", "crypto_blob", "verification_proof"
        ]
        for u in unambiguous:
            if u in name:
                return True
                
        return False

    def _severity_for_sql_limit(self, field_name: str, limit: int, column_type: str) -> str:
        # Determine risk severity based on column size and crypto type.
        # PQC material is much larger than classical RSA/ECC (e.g., ML-DSA-44 signature is 2420 bytes).
        name = field_name.lower()
        ctype = column_type.upper()
        
        is_sig_proof = "signature" in name or "sig" in name or "proof" in name or "attestation" in name
        is_key_token = "key" in name or "token" in name or "jwt" in name
        is_cert = "cert" in name or "certificate" in name
        
        if ctype == "VARBINARY":
            if is_sig_proof and limit <= 512: return "CRITICAL"
            if is_key_token and limit <= 1024: return "HIGH"
            return "MEDIUM"
        else:
            if is_sig_proof and limit <= 512: return "CRITICAL"
            if is_key_token and limit <= 1024: return "HIGH"
            if is_cert and limit <= 2048: return "HIGH"
            return "MEDIUM"

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
            finding_type="database_limit",
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
