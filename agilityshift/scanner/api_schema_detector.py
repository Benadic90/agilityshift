import re
from agilityshift.models import ScannedFile, Finding

class APISchemaDetector:
    # Rule 1/2: Extract YAML or JSON fields
    # We use basic line-based regexes to parse without loading the entire DOM,
    # preventing crashes on incomplete/invalid files.
    RE_YAML_FIELD = re.compile(r"^\s*([a-zA-Z0-9_\"'`]+)\s*:(?!\s*\S+\s*:\s*)")
    RE_JSON_FIELD = re.compile(r"^\s*\"([a-zA-Z0-9_]+)\"\s*:\s*\{")
    RE_MAX_LENGTH = re.compile(r"[\"']?maxLength[\"']?\s*:\s*(\d+)")
    
    # Rule 3: Extract body size limits
    RE_BODY_LIMIT = re.compile(r"[\"']?(?:bodyLimit|maxBodySize|requestBodyLimit|limit)[\"']?\s*:\s*[\"']?(\d+(?:\.\d+)?[a-zA-Z]*)[\"']?", re.IGNORECASE)

    CRYPTO_WORDS = {"sig", "key", "jwt", "cert", "proof"}
    CRYPTO_UNAMBIGUOUS = [
        "signature", "public_key", "private_key", "publickey", "privatekey", "token",
        "certificate", "attestation", "signed_payload", "signedpayload",
        "signed_data", "signeddata", "crypto_blob", "cryptoblob",
        "verification_proof", "verificationproof", "attestationproof", "attestation_proof"
    ]

    def detect(self, scanned_files: list[ScannedFile]) -> list[Finding]:
        findings = []
        for file in scanned_files:
            if not self._is_api_schema_file(file):
                continue
            
            has_crypto_context = self._file_contains_crypto_context(file)
            
            for i, line in enumerate(file.lines):
                line_number = i + 1
                
                is_yaml = file.extension in {".yaml", ".yml"}
                is_json = file.extension == ".json"
                
                # Extract field context
                field_name = None
                if is_yaml:
                    field_name = self._extract_yaml_field(line)
                if is_json and not field_name:
                    field_name = self._extract_json_field(line)
                if is_json and not field_name:
                    m = re.match(r'^\s*"([a-zA-Z0-9_]+)"\s*:', line)
                    if m: field_name = m.group(1)

                if field_name and self._is_crypto_field(field_name):
                    # Look ahead 10 lines to find maxLength associated with this field
                    for j in range(1, 11):
                        if i + j >= len(file.lines):
                            break
                        lookahead_line = file.lines[i + j]
                        limit = self._extract_max_length(lookahead_line)
                        if limit is not None:
                            rule_id = "API_JSON_CRYPTO_MAX_LENGTH_LIMIT" if is_json else "API_CRYPTO_MAX_LENGTH_LIMIT"
                            title = "Crypto-related JSON schema maxLength limit" if is_json else "Crypto-related API maxLength limit"
                            desc = "This JSON schema may reject larger post-quantum cryptographic material." if is_json else "This API contract may reject larger post-quantum signatures, keys, certificates, or proofs because maxLength is too small."
                            severity = self._severity_for_api_limit(field_name, limit)
                            
                            findings.append(self._make_finding(
                                rule_id=rule_id,
                                title=title,
                                description=desc,
                                file_path=file.relative_path,
                                line_number=i + j + 1,
                                line_text=lookahead_line.strip(),
                                current_limit=limit,
                                limit_unit="characters",
                                severity=severity,
                                suggestion="Increase maxLength or use a configurable policy based on selected PQC algorithm profile." if is_json else "Increase API maxLength based on target PQC migration profile or make it configurable."
                            ))
                            break

                # Detect request body limits conditionally
                if has_crypto_context:
                    body_match = self.RE_BODY_LIMIT.search(line)
                    if body_match:
                        raw_val = body_match.group(1)
                        bytes_val = self._parse_size_to_bytes(raw_val)
                        if bytes_val is not None:
                            sev = "MEDIUM"
                            if bytes_val <= 1024:
                                sev = "CRITICAL"
                            elif bytes_val <= 2048:
                                sev = "HIGH"
                            
                            findings.append(self._make_finding(
                                rule_id="API_SMALL_REQUEST_BODY_LIMIT",
                                title="Small request body limit may reject PQC payloads",
                                description="This API request body limit may be too small when signatures, keys, or certificates grow during PQC migration.",
                                file_path=file.relative_path,
                                line_number=line_number,
                                line_text=line.strip(),
                                current_limit=bytes_val,
                                limit_unit="bytes",
                                severity=sev,
                                suggestion="Increase request body limit based on maximum expected PQC payload size and apply explicit validation."
                            ))

        return self._dedupe_findings(findings)

    def _is_api_schema_file(self, file: ScannedFile) -> bool:
        return file.extension in {".yaml", ".yml", ".json"}

    def _normalize_field_name(self, name: str) -> str:
        return name.replace('"', '').replace("'", "").replace("`", "").lower()

    def _is_crypto_field(self, field_name: str) -> bool:
        name = self._normalize_field_name(field_name)
        words = re.split(r'[^a-z0-9]', name)
        if any(w in self.CRYPTO_WORDS for w in words):
            return True
        for u in self.CRYPTO_UNAMBIGUOUS:
            if u in name:
                return True
        return False

    def _severity_for_api_limit(self, field_name: str, limit: int) -> str:
        name = self._normalize_field_name(field_name)
        is_sig = "signature" in name or "sig" in name or "proof" in name or "attestation" in name
        is_key = "key" in name or "token" in name or "jwt" in name
        is_cert = "cert" in name
        
        if is_sig and limit <= 512:
            return "CRITICAL"
        if is_key and limit <= 1024:
            return "HIGH"
        if is_cert and limit <= 2048:
            return "HIGH"
        return "MEDIUM"

    def _extract_yaml_field(self, line: str) -> str | None:
        m = self.RE_YAML_FIELD.match(line)
        if m:
            return m.group(1)
        return None

    def _extract_json_field(self, line: str) -> str | None:
        m = self.RE_JSON_FIELD.match(line)
        if m:
            return m.group(1)
        return None

    def _extract_max_length(self, line: str) -> int | None:
        m = self.RE_MAX_LENGTH.search(line)
        if m:
            return int(m.group(1))
        return None

    def _parse_size_to_bytes(self, value: str) -> int | None:
        v = value.strip().lower()
        if v.isdigit():
            return int(v)
        if v.endswith("kb"):
            try:
                num = float(v[:-2].strip())
                return int(num * 1024)
            except ValueError:
                pass
        if v.endswith("k"):
            try:
                num = float(v[:-1].strip())
                return int(num * 1024)
            except ValueError:
                pass
        return None

    def _file_contains_crypto_context(self, file: ScannedFile) -> bool:
        content_lower = file.content.lower()
        check_words = ["signature", "publickey", "certificate", "token", "attestation", "privatekey"]
        return any(w in content_lower for w in check_words)

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
            finding_type="api_contract_limit",
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
