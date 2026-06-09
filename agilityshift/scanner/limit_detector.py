import tree_sitter
import tree_sitter_javascript
import tree_sitter_typescript
from agilityshift.models import ScannedFile, Finding

class JavaScriptLimitDetector:
    def __init__(self):
        self.js_lang = tree_sitter.Language(tree_sitter_javascript.language())
        self.ts_lang = tree_sitter.Language(tree_sitter_typescript.language_typescript())
        self.js_parser = tree_sitter.Parser(self.js_lang)
        self.ts_parser = tree_sitter.Parser(self.ts_lang)

    def detect(self, scanned_files: list[ScannedFile]) -> list[Finding]:
        findings = []
        for file in scanned_files:
            if file.extension in {".js", ".jsx"}:
                parser = self.js_parser
            elif file.extension in {".ts", ".tsx"}:
                parser = self.ts_parser
            else:
                continue
            
            code_bytes = file.content.encode("utf-8")
            tree = parser.parse(code_bytes)
            findings.extend(self._traverse_and_find(tree.root_node, file, code_bytes))

        return self._dedupe_findings(findings)

    def _traverse_and_find(self, node, file: ScannedFile, code_bytes: bytes) -> list[Finding]:
        findings = []
        
        def walk(n):
            # Rule 1 & 2: Buffer.alloc / Buffer.allocUnsafe
            if n.type == "call_expression":
                func_node = n.child_by_field_name("function")
                if func_node and func_node.type == "member_expression":
                    obj_node = func_node.child_by_field_name("object")
                    prop_node = func_node.child_by_field_name("property")
                    if obj_node and prop_node and obj_node.type == "identifier" and prop_node.type == "property_identifier":
                        obj_name = code_bytes[obj_node.start_byte:obj_node.end_byte].decode("utf-8")
                        prop_name = code_bytes[prop_node.start_byte:prop_node.end_byte].decode("utf-8")
                        
                        if obj_name == "Buffer" and prop_name in {"alloc", "allocUnsafe"}:
                            args_node = n.child_by_field_name("arguments")
                            if args_node and len(args_node.named_children) >= 1:
                                arg = args_node.named_children[0]
                                if arg.type == "number":
                                    limit = int(code_bytes[arg.start_byte:arg.end_byte].decode("utf-8"))
                                    line_num = n.start_point[0] + 1
                                    line_text = file.lines[line_num - 1].strip() if line_num - 1 < len(file.lines) else ""
                                    
                                    if prop_name == "alloc":
                                        findings.append(self._make_finding(
                                            "JS_BUFFER_ALLOC_FIXED_SIZE", "Fixed-size Buffer allocation",
                                            "This buffer assumes signatures fit inside a fixed byte limit.",
                                            file.relative_path, line_num, line_text, limit, "bytes",
                                            self._severity_for_limit(limit, "MEDIUM"),
                                            'Use dynamic Buffer.from(signature, "base64") and validate against a configurable PQC migration policy.'
                                        ))
                                    else:
                                        findings.append(self._make_finding(
                                            "JS_BUFFER_ALLOC_UNSAFE_FIXED_SIZE", "Fixed-size unsafe Buffer allocation",
                                            "This unsafe buffer assumes signatures fit inside a fixed byte limit.",
                                            file.relative_path, line_num, line_text, limit, "bytes",
                                            self._severity_for_limit(limit, "MEDIUM"),
                                            'Avoid fixed unsafe buffers for cryptographic material. Use dynamic decoding and explicit validation.'
                                        ))
                                        
            # Rule 3: Crypto length validation (e.g. signature.length > 256)
            if n.type == "binary_expression":
                left = n.child_by_field_name("left")
                op = n.child_by_field_name("operator")
                right = n.child_by_field_name("right")
                
                if left and right and op and code_bytes[op.start_byte:op.end_byte].decode("utf-8") in {">", ">="}:
                    if left.type == "member_expression" and right.type == "number":
                        obj_node = left.child_by_field_name("object")
                        prop_node = left.child_by_field_name("property")
                        if obj_node and prop_node and prop_node.type == "property_identifier":
                            prop_name = code_bytes[prop_node.start_byte:prop_node.end_byte].decode("utf-8")
                            if prop_name == "length":
                                var_name = code_bytes[obj_node.start_byte:obj_node.end_byte].decode("utf-8").lower()
                                limit = int(code_bytes[right.start_byte:right.end_byte].decode("utf-8"))
                                
                                is_crypto = False
                                sev = "MEDIUM"
                                if "signature" in var_name or "sig" in var_name:
                                    is_crypto = True
                                    sev = "CRITICAL" if limit <= 512 else "MEDIUM"
                                elif any(k in var_name for k in ["publickey", "key", "cert", "token", "proof", "attestation"]):
                                    is_crypto = True
                                    sev = "HIGH" if limit <= 2048 else "MEDIUM"
                                    
                                if is_crypto:
                                    line_num = n.start_point[0] + 1
                                    line_text = file.lines[line_num - 1].strip() if line_num - 1 < len(file.lines) else ""
                                    findings.append(self._make_finding(
                                        "JS_CRYPTO_LENGTH_LIMIT", "Hardcoded crypto length validation",
                                        "Hardcoded length checks will fail when PQC keys and signatures are introduced.",
                                        file.relative_path, line_num, line_text, limit, "chars/bytes", sev,
                                        "Replace hardcoded length checks with configurable limits based on target PQC profiles."
                                    ))
                                    
            # Rule 4: Crypto truncation (e.g. signature.slice(0, 256))
            if n.type == "call_expression":
                func_node = n.child_by_field_name("function")
                if func_node and func_node.type == "member_expression":
                    obj_node = func_node.child_by_field_name("object")
                    prop_node = func_node.child_by_field_name("property")
                    if obj_node and prop_node and prop_node.type == "property_identifier":
                        prop_name = code_bytes[prop_node.start_byte:prop_node.end_byte].decode("utf-8")
                        if prop_name in {"slice", "substring", "substr"}:
                            var_name = code_bytes[obj_node.start_byte:obj_node.end_byte].decode("utf-8").lower()
                            is_crypto = any(k in var_name for k in ["signature", "sig", "token", "jwt", "publickey", "key", "cert", "proof", "attestation"])
                            if is_crypto:
                                args_node = n.child_by_field_name("arguments")
                                if args_node and len(args_node.named_children) >= 2:
                                    arg1 = args_node.named_children[0]
                                    arg2 = args_node.named_children[1]
                                    if arg1.type == "number" and arg2.type == "number":
                                        val1 = code_bytes[arg1.start_byte:arg1.end_byte].decode("utf-8")
                                        if val1 == "0":
                                            limit = int(code_bytes[arg2.start_byte:arg2.end_byte].decode("utf-8"))
                                            sev = "HIGH" if limit <= 512 else "MEDIUM"
                                            line_num = n.start_point[0] + 1
                                            line_text = file.lines[line_num - 1].strip() if line_num - 1 < len(file.lines) else ""
                                            findings.append(self._make_finding(
                                                "JS_CRYPTO_TRUNCATION_LIMIT", "Possible crypto material truncation",
                                                "Truncating crypto material will silently destroy PQC keys and signatures.",
                                                file.relative_path, line_num, line_text, limit, "chars/bytes", sev,
                                                "Do not truncate signatures, keys, or tokens. Decode and validate complete cryptographic material."
                                            ))

            # Rule 5: Crypto size constants (e.g. const MAX_SIGNATURE_SIZE = 256;)
            if n.type == "variable_declarator":
                name_node = n.child_by_field_name("name")
                value_node = n.child_by_field_name("value")
                if name_node and value_node and name_node.type == "identifier" and value_node.type == "number":
                    var_name = code_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8").upper()
                    is_crypto_const = any(k in var_name for k in ["SIGNATURE", "SIG", "PUBLIC_KEY", "PRIVATE_KEY", "KEY", "TOKEN", "JWT", "CERT", "CERTIFICATE", "PROOF", "ATTESTATION"])
                    if is_crypto_const:
                        limit = int(code_bytes[value_node.start_byte:value_node.end_byte].decode("utf-8"))
                        line_num = n.start_point[0] + 1
                        line_text = file.lines[line_num - 1].strip() if line_num - 1 < len(file.lines) else ""
                        findings.append(self._make_finding(
                            "JS_CRYPTO_LIMIT_CONSTANT", "Hardcoded cryptographic size constant",
                            "Hardcoded constants for crypto sizes will break during PQC migration.",
                            file.relative_path, line_num, line_text, limit, "bytes/chars",
                            self._severity_for_limit(limit, "MEDIUM"),
                            "Move crypto-size limits into a configurable PQC migration policy."
                        ))

            for child in n.children:
                walk(child)

        walk(node)
        return findings

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
