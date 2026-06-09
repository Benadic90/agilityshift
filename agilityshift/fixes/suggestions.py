from agilityshift.models import Finding

class SuggestionEngine:
    def suggest_for_findings(self, findings: list[Finding]) -> list[Finding]:
        return [self.suggest_for_finding(f) for f in findings]

    def suggest_for_finding(self, finding: Finding) -> Finding:
        # We always enforce manual review. Auto-patching cryptographic limits is 
        # highly dangerous and can silently drop security validation checks if done blindly.
        # Different codebase layers (DB, JS, APIs) require context-aware migration paths.
        finding.manual_review_required = True
        
        rule_id = finding.rule_id
        
        if rule_id == "JS_BUFFER_ALLOC_FIXED_SIZE":
            finding.fix_title = "Use dynamic buffer decoding"
            finding.fix_description = "Fixed-size buffers can truncate or reject larger PQC signatures. Decode the complete signature dynamically and validate it against a configurable policy."
            finding.suggested_fix = "Replace Buffer.alloc(number) with Buffer.from(signature, \"base64\") and validate the decoded length."
            finding.safe_example = 'const sigBuffer = Buffer.from(signature, "base64");\n\nif (sigBuffer.length > MAX_PQC_SIGNATURE_BYTES) {\n  throw new Error("Signature exceeds configured PQC migration policy");\n}'
            finding.fix_confidence = "HIGH"
            
        elif rule_id == "JS_BUFFER_ALLOC_UNSAFE_FIXED_SIZE":
            finding.fix_title = "Avoid unsafe fixed-size buffers"
            finding.fix_description = "Buffer.allocUnsafe with fixed limits is risky for cryptographic material because it may allocate memory unsafely and still fail for larger PQC signatures."
            finding.suggested_fix = 'Use Buffer.from(signature, "base64") or a safe dynamic allocation method and validate against a configurable PQC policy.'
            finding.safe_example = 'const sigBuffer = Buffer.from(signature, "base64");\n\nif (sigBuffer.length > MAX_PQC_SIGNATURE_BYTES) {\n  throw new Error("Signature exceeds configured PQC migration policy");\n}'
            finding.fix_confidence = "HIGH"
            
        elif rule_id == "JS_CRYPTO_LENGTH_LIMIT" or rule_id == "JS_CRYPTO_LIMIT_CONS": # JS_CRYPTO_LIMIT_CONS is what my JS detector creates
            finding.fix_title = "Replace hardcoded crypto length check"
            finding.fix_description = "Hardcoded length checks may reject larger PQC signatures, keys, certificates, tokens, or proofs."
            finding.suggested_fix = "Move crypto-size limits into a configuration file based on the selected PQC migration profile."
            finding.safe_example = 'const MAX_PQC_SIGNATURE_BYTES = config.crypto.maxSignatureBytes;\n\nif (Buffer.byteLength(signature, "base64") > MAX_PQC_SIGNATURE_BYTES) {\n  throw new Error("Signature exceeds configured PQC policy");\n}'
            finding.fix_confidence = "HIGH"
            
        elif rule_id == "JS_CRYPTO_TRUNCATION_LIMIT" or rule_id == "JS_CRYPTO_TRUNC_LIMIT":
            finding.fix_title = "Remove cryptographic material truncation"
            finding.fix_description = "Truncating signatures, keys, or tokens may break verification and can corrupt cryptographic material after PQC migration."
            finding.suggested_fix = "Do not use slice/substring/substr to shorten cryptographic material. Validate full input instead."
            finding.safe_example = 'const normalizedSignature = signature.trim();\n\nif (!normalizedSignature) {\n  throw new Error("Missing signature");\n}'
            finding.fix_confidence = "MEDIUM"
            
        elif rule_id == "JS_CRYPTO_LIMIT_CONSTANT":
            finding.fix_title = "Move crypto-size constant to PQC policy"
            finding.fix_description = "Hardcoded crypto-size constants can become outdated when the migration target changes."
            finding.suggested_fix = "Store crypto-size limits in a configurable PQC migration policy."
            finding.safe_example = 'const cryptoPolicy = {\n  targetProfile: "ML-DSA-65",\n  maxSignatureBytes: 5000\n};'
            finding.fix_confidence = "MEDIUM"
            
        elif rule_id == "SQL_CRYPTO_VARCHAR_LIMIT":
            finding.fix_title = "Use migration-safe database storage"
            finding.fix_description = "VARCHAR limits may be too small for larger PQC signatures, keys, certificates, or proofs."
            finding.suggested_fix = "Use TEXT, BYTEA, VARBINARY, BLOB, or increase the column size according to the target PQC profile and database engine."
            finding.safe_example = "PostgreSQL:\nsignature BYTEA\n\nMySQL:\nsignature VARBINARY(5000)\n\nGeneric:\nsignature TEXT"
            finding.fix_confidence = "HIGH"
            
        elif rule_id == "SQL_CRYPTO_CHAR_LIMIT":
            finding.fix_title = "Avoid fixed CHAR for cryptographic material"
            finding.fix_description = "Fixed CHAR columns are not suitable for variable-size cryptographic material during PQC migration."
            finding.suggested_fix = "Use TEXT, BYTEA, VARBINARY, or BLOB instead of fixed CHAR."
            finding.safe_example = "signature TEXT"
            finding.fix_confidence = "HIGH"
            
        elif rule_id == "SQL_CRYPTO_VARBINARY_LIMIT":
            finding.fix_title = "Increase binary crypto storage size"
            finding.fix_description = "This binary column may be too small for larger PQC signatures, keys, ciphertexts, or proofs."
            finding.suggested_fix = "Increase VARBINARY size or use BLOB/BYTEA depending on database engine."
            finding.safe_example = "signature VARBINARY(5000)"
            finding.fix_confidence = "HIGH"
            
        elif rule_id == "SQL_CRYPTO_NVARCHAR_LIMIT":
            finding.fix_title = "Use migration-safe text/binary storage"
            finding.fix_description = "NVARCHAR limits may reject larger cryptographic material after PQC migration."
            finding.suggested_fix = "Use TEXT, BYTEA, VARBINARY, BLOB, or increase max length according to PQC policy."
            finding.safe_example = "signature TEXT"
            finding.fix_confidence = "MEDIUM"
            
        elif rule_id == "API_CRYPTO_MAX_LENGTH_LIMIT":
            finding.fix_title = "Increase API maxLength for PQC migration"
            finding.fix_description = "API schema maxLength may reject larger PQC signatures, keys, certificates, tokens, or proofs."
            finding.suggested_fix = "Increase maxLength based on the selected PQC profile or make the limit configurable."
            finding.safe_example = "signature:\n  type: string\n  maxLength: 5000"
            finding.fix_confidence = "HIGH"
            
        elif rule_id == "API_JSON_CRYPTO_MAX_LENGTH_LIMIT":
            finding.fix_title = "Increase JSON schema maxLength"
            finding.fix_description = "JSON schema maxLength may reject larger post-quantum cryptographic material."
            finding.suggested_fix = "Increase maxLength or make it configurable based on target PQC profile."
            finding.safe_example = '{\n  "signature": {\n    "type": "string",\n    "maxLength": 5000\n  }\n}'
            finding.fix_confidence = "HIGH"
            
        elif rule_id == "API_SMALL_REQUEST_BODY_LIMIT":
            finding.fix_title = "Increase request body limit safely"
            finding.fix_description = "Small request body limits may reject larger PQC signatures, certificates, or proof payloads."
            finding.suggested_fix = "Increase request body limit based on maximum expected PQC payload size and add explicit validation."
            finding.safe_example = 'app.use(express.json({ limit: "16kb" }));'
            finding.fix_confidence = "MEDIUM"
            
        else:
            finding.fix_title = "Manual review required"
            finding.fix_description = "This finding may represent a PQC migration breakage risk, but no specific fix template exists yet."
            finding.suggested_fix = "Review this code, database field, or API contract against the target PQC migration profile."
            finding.safe_example = "None"
            finding.fix_confidence = "LOW"
            
        return finding
