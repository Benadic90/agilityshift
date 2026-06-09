import json
import uuid
from pathlib import Path
from agilityshift.models import Finding, PQCProfile

class CBOMReportWriter:
    def infer_asset_type_and_name(self, finding: Finding) -> tuple[str, str]:
        text = finding.line_text.lower() if finding.line_text else ""
        if any(keyword in text for keyword in ["signature", "sig", "sign", "verify"]):
            return "digital_signature", "signature"
        if any(keyword in text for keyword in ["public_key", "publickey", "public key"]):
            return "public_key", "public_key"
        if any(keyword in text for keyword in ["private_key", "privatekey", "private key"]):
            return "private_key", "private_key"
        if any(keyword in text for keyword in ["certificate", "cert"]):
            return "certificate", "certificate"
        if any(keyword in text for keyword in ["jwt", "token"]):
            return "token", "token"
        if any(keyword in text for keyword in ["proof", "attestation"]):
            return "proof", "proof"
        return "unknown_crypto_material", "crypto_material"

    def infer_algorithm(self, finding: Finding) -> str | None:
        text = finding.line_text if finding.line_text else ""
        text_lower = text.lower()
        if "rs256" in text_lower:
            return "RS256"
        if "rsa" in text_lower:
            return "RSA"
        if "ecdsa" in text_lower:
            return "ECDSA"
        if "sha256" in text_lower or "sha-256" in text_lower:
            return "SHA-256"
        if "ml-dsa" in text_lower:
            return "ML-DSA"
        return None

    def infer_usage(self, finding: Finding) -> str:
        path = finding.file_path.lower() if finding.file_path else ""
        if "auth" in path or "verify" in path or "signature" in path:
            return "authentication or signature verification"
        if "payment" in path or "transaction" in path:
            return "payment verification"
            
        if finding.finding_type == "database_schema":
            return "cryptographic material storage"
        if finding.finding_type == "api_contract":
            return "API validation of cryptographic material"
            
        return "cryptographic material handling"

    def finding_to_crypto_asset(self, finding: Finding, index: int) -> dict:
        asset_type, name = self.infer_asset_type_and_name(finding)
        
        return {
            "id": f"crypto-asset-{index}",
            "type": asset_type,
            "name": name,
            "algorithm": self.infer_algorithm(finding),
            "usage": self.infer_usage(finding),
            "location": {
                "file": finding.file_path,
                "line": finding.line_number
            },
            "sourceRuleId": finding.rule_id,
            "migrationRisk": finding.risk_message,
            "severity": finding.severity,
            "recommendedAction": finding.developer_guidance if finding.developer_guidance else finding.suggested_fix
        }

    def build_cbom_data(self, target_path: Path, profile: PQCProfile, findings: list[Finding]) -> dict:
        assets = []
        critical = 0
        high = 0
        medium = 0
        low = 0
        
        for idx, f in enumerate(findings, start=1):
            assets.append(self.finding_to_crypto_asset(f, idx))
            s = f.severity.upper()
            if s == "CRITICAL":
                critical += 1
            elif s == "HIGH":
                high += 1
            elif s == "MEDIUM":
                medium += 1
            elif s == "LOW":
                low += 1

        req_bytes = profile.signature_bytes if profile and hasattr(profile, "signature_bytes") else None

        return {
            "bomFormat": "CycloneDX-inspired",
            "specVersion": "experimental",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "tool": {
                    "name": "AgilityShift",
                    "version": "0.1.0"
                },
                "target": {
                    "path": str(target_path),
                    "pqcProfile": profile.name if profile else "Unknown",
                    "requiredSignatureBytes": req_bytes
                },
                "note": "This is a CBOM-style crypto inventory export for PQC migration readiness. It is not a complete official CycloneDX CBOM implementation yet."
            },
            "cryptoAssets": assets,
            "summary": {
                "totalCryptoAssets": len(assets),
                "criticalAssets": critical,
                "highAssets": high,
                "mediumAssets": medium,
                "lowAssets": low,
                "pqcReadinessConcern": critical > 0 or high > 0
            }
        }

    def write_report(self, output_path: Path, target_path: Path, profile: PQCProfile, findings: list[Finding]) -> Path:
        cbom_data = self.build_cbom_data(target_path, profile, findings)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(cbom_data, f, indent=2)
        return output_path
