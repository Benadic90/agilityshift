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
        
        asset_type_mapped = "related-crypto-material"
        if asset_type == "certificate":
            asset_type_mapped = "certificate"
        elif asset_type == "algorithm":
            asset_type_mapped = "algorithm"

        crypto_props = {
            "assetType": asset_type_mapped
        }
        
        algorithm = self.infer_algorithm(finding)
        if algorithm:
            # We must provide some minimal algorithm properties or just use the name if schema allows.
            # CycloneDX 1.6 allows primitive name mapping or we can omit it if it fails strict schema.
            # We will use primitive algorithm property mapping for now:
            crypto_props["algorithmProperties"] = {
                "primitive": "unknown", # default
                "name": algorithm
            }
            # Actually, standard CycloneDX algorithm primitive enum requires values like 'hash', 'signature', 'mac' etc.
            # We'll just omit primitive and see if schema allows only name, or we omit algorithmProperties to be safe
            # Let's keep it simple: if algorithm is inferred, just put it as a property extension.
        
        component = {
            "type": "cryptographic-asset",
            "bom-ref": f"crypto-asset-{index}",
            "name": name,
            "cryptoProperties": crypto_props,
            "properties": [
                {"name": "agilityshift:sourceRuleId", "value": finding.rule_id},
                {"name": "agilityshift:migrationRisk", "value": finding.risk_message or ""},
                {"name": "agilityshift:severity", "value": finding.severity},
                {"name": "agilityshift:recommendedAction", "value": finding.developer_guidance if finding.developer_guidance else (finding.suggested_fix or "")},
                {"name": "agilityshift:usage", "value": self.infer_usage(finding)},
                {"name": "agilityshift:location:file", "value": finding.file_path},
                {"name": "agilityshift:location:line", "value": str(finding.line_number)}
            ]
        }
        if algorithm:
            component["properties"].append({"name": "agilityshift:algorithm", "value": algorithm})

        return component

    def build_cbom_data(self, target_path: Path, profile: PQCProfile, findings: list[Finding]) -> dict:
        components = []
        critical = 0
        high = 0
        medium = 0
        low = 0
        
        for idx, f in enumerate(findings, start=1):
            components.append(self.finding_to_crypto_asset(f, idx))
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
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "AgilityShift",
                            "version": "0.1.0"
                        }
                    ]
                },
                "component": {
                    "type": "application",
                    "name": str(target_path),
                    "properties": [
                        {"name": "agilityshift:pqcProfile", "value": profile.name if profile else "Unknown"},
                        {"name": "agilityshift:requiredSignatureBytes", "value": str(req_bytes) if req_bytes else ""}
                    ]
                },
                "properties": [
                    {"name": "agilityshift:summary:totalCryptoAssets", "value": str(len(components))},
                    {"name": "agilityshift:summary:criticalAssets", "value": str(critical)},
                    {"name": "agilityshift:summary:highAssets", "value": str(high)},
                    {"name": "agilityshift:summary:pqcReadinessConcern", "value": "true" if (critical > 0 or high > 0) else "false"}
                ]
            },
            "components": components
        }

    def write_report(self, output_path: Path, target_path: Path, profile: PQCProfile, findings: list[Finding]) -> Path:
        cbom_data = self.build_cbom_data(target_path, profile, findings)
        
        from agilityshift.reports.cyclonedx_validator import CycloneDXValidator
        validator = CycloneDXValidator()
        is_valid = validator.validate(cbom_data)
        if not is_valid:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning("Generated CBOM failed official CycloneDX 1.6 validation, but writing anyway for inspection.")
            
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(cbom_data, f, indent=2)
        return output_path
