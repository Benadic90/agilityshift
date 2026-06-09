import json
import logging
import requests
from jsonschema import validate, exceptions

logger = logging.getLogger(__name__)

CYCLONEDX_1_6_SCHEMA_URL = "https://cyclonedx.org/schema/bom-1.6.schema.json"

class CycloneDXValidator:
    def __init__(self):
        self.schema = None

    def _fetch_schema(self):
        if self.schema is not None:
            return self.schema
        
        try:
            response = requests.get(CYCLONEDX_1_6_SCHEMA_URL, timeout=5)
            response.raise_for_status()
            self.schema = response.json()
        except requests.exceptions.RequestException as e:
            logger.warning(f"Failed to fetch CycloneDX 1.6 schema: {e}")
            self.schema = None
        except ValueError:
            logger.warning("Failed to parse CycloneDX 1.6 schema JSON")
            self.schema = None
            
        return self.schema

    def validate(self, cbom_data: dict) -> bool:
        """
        Validates the given CBOM data against the official CycloneDX 1.6 schema.
        Returns True if valid (or if schema couldn't be fetched), False if invalid.
        """
        schema = self._fetch_schema()
        if schema is None:
            # Cannot validate, assume valid or at least don't block
            return True
            
        try:
            validate(instance=cbom_data, schema=schema)
            return True
        except exceptions.ValidationError as e:
            logger.error(f"CycloneDX Validation Error: {e.message} at {list(e.path)}")
            return False
        except exceptions.SchemaError as e:
            logger.error(f"CycloneDX Schema Error: {e.message}")
            return False
