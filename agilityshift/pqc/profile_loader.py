import json
from pathlib import Path
from agilityshift.models import PQCProfile

class PQCProfileLoader:
    def __init__(self, profiles_path: Path | None = None):
        if profiles_path is None:
            # Default to the bundled profiles.json in the same directory
            self.profiles_path = Path(__file__).parent / "profiles.json"
        else:
            self.profiles_path = profiles_path
            
    def load_profiles(self) -> dict[str, PQCProfile]:
        # Load the configuration JSON that maps profile names to byte sizes
        with open(self.profiles_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        profiles = {}
        for name, p in data.items():
            profiles[name] = PQCProfile(
                name=name,
                signature_bytes=p["signature_bytes"],
                level=p["level"],
                type=p["type"],
                description=p["description"]
            )
        return profiles
        
    def get_profile(self, name: str) -> PQCProfile:
        profiles = self.load_profiles()
        if name not in profiles:
            raise ValueError(f"PQC Profile '{name}' not found. Available profiles: {', '.join(profiles.keys())}")
        return profiles[name]
        
    def get_default_profile(self) -> PQCProfile:
        return self.get_profile("ML-DSA-65")
        
    def list_profile_names(self) -> list[str]:
        return list(self.load_profiles().keys())
