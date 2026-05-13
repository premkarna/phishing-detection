import logging
import itertools

class APIRotator:
    def __init__(self, api_keys: list, service_name: str = "Service"):
        # Empty keys ni filter chesthunnam
        self.api_keys = [key for key in api_keys if key and str(key).strip()]
        self.service_name = service_name
        
        if not self.api_keys:
            logging.error(f"[!] CRITICAL: No API keys provided for {self.service_name}")
            self.cycle = itertools.cycle([""])
        else:
            # itertools.cycle anedi infinite round-robin loop create chesthundi
            self.cycle = itertools.cycle(self.api_keys)
            logging.info(f"[+] ROTATOR ACTIVE: Loaded {len(self.api_keys)} keys for {self.service_name}")

    def get_key(self) -> str:
        """Returns the next API key in the cycle."""
        if not self.api_keys:
            return ""
        return next(self.cycle)