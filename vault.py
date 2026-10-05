import time
import threading

class EphemeralRAMVault:
    def __init__(self, default_ttl: int = 15):
        self.default_ttl = default_ttl
        self._store = {}
        self._lock = threading.Lock()

    def store_mapping(self, token: str, cleartext: str, custom_ttl: int = None):
        expiry = time.time() + (custom_ttl if custom_ttl is not None else self.default_ttl)
        with self._lock:
            self._store[token] = {"cleartext": cleartext, "expires_at": expiry}

    def retrieve_cleartext(self, token: str):
        with self._lock:
            entry = self._store.get(token)
            if not entry or time.time() > entry["expires_at"]:
                if token in self._store:
                    del self._store[token]
                return None
            return entry["cleartext"]

    def get_live_memory_map(self):
        now = time.time()
        with self._lock:
            expired = [k for k, v in self._store.items() if now > v["expires_at"]]
            for k in expired:
                del self._store[k]
            
            return [
                {
                    "token": k,
                    "cleartext": v["cleartext"],
                    "ttl_remaining": max(0, int(v["expires_at"] - now))
                }
                for k, v in self._store.items()
            ]

ram_vault = EphemeralRAMVault()