"""Cyphera SDK — protect/access API with configuration-driven encryption."""

import json
import os
import hashlib
import hmac
from .ff1 import FF1
from .ff3 import FF3

ALPHABETS = {
    "digits": "0123456789",
    "alpha_lower": "abcdefghijklmnopqrstuvwxyz",
    "alpha_upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "alpha": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "alphanumeric": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
}


_CLOUD_SOURCES = ("aws-kms", "gcp-kms", "azure-kv", "vault")

_keychain = None


def _resolve_key_source(name: str, config: dict) -> bytes:
    source = config["source"]

    if source == "env":
        var_name = config.get("var")
        if not var_name:
            raise ValueError(f"Key '{name}': source 'env' requires 'var' field")
        val = os.environ.get(var_name)
        if not val:
            raise ValueError(f"Key '{name}': environment variable '{var_name}' is not set")
        encoding = config.get("encoding", "hex")
        if encoding == "base64":
            import base64
            return base64.b64decode(val)
        return bytes.fromhex(val)

    if source == "file":
        file_path = config.get("path")
        if not file_path:
            raise ValueError(f"Key '{name}': source 'file' requires 'path' field")
        with open(file_path) as f:
            raw = f.read().strip()
        encoding = config.get("encoding")
        if not encoding:
            encoding = "base64" if file_path.endswith((".b64", ".base64")) else "hex"
        if encoding == "base64":
            import base64
            return base64.b64decode(raw)
        return bytes.fromhex(raw)

    if source in _CLOUD_SOURCES:
        global _keychain
        if _keychain is None:
            try:
                import cyphera_keychain
                _keychain = cyphera_keychain
            except ImportError:
                _keychain = False
        if not _keychain:
            raise ImportError(
                f"Key '{name}' requires source '{source}' but cyphera-keychain is not installed.\n"
                f"Install it: pip install cyphera-keychain[{source.replace('-', '_')}]"
            )
        return _keychain.resolve(source, config)

    raise ValueError(f"Key '{name}': unknown source '{source}'. Valid sources: env, file, {', '.join(_CLOUD_SOURCES)}")


class Cyphera:
    def __init__(self, config: dict):
        self._configurations = {}
        self._header_index = {}
        self._keys = {}

        # Load keys
        for name, val in config.get("keys", {}).items():
            if isinstance(val, str):
                # Shorthand: bare hex string
                self._keys[name] = bytes.fromhex(val)
            elif "material" in val:
                # Inline hex material
                self._keys[name] = bytes.fromhex(val["material"])
            elif "source" in val:
                # Resolve from source
                self._keys[name] = _resolve_key_source(name, val)
            else:
                raise ValueError(f"Key '{name}' must have either 'material' or 'source'")

        # Load configurations + build header index
        for name, cfg in config.get("configurations", {}).items():
            header_enabled = cfg.get("header_enabled", True)
            header = cfg.get("header")

            if header_enabled and not header:
                raise ValueError(f"Configuration '{name}' has header_enabled=true but no header specified")

            if header_enabled and header:
                if header in self._header_index:
                    raise ValueError(f"Header collision: '{header}' used by both '{self._header_index[header]}' and '{name}'")
                self._header_index[header] = name

            self._configurations[name] = {
                "engine": cfg.get("engine", "ff1"),
                "alphabet": ALPHABETS.get(cfg.get("alphabet"), cfg.get("alphabet") or ALPHABETS["alphanumeric"]),
                "key_ref": cfg.get("key_ref"),
                "header": header,
                "header_enabled": header_enabled,
                "header_length": cfg.get("header_length", 3),
                "pattern": cfg.get("pattern"),
                "algorithm": cfg.get("algorithm", "sha256"),
            }

    @classmethod
    def load(cls):
        """Auto-discover configuration: CYPHERA_CONFIG_FILE env, ./cyphera.json, /etc/cyphera/cyphera.json"""
        env_path = os.environ.get("CYPHERA_CONFIG_FILE")
        if env_path and os.path.exists(env_path):
            return cls.from_file(env_path)
        if os.path.exists("cyphera.json"):
            return cls.from_file("cyphera.json")
        if os.path.exists("/etc/cyphera/cyphera.json"):
            return cls.from_file("/etc/cyphera/cyphera.json")
        raise FileNotFoundError("No configuration file found. Checked: CYPHERA_CONFIG_FILE env, ./cyphera.json, /etc/cyphera/cyphera.json")

    @classmethod
    def from_file(cls, path: str):
        """Load from a JSON configuration file."""
        with open(path) as f:
            config = json.load(f)
        return cls(config)

    def protect(self, value: str, configuration_name: str) -> str:
        configuration = self._get_configuration(configuration_name)
        engine = configuration["engine"]

        if engine in ("ff1", "ff3"):
            return self._protect_fpe(value, configuration, engine == "ff3")
        elif engine == "mask":
            return self._protect_mask(value, configuration)
        elif engine == "hash":
            return self._protect_hash(value, configuration)
        else:
            raise ValueError(f"Unknown engine: {engine}")

    def access(self, protected_value: str, configuration_name: str = None) -> str:
        if configuration_name:
            configuration = self._get_configuration(configuration_name)
            if configuration["header_enabled"]:
                raise ValueError(
                    f"configuration '{configuration_name}' has header_enabled=True; "
                    "use access(value) — the header identifies the configuration. "
                    "The two-arg form is for header_enabled=False configurations only."
                )
            return self._access_fpe(protected_value, configuration)

        # Header-based lookup — longest headers first
        for header in sorted(self._header_index.keys(), key=len, reverse=True):
            if protected_value.startswith(header):
                configuration = self._get_configuration(self._header_index[header])
                # Strip the header before delegating; _access_fpe always assumes raw input.
                return self._access_fpe(protected_value[len(header):], configuration)

        raise ValueError("No matching header found. Use access(value, configuration_name) for headerless values.")

    # ── FPE ──

    def _protect_fpe(self, value: str, configuration: dict, is_ff3: bool) -> str:
        key = self._resolve_key(configuration["key_ref"])
        alphabet = configuration["alphabet"]

        # Strip passthroughs
        encryptable, positions, chars = self._extract_passthroughs(value, alphabet)

        if not encryptable:
            raise ValueError("No encryptable characters in input")

        # Encrypt
        if is_ff3:
            cipher = FF3(key, b"\x00" * 8, alphabet)
        else:
            cipher = FF1(key, b"", alphabet)
        encrypted = cipher.encrypt(encryptable)

        # Reinsert passthroughs
        result = self._reinsert_passthroughs(encrypted, positions, chars)

        # Prepend header
        if configuration["header_enabled"] and configuration["header"]:
            return configuration["header"] + result
        return result

    def _access_fpe(self, protected_value: str, configuration: dict) -> str:
        """Internal: decrypt assuming `protected_value` is already header-stripped.

        Used by `access(value)` (which strips the header itself) and by
        `access(value, name)` (only valid for header_enabled=False configs).
        """
        if configuration["engine"] not in ("ff1", "ff3"):
            raise ValueError(f"Cannot reverse '{configuration['engine']}' — not reversible")

        key = self._resolve_key(configuration["key_ref"])
        alphabet = configuration["alphabet"]

        # Strip passthroughs
        encryptable, positions, chars = self._extract_passthroughs(protected_value, alphabet)

        # Decrypt
        if configuration["engine"] == "ff3":
            cipher = FF3(key, b"\x00" * 8, alphabet)
        else:
            cipher = FF1(key, b"", alphabet)
        decrypted = cipher.decrypt(encryptable)

        # Reinsert passthroughs
        return self._reinsert_passthroughs(decrypted, positions, chars)

    # ── Mask ──

    def _protect_mask(self, value: str, configuration: dict) -> str:
        pattern = configuration["pattern"]
        if not pattern:
            raise ValueError("Mask configuration requires 'pattern'")
        length = len(value)
        if pattern in ("last4", "last_4"):
            return "*" * max(0, length - 4) + value[-4:]
        elif pattern in ("last2", "last_2"):
            return "*" * max(0, length - 2) + value[-2:]
        elif pattern in ("first1", "first_1"):
            return value[:1] + "*" * max(0, length - 1)
        elif pattern in ("first3", "first_3"):
            return value[:3] + "*" * max(0, length - 3)
        else:  # "full" or default
            return "*" * length

    # ── Hash ──

    def _protect_hash(self, value: str, configuration: dict) -> str:
        algo = configuration["algorithm"].replace("-", "").lower()
        algo_map = {"sha256": "sha256", "sha384": "sha384", "sha512": "sha512"}
        hash_algo = algo_map.get(algo)
        if not hash_algo:
            raise ValueError(f"Unsupported hash algorithm: {configuration['algorithm']}")

        data = value.encode("utf-8")

        if configuration["key_ref"]:
            key = self._resolve_key(configuration["key_ref"])
            return hmac.new(key, data, hash_algo).hexdigest()
        else:
            return hashlib.new(hash_algo, data).hexdigest()

    # ── Helpers ──

    def _get_configuration(self, name: str) -> dict:
        configuration = self._configurations.get(name)
        if not configuration:
            raise ValueError(f"Unknown configuration: {name}")
        return configuration

    def _resolve_key(self, key_ref: str) -> bytes:
        if not key_ref:
            raise ValueError("No key_ref in configuration")
        key = self._keys.get(key_ref)
        if not key:
            raise ValueError(f"Unknown key: {key_ref}")
        return key

    @staticmethod
    def _extract_passthroughs(value: str, alphabet: str):
        encryptable = ""
        positions = []
        chars = []
        for i, c in enumerate(value):
            if c in alphabet:
                encryptable += c
            else:
                positions.append(i)
                chars.append(c)
        return encryptable, positions, chars

    @staticmethod
    def _reinsert_passthroughs(encrypted: str, positions: list, chars: list) -> str:
        result = list(encrypted)
        for i, pos in enumerate(positions):
            if pos <= len(result):
                result.insert(pos, chars[i])
            else:
                result.append(chars[i])
        return "".join(result)
