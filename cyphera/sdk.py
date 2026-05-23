"""Cyphera SDK — protect/access API with configuration-driven encryption."""

import json
import os
import sys
import hashlib
import hmac
from .ff1 import FF1
from .ff3 import FF3, FF31

_ff3_warned = False


def _warn_ff3_deprecated() -> None:
    """Emit the FF3 deprecation warning to stderr, once per process. Original
    FF3 is cryptographically weak; configurations should use the 'ff31' engine.
    """
    global _ff3_warned
    if not _ff3_warned:
        _ff3_warned = True
        print(
            "WARNING: engine 'ff3' is deprecated and cryptographically weak "
            "— migrate to 'ff31' (FF3-1).",
            file=sys.stderr,
        )

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
                raise ValueError("configuration error: header must be specified")

            if header_enabled and header:
                if header in self._header_index:
                    raise ValueError("configuration error: header collision")
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

        if engine in ("ff1", "ff3", "ff31"):
            return self._protect_fpe(value, configuration)
        elif engine == "mask":
            return self._protect_mask(value, configuration)
        elif engine == "hash":
            return self._protect_hash(value, configuration)
        else:
            raise ValueError(f"unknown engine: {engine}")

    def access(self, value: str, configuration_name: str | None = None) -> str:
        """Reverse a protected value.

        The primary, one-argument form ``access(value)`` is header-driven:
        the SDK checks the leading bytes of ``value`` against the
        registered headers (longest first to avoid prefix collisions),
        strips the matched header, and decrypts.

        The two-argument form ``access(value, configuration_name)`` is an
        escape hatch for unique situations where the protected value has
        no header (mainframe formats, fixed-width legacy systems, etc.).
        The caller names the configuration explicitly; ``value`` is
        decrypted as raw headerless ciphertext. There is no
        ``header_enabled`` guard — the caller asserts the input has no
        header.
        """
        if configuration_name is not None:
            # Escape-hatch form — caller names the configuration explicitly.
            configuration = self._get_configuration(configuration_name)
            engine = configuration["engine"]
            if engine == "mask":
                raise ValueError(f"cannot reverse '{configuration_name}' — mask is irreversible")
            if engine == "hash":
                raise ValueError(f"cannot reverse '{configuration_name}' — hash is irreversible")
            return self._access_fpe(value, configuration)

        # Primary form — header-based lookup, longest headers first.
        for header in sorted(self._header_index.keys(), key=len, reverse=True):
            if value.startswith(header):
                configuration = self._get_configuration(self._header_index[header])
                # Strip the header before delegating; _access_fpe always assumes raw input.
                return self._access_fpe(value[len(header):], configuration)

        raise ValueError("no matching header found")

    # ── FPE ──

    def _protect_fpe(self, value: str, configuration: dict) -> str:
        key = self._resolve_key(configuration["key_ref"])
        alphabet = configuration["alphabet"]

        # Strip passthroughs
        encryptable, positions, chars = self._extract_passthroughs(value, alphabet)

        if not encryptable:
            raise ValueError("no encryptable characters in input")

        # Encrypt
        engine = configuration["engine"]
        if engine == "ff3":
            _warn_ff3_deprecated()
            cipher = FF3(key, b"\x00" * 8, alphabet)
        elif engine == "ff31":
            cipher = FF31(key, b"\x00" * 7, alphabet)
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

        Used by ``access(value)`` (which strips the header itself) and by
        the ``access(value, name)`` escape hatch (where the caller asserts
        the input has no header).
        """
        if configuration["engine"] not in ("ff1", "ff3", "ff31"):
            raise ValueError(f"unknown engine: {configuration['engine']}")

        key = self._resolve_key(configuration["key_ref"])
        alphabet = configuration["alphabet"]

        # Strip passthroughs
        encryptable, positions, chars = self._extract_passthroughs(protected_value, alphabet)

        # Decrypt
        engine = configuration["engine"]
        if engine == "ff3":
            _warn_ff3_deprecated()
            cipher = FF3(key, b"\x00" * 8, alphabet)
        elif engine == "ff31":
            cipher = FF31(key, b"\x00" * 7, alphabet)
        else:
            cipher = FF1(key, b"", alphabet)
        decrypted = cipher.decrypt(encryptable)

        # Reinsert passthroughs
        return self._reinsert_passthroughs(decrypted, positions, chars)

    # ── Mask ──

    def _protect_mask(self, value: str, configuration: dict) -> str:
        pattern = configuration["pattern"]
        if not pattern:
            raise ValueError("mask pattern required")
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
            raise ValueError(f"configuration not found: {name}")
        return configuration

    def _resolve_key(self, key_ref: str) -> bytes:
        if not key_ref:
            raise ValueError("key error: no key_ref in configuration")
        key = self._keys.get(key_ref)
        if not key:
            raise ValueError(f"key error: key '{key_ref}' not found")
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
