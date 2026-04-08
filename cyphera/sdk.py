"""Cyphera SDK — protect/access API with policy-driven encryption."""

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


class Cyphera:
    def __init__(self, config: dict):
        self._policies = {}
        self._tag_index = {}
        self._keys = {}

        # Load keys
        for name, val in config.get("keys", {}).items():
            material = val if isinstance(val, str) else val.get("material", "")
            self._keys[name] = bytes.fromhex(material)

        # Load policies + build tag index
        for name, pol in config.get("policies", {}).items():
            tag_enabled = pol.get("tag_enabled", True)
            tag = pol.get("tag")

            if tag_enabled and not tag:
                raise ValueError(f"Policy '{name}' has tag_enabled=true but no tag specified")

            if tag_enabled and tag:
                if tag in self._tag_index:
                    raise ValueError(f"Tag collision: '{tag}' used by both '{self._tag_index[tag]}' and '{name}'")
                self._tag_index[tag] = name

            self._policies[name] = {
                "engine": pol.get("engine", "ff1"),
                "alphabet": ALPHABETS.get(pol.get("alphabet"), pol.get("alphabet") or ALPHABETS["alphanumeric"]),
                "key_ref": pol.get("key_ref"),
                "tag": tag,
                "tag_enabled": tag_enabled,
                "tag_length": pol.get("tag_length", 3),
                "pattern": pol.get("pattern"),
                "algorithm": pol.get("algorithm", "sha256"),
            }

    @classmethod
    def load(cls):
        """Auto-discover policy: CYPHERA_POLICY_FILE env, ./cyphera.json, /etc/cyphera/cyphera.json"""
        env_path = os.environ.get("CYPHERA_POLICY_FILE")
        if env_path and os.path.exists(env_path):
            return cls.from_file(env_path)
        if os.path.exists("cyphera.json"):
            return cls.from_file("cyphera.json")
        if os.path.exists("/etc/cyphera/cyphera.json"):
            return cls.from_file("/etc/cyphera/cyphera.json")
        raise FileNotFoundError("No policy file found. Checked: CYPHERA_POLICY_FILE env, ./cyphera.json, /etc/cyphera/cyphera.json")

    @classmethod
    def from_file(cls, path: str):
        """Load from a JSON policy file."""
        with open(path) as f:
            config = json.load(f)
        return cls(config)

    def protect(self, value: str, policy_name: str) -> str:
        policy = self._get_policy(policy_name)
        engine = policy["engine"]

        if engine in ("ff1", "ff3"):
            return self._protect_fpe(value, policy, engine == "ff3")
        elif engine == "mask":
            return self._protect_mask(value, policy)
        elif engine == "hash":
            return self._protect_hash(value, policy)
        else:
            raise ValueError(f"Unknown engine: {engine}")

    def access(self, protected_value: str, policy_name: str = None) -> str:
        if policy_name:
            policy = self._get_policy(policy_name)
            return self._access_fpe(protected_value, policy)

        # Tag-based lookup — longest tags first
        for tag in sorted(self._tag_index.keys(), key=len, reverse=True):
            if protected_value.startswith(tag):
                policy = self._get_policy(self._tag_index[tag])
                return self._access_fpe(protected_value, policy)

        raise ValueError("No matching tag found. Use access(value, policy_name) for untagged values.")

    # ── FPE ──

    def _protect_fpe(self, value: str, policy: dict, is_ff3: bool) -> str:
        key = self._resolve_key(policy["key_ref"])
        alphabet = policy["alphabet"]

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

        # Prepend tag
        if policy["tag_enabled"] and policy["tag"]:
            return policy["tag"] + result
        return result

    def _access_fpe(self, protected_value: str, policy: dict) -> str:
        if policy["engine"] not in ("ff1", "ff3"):
            raise ValueError(f"Cannot reverse '{policy['engine']}' — not reversible")

        key = self._resolve_key(policy["key_ref"])
        alphabet = policy["alphabet"]

        # Strip tag
        without_tag = protected_value
        if policy["tag_enabled"] and policy["tag"]:
            without_tag = protected_value[len(policy["tag"]):]

        # Strip passthroughs
        encryptable, positions, chars = self._extract_passthroughs(without_tag, alphabet)

        # Decrypt
        if policy["engine"] == "ff3":
            cipher = FF3(key, b"\x00" * 8, alphabet)
        else:
            cipher = FF1(key, b"", alphabet)
        decrypted = cipher.decrypt(encryptable)

        # Reinsert passthroughs
        return self._reinsert_passthroughs(decrypted, positions, chars)

    # ── Mask ──

    def _protect_mask(self, value: str, policy: dict) -> str:
        pattern = policy["pattern"]
        if not pattern:
            raise ValueError("Mask policy requires 'pattern'")
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

    def _protect_hash(self, value: str, policy: dict) -> str:
        algo = policy["algorithm"].replace("-", "").lower()
        algo_map = {"sha256": "sha256", "sha384": "sha384", "sha512": "sha512"}
        hash_algo = algo_map.get(algo)
        if not hash_algo:
            raise ValueError(f"Unsupported hash algorithm: {policy['algorithm']}")

        data = value.encode("utf-8")

        if policy["key_ref"]:
            key = self._resolve_key(policy["key_ref"])
            return hmac.new(key, data, hash_algo).hexdigest()
        else:
            return hashlib.new(hash_algo, data).hexdigest()

    # ── Helpers ──

    def _get_policy(self, name: str) -> dict:
        policy = self._policies.get(name)
        if not policy:
            raise ValueError(f"Unknown policy: {name}")
        return policy

    def _resolve_key(self, key_ref: str) -> bytes:
        if not key_ref:
            raise ValueError("No key_ref in policy")
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
