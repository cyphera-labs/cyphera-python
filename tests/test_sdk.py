"""Tests for the Cyphera SDK layer."""
import pytest
from cyphera import Cyphera


CONFIG = {
    "policies": {
        "ssn": {"engine": "ff1", "key_ref": "test-key", "tag": "T01"},
        "ssn_digits": {"engine": "ff1", "alphabet": "digits", "tag_enabled": False, "key_ref": "test-key"},
        "ssn_mask": {"engine": "mask", "pattern": "last4", "tag_enabled": False},
        "ssn_hash": {"engine": "hash", "algorithm": "sha256", "key_ref": "test-key", "tag_enabled": False},
    },
    "keys": {
        "test-key": {"material": "2B7E151628AED2A6ABF7158809CF4F3C"},
    },
}


def test_protect_access_with_tag():
    c = Cyphera(CONFIG)
    protected = c.protect("123456789", "ssn")
    assert protected.startswith("T01")
    assert len(protected) > len("123456789")
    accessed = c.access(protected)
    assert accessed == "123456789"


def test_protect_access_with_passthroughs():
    c = Cyphera(CONFIG)
    protected = c.protect("123-45-6789", "ssn")
    assert "-" in protected
    accessed = c.access(protected)
    assert accessed == "123-45-6789"


def test_untagged_digits_roundtrip():
    c = Cyphera(CONFIG)
    protected = c.protect("123456789", "ssn_digits")
    assert len(protected) == 9
    accessed = c.access(protected, "ssn_digits")
    assert accessed == "123456789"


def test_deterministic():
    c = Cyphera(CONFIG)
    a = c.protect("123456789", "ssn")
    b = c.protect("123456789", "ssn")
    assert a == b


def test_mask_last4():
    c = Cyphera(CONFIG)
    result = c.protect("123-45-6789", "ssn_mask")
    assert result == "*******6789"


def test_hash_deterministic():
    c = Cyphera(CONFIG)
    a = c.protect("123-45-6789", "ssn_hash")
    b = c.protect("123-45-6789", "ssn_hash")
    assert a == b
    assert all(ch in "0123456789abcdef" for ch in a)


def test_access_nonreversible_raises():
    c = Cyphera(CONFIG)
    masked = c.protect("123-45-6789", "ssn_mask")
    with pytest.raises(ValueError, match="No matching tag"):
        c.access(masked)


def test_tag_collision_raises():
    with pytest.raises(ValueError, match="Tag collision"):
        Cyphera({
            "policies": {
                "a": {"engine": "ff1", "key_ref": "k", "tag": "ABC"},
                "b": {"engine": "ff1", "key_ref": "k", "tag": "ABC"},
            },
            "keys": {"k": {"material": "2B7E151628AED2A6ABF7158809CF4F3C"}},
        })


def test_tag_required_raises():
    with pytest.raises(ValueError, match="no tag specified"):
        Cyphera({
            "policies": {"a": {"engine": "ff1", "key_ref": "k"}},
            "keys": {"k": {"material": "2B7E151628AED2A6ABF7158809CF4F3C"}},
        })


def test_unicode_passthroughs():
    c = Cyphera(CONFIG)
    protected = c.protect("José123456", "ssn")
    accessed = c.access(protected)
    assert accessed == "José123456"


def test_key_source_env(monkeypatch):
    monkeypatch.setenv("TEST_CYPHERA_KEY", "2B7E151628AED2A6ABF7158809CF4F3C")
    c = Cyphera({
        "policies": {"ssn": {"engine": "ff1", "key_ref": "k", "tag": "T01"}},
        "keys": {"k": {"source": "env", "var": "TEST_CYPHERA_KEY"}},
    })
    p = c.protect("123456789", "ssn")
    assert p.startswith("T01")
    assert c.access(p) == "123456789"


def test_key_source_env_base64(monkeypatch):
    import base64
    key_b64 = base64.b64encode(bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C")).decode()
    monkeypatch.setenv("TEST_CYPHERA_KEY_B64", key_b64)
    c = Cyphera({
        "policies": {"ssn": {"engine": "ff1", "key_ref": "k", "tag": "T01"}},
        "keys": {"k": {"source": "env", "var": "TEST_CYPHERA_KEY_B64", "encoding": "base64"}},
    })
    p = c.protect("123456789", "ssn")
    assert p.startswith("T01")
    assert c.access(p) == "123456789"


def test_key_source_env_missing_raises():
    with pytest.raises(ValueError, match="not set"):
        Cyphera({
            "policies": {"ssn": {"engine": "ff1", "key_ref": "k", "tag": "T01"}},
            "keys": {"k": {"source": "env", "var": "NONEXISTENT_CYPHERA_KEY_9999"}},
        })


def test_key_source_file(tmp_path):
    key_file = tmp_path / "key.hex"
    key_file.write_text("2B7E151628AED2A6ABF7158809CF4F3C")
    c = Cyphera({
        "policies": {"ssn": {"engine": "ff1", "key_ref": "k", "tag": "T01"}},
        "keys": {"k": {"source": "file", "path": str(key_file)}},
    })
    p = c.protect("123456789", "ssn")
    assert p.startswith("T01")
    assert c.access(p) == "123456789"


def test_key_source_cloud_without_keychain_raises():
    with pytest.raises(ImportError, match="cyphera-keychain"):
        Cyphera({
            "policies": {"ssn": {"engine": "ff1", "key_ref": "k", "tag": "T01"}},
            "keys": {"k": {"source": "aws-kms", "arn": "arn:aws:kms:us-east-1:123:key/abc"}},
        })


def test_key_source_unknown_raises():
    with pytest.raises(ValueError, match="unknown source"):
        Cyphera({
            "policies": {"ssn": {"engine": "ff1", "key_ref": "k", "tag": "T01"}},
            "keys": {"k": {"source": "magic"}},
        })


def test_key_source_env_matches_inline(monkeypatch):
    monkeypatch.setenv("TEST_CYPHERA_KEY2", "2B7E151628AED2A6ABF7158809CF4F3C")
    c_inline = Cyphera(CONFIG)
    c_env = Cyphera({
        "policies": CONFIG["policies"],
        "keys": {"test-key": {"source": "env", "var": "TEST_CYPHERA_KEY2"}},
    })
    p1 = c_inline.protect("123456789", "ssn")
    p2 = c_env.protect("123456789", "ssn")
    assert p1 == p2, "env source should produce identical output to inline material"
