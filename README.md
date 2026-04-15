# cyphera

[![CI](https://github.com/cyphera-labs/cyphera-python/actions/workflows/ci.yml/badge.svg)](https://github.com/cyphera-labs/cyphera-python/actions/workflows/ci.yml)
[![Security](https://github.com/cyphera-labs/cyphera-python/actions/workflows/codeql.yml/badge.svg)](https://github.com/cyphera-labs/cyphera-python/actions/workflows/codeql.yml)
[![PyPI](https://img.shields.io/pypi/v/cyphera)](https://pypi.org/project/cyphera/)
[![Python](https://img.shields.io/pypi/pyversions/cyphera)](https://pypi.org/project/cyphera/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

Data protection SDK for Python — format-preserving encryption (FF1/FF3), AES-GCM, data masking, and hashing.

```
pip install cyphera
```

## Usage

```python
from cyphera import Cyphera

# Auto-discover: checks CYPHERA_POLICY_FILE env, ./cyphera.json, /etc/cyphera/cyphera.json
c = Cyphera.load()

# Or load from a specific file
c = Cyphera.from_file("./config/cyphera.json")

# Or inline config
c = Cyphera({
    "policies": {
        "ssn": {"engine": "ff1", "key_ref": "my-key", "tag": "T01"},
    },
    "keys": {
        "my-key": {"material": "2B7E151628AED2A6ABF7158809CF4F3C"},
    },
})

# Protect
encrypted = c.protect("123-45-6789", "ssn")
# → "T01i6J-xF-07pX" (tagged, dashes preserved)

# Access (tag-based, no policy name needed)
decrypted = c.access(encrypted)
# → "123-45-6789"
```

## Policy File (cyphera.json)

```json
{
  "policies": {
    "ssn": { "engine": "ff1", "key_ref": "my-key", "tag": "T01" },
    "ssn_mask": { "engine": "mask", "pattern": "last4", "tag_enabled": false }
  },
  "keys": {
    "my-key": { "material": "2B7E151628AED2A6ABF7158809CF4F3C" }
  }
}
```

## Cross-Language Compatible

All six SDKs produce identical output for the same inputs:

```
Input:       123-45-6789
Java:        T01i6J-xF-07pX
Rust:        T01i6J-xF-07pX
Node:        T01i6J-xF-07pX
Python:      T01i6J-xF-07pX
Go:          T01i6J-xF-07pX
.NET:        T01i6J-xF-07pX
```

## Status

Alpha. API is unstable. Cross-language test vectors validated against Java, Rust, Node, Go, and .NET implementations.

## License

Apache 2.0 — Copyright 2026 Horizon Digital Engineering LLC
