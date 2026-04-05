# cyphera

Data obfuscation SDK for Python. FPE, AES, masking, hashing.

```
pip install cyphera
```

```python
from cyphera import FF1

cipher = FF1(key, tweak)
encrypted = cipher.encrypt("0123456789")
decrypted = cipher.decrypt(encrypted)
```

## Status

Early development. FF1 and FF3 engines with all NIST test vectors.

## License

Apache 2.0
