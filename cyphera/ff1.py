"""FF1 Format-Preserving Encryption (NIST SP 800-38G)."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DIGITS = "0123456789"
ALPHANUMERIC = "0123456789abcdefghijklmnopqrstuvwxyz"


class FF1:
    def __init__(self, key: bytes, tweak: bytes, alphabet: str = ALPHANUMERIC):
        if len(key) not in (16, 24, 32):
            raise ValueError(f"invalid key length: {len(key)} (expected 16, 24, or 32)")
        if len(alphabet) < 2:
            raise ValueError("Alphabet must have >= 2 characters")
        self._key = key
        self._tweak = tweak
        self._alphabet = alphabet
        self._radix = len(alphabet)
        self._char_to_int = {c: i for i, c in enumerate(alphabet)}

    def encrypt(self, plaintext: str) -> str:
        digits = self._to_digits(plaintext)
        result = self._ff1_encrypt(digits, self._tweak)
        return self._from_digits(result)

    def decrypt(self, ciphertext: str) -> str:
        digits = self._to_digits(ciphertext)
        result = self._ff1_decrypt(digits, self._tweak)
        return self._from_digits(result)

    def _to_digits(self, s: str) -> list[int]:
        digits = []
        for pos, c in enumerate(s):
            idx = self._char_to_int.get(c)
            if idx is None:
                raise ValueError(f"invalid char '{c}' at position {pos}")
            digits.append(idx)
        return digits

    def _from_digits(self, d: list[int]) -> str:
        return "".join(self._alphabet[i] for i in d)

    def _aes_ecb(self, block: bytes) -> bytes:
        # NIST SP 800-38G requires AES-ECB as the PRF for FF1/FF3 Feistel rounds.
        # This is single-block encryption used as a building block, not ECB mode applied to user data.
        cipher = Cipher(algorithms.AES(self._key), modes.ECB())
        enc = cipher.encryptor()
        return enc.update(block) + enc.finalize()

    def _prf(self, data: bytes) -> bytes:
        y = b"\x00" * 16
        for i in range(0, len(data), 16):
            block = bytes(a ^ b for a, b in zip(y, data[i : i + 16]))
            y = self._aes_ecb(block)
        return y

    def _expand_s(self, r: bytes, d: int) -> bytes:
        blocks = (d + 15) // 16
        out = bytearray(r)
        for j in range(1, blocks):
            x = j.to_bytes(16, "big")
            # XOR with R (not previous block) per NIST SP 800-38G
            x = bytes(a ^ b for a, b in zip(x, r))
            enc = self._aes_ecb(x)
            out.extend(enc)
        return bytes(out[:d])

    def _num(self, digits: list[int]) -> int:
        result = 0
        for d in digits:
            result = result * self._radix + d
        return result

    def _str(self, num: int, length: int) -> list[int]:
        result = [0] * length
        for i in range(length - 1, -1, -1):
            result[i] = num % self._radix
            num //= self._radix
        return result

    def _check_length(self, n: int) -> None:
        # NIST SP 800-38G: length >= 2 and radix^length >= 1,000,000.
        if n < 2 or self._radix ** n < 1_000_000:
            raise ValueError(
                "input too short (NIST minimum: length >= 2 and "
                "radix^length >= 1,000,000)"
            )

    def _compute_b(self, v: int) -> int:
        # NIST SP 800-38G: b = ceil(ceil(v*log2(radix))/8), computed with exact
        # integer arithmetic. ceil(v*log2(radix)) is the bit length of
        # radix^v - 1. Floating-point log2 is forbidden here — rounding errors
        # would corrupt the ciphertext.
        bits = (self._radix ** v - 1).bit_length()
        return (bits + 7) // 8

    def _build_p(self, u: int, n: int, t: int) -> bytes:
        return bytes(
            [1, 2, 1, (self._radix >> 16) & 0xFF, (self._radix >> 8) & 0xFF, self._radix & 0xFF, 10, u]
            + list(n.to_bytes(4, "big"))
            + list(t.to_bytes(4, "big"))
        )

    def _build_q(self, T: bytes, i: int, num_bytes: bytes, b: int) -> bytes:
        pad = (16 - ((len(T) + 1 + b) % 16)) % 16
        q = bytearray(T)
        q.extend(b"\x00" * pad)
        q.append(i)
        if len(num_bytes) < b:
            q.extend(b"\x00" * (b - len(num_bytes)))
        start = max(0, len(num_bytes) - b)
        q.extend(num_bytes[start:])
        return bytes(q)

    def _ff1_encrypt(self, pt: list[int], T: bytes) -> list[int]:
        n = len(pt)
        self._check_length(n)
        u, v = n // 2, n - n // 2
        A, B = pt[:u], pt[u:]

        b = self._compute_b(v)
        d = 4 * ((b + 3) // 4) + 4
        P = self._build_p(u, n, len(T))

        for i in range(10):
            num_b = self._num(B).to_bytes(max(b, 1), "big")
            if len(num_b) > b:
                num_b = num_b[-b:] if b > 0 else b""
            Q = self._build_q(T, i, num_b, b)
            R = self._prf(P + Q)
            S = self._expand_s(R, d)
            y = int.from_bytes(S, "big")

            m = u if i % 2 == 0 else v
            c = (self._num(A) + y) % (self._radix ** m)
            A, B = B, self._str(c, m)

        return A + B

    def _ff1_decrypt(self, ct: list[int], T: bytes) -> list[int]:
        n = len(ct)
        self._check_length(n)
        u, v = n // 2, n - n // 2
        A, B = ct[:u], ct[u:]

        b = self._compute_b(v)
        d = 4 * ((b + 3) // 4) + 4
        P = self._build_p(u, n, len(T))

        for i in range(9, -1, -1):
            num_a = self._num(A).to_bytes(max(b, 1), "big")
            if len(num_a) > b:
                num_a = num_a[-b:] if b > 0 else b""
            Q = self._build_q(T, i, num_a, b)
            R = self._prf(P + Q)
            S = self._expand_s(R, d)
            y = int.from_bytes(S, "big")

            m = u if i % 2 == 0 else v
            mod = self._radix ** m
            c = (self._num(B) - y) % mod
            B, A = A, self._str(c, m)

        return A + B
