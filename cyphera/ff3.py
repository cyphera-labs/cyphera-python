"""FF3-1 Format-Preserving Encryption (NIST SP 800-38G Rev 1)."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DIGITS = "0123456789"
ALPHANUMERIC = "0123456789abcdefghijklmnopqrstuvwxyz"


class FF3:
    def __init__(self, key: bytes, tweak: bytes, alphabet: str = ALPHANUMERIC):
        if len(key) not in (16, 24, 32):
            raise ValueError(f"Key must be 16, 24, or 32 bytes, got {len(key)}")
        if len(tweak) != 8:
            raise ValueError(f"Tweak must be exactly 8 bytes, got {len(tweak)}")
        if len(alphabet) < 2:
            raise ValueError("Alphabet must have >= 2 characters")
        # FF3 reverses the key
        self._key = key[::-1]
        self._tweak = tweak
        self._alphabet = alphabet
        self._radix = len(alphabet)
        self._char_to_int = {c: i for i, c in enumerate(alphabet)}

    def encrypt(self, plaintext: str) -> str:
        digits = self._to_digits(plaintext)
        result = self._ff3_encrypt(digits)
        return self._from_digits(result)

    def decrypt(self, ciphertext: str) -> str:
        digits = self._to_digits(ciphertext)
        result = self._ff3_decrypt(digits)
        return self._from_digits(result)

    def _to_digits(self, s: str) -> list[int]:
        return [self._char_to_int[c] for c in s]

    def _from_digits(self, d: list[int]) -> str:
        return "".join(self._alphabet[i] for i in d)

    def _aes_ecb(self, block: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(self._key), modes.ECB())
        enc = cipher.encryptor()
        return enc.update(block) + enc.finalize()

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

    def _calc_p(self, round_num: int, w: bytes, half: list[int]) -> int:
        inp = bytearray(16)
        inp[0:4] = w
        inp[3] ^= round_num

        rev_half = list(reversed(half))
        half_num = self._num(rev_half)
        half_bytes = half_num.to_bytes(max(1, (half_num.bit_length() + 7) // 8), "big") if half_num > 0 else b"\x00"

        if len(half_bytes) <= 12:
            inp[16 - len(half_bytes) : 16] = half_bytes
        else:
            inp[4:16] = half_bytes[-12:]

        rev_inp = bytes(reversed(inp))
        aes_out = self._aes_ecb(rev_inp)
        rev_out = bytes(reversed(aes_out))
        return int.from_bytes(rev_out, "big")

    def _ff3_encrypt(self, pt: list[int]) -> list[int]:
        n = len(pt)
        u = (n + 1) // 2
        v = n - u
        A, B = pt[:u], pt[u:]

        for i in range(8):
            if i % 2 == 0:
                w = self._tweak[4:8]
                p = self._calc_p(i, w, B)
                m = self._radix ** u
                a_num = self._num(list(reversed(A)))
                y = (a_num + p) % m
                new = self._str(y, u)
                A = list(reversed(new))
            else:
                w = self._tweak[0:4]
                p = self._calc_p(i, w, A)
                m = self._radix ** v
                b_num = self._num(list(reversed(B)))
                y = (b_num + p) % m
                new = self._str(y, v)
                B = list(reversed(new))

        return A + B

    def _ff3_decrypt(self, ct: list[int]) -> list[int]:
        n = len(ct)
        u = (n + 1) // 2
        v = n - u
        A, B = ct[:u], ct[u:]

        for i in range(7, -1, -1):
            if i % 2 == 0:
                w = self._tweak[4:8]
                p = self._calc_p(i, w, B)
                m = self._radix ** u
                a_num = self._num(list(reversed(A)))
                y = (a_num - p) % m
                new = self._str(y, u)
                A = list(reversed(new))
            else:
                w = self._tweak[0:4]
                p = self._calc_p(i, w, A)
                m = self._radix ** v
                b_num = self._num(list(reversed(B)))
                y = (b_num - p) % m
                new = self._str(y, v)
                B = list(reversed(new))

        return A + B
