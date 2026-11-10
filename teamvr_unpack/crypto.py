"""Inno Setup 6.4 encryption (XChaCha20) and the two key-derivation functions.

Stock 6.4 (Shared.SetupTypes.GenerateEncryptionKey):
    key = PBKDF2-HMAC-SHA256(UTF-16LE(password), salt[16], iterations, 32)

Team V.R build (reversed from their Setup.e32):
    key = BLAKE2b-512(key = salt[64], message = UTF-16LE(password)[:len(password)])[16:48]
    - the character count is passed where a byte count is expected, so only the first
      len(password) BYTES of the UTF-16 string are hashed (about half the password);
    - the 200000 "iterations" header field is never read.

Password check (identical in both): encrypt four zero bytes with XChaCha20(key, nonce') where
nonce' = base nonce with RandomXorFirstSlice xor -1, compare with SetupHeader.PasswordTest.
Per chunk: nonce = base nonce with RandomXorStartOffset ^= chunk StartOffset and
RandomXorFirstSlice ^= chunk FirstSlice; the keystream starts after the 'zlb'#26 marker.
"""
import hashlib
import itertools
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

MASK = 0xFFFFFFFF


def _rotl(v, c):
    return ((v << c) | (v >> (32 - c))) & MASK


def _qr(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & MASK; x[d] = _rotl(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & MASK; x[b] = _rotl(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & MASK; x[d] = _rotl(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & MASK; x[b] = _rotl(x[b] ^ x[c], 7)


def hchacha20(key, nonce16):
    x = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574] + list(struct.unpack("<8I", key)) + \
        list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        _qr(x, 0, 4, 8, 12); _qr(x, 1, 5, 9, 13); _qr(x, 2, 6, 10, 14); _qr(x, 3, 7, 11, 15)
        _qr(x, 0, 5, 10, 15); _qr(x, 1, 6, 11, 12); _qr(x, 2, 7, 8, 13); _qr(x, 3, 4, 9, 14)
    return struct.pack("<8I", *(x[0:4] + x[12:16]))


def xchacha20(key, nonce24, counter=0):
    """Return a stream cipher context (.update(bytes)). Original DJB layout: 64-bit block counter."""
    sub = hchacha20(key, nonce24[:16])
    iv = struct.pack("<Q", counter) + nonce24[16:24]
    return Cipher(algorithms.ChaCha20(sub, iv), mode=None).encryptor()


class Nonce:
    def __init__(self, raw24):
        self.xor_start, self.xor_slice = struct.unpack_from("<qi", raw24, 0)
        self.rest = struct.unpack_from("<3i", raw24, 12)

    def pack(self, start_offset_xor=0, first_slice_xor=0):
        xs = self.xor_start ^ start_offset_xor
        xf = self.xor_slice ^ first_slice_xor
        xs = (xs + (1 << 63)) % (1 << 64) - (1 << 63)
        xf = (xf + (1 << 31)) % (1 << 32) - (1 << 31)
        return struct.pack("<qi3i", xs, xf, *self.rest)


def kdf_stock(password, salt, iterations):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-16le"), salt, iterations, 32)


def kdf_teamvr_bytes(message, salt):
    return hashlib.blake2b(message, key=salt, digest_size=64).digest()[16:48]


def kdf_teamvr(password, salt):
    return kdf_teamvr_bytes(password.encode("utf-16le")[:len(password)], salt)


def password_ok(key, nonce, password_test):
    ctx = xchacha20(key, nonce.pack(0, -1))
    return struct.unpack("<i", ctx.update(b"\0\0\0\0"))[0] == password_test


DEFAULT_CANDIDATES = [""] + ["Zet%d" % n for n in range(0, 60)] + ["Zet%d" % n for n in range(-59, 0)]


def password_ok_63(password, header):
    """Inno 6.3 Main.TestPassword: SHA1('PasswordCheckHash' + PasswordSalt[8] + UTF-16LE(password))."""
    h = hashlib.sha1(b"PasswordCheckHash" + header["PasswordSalt"] + password.encode("utf-16le")).digest()
    return h == header["PasswordHash"]


class _PyARC4:
    """Pure-Python ARC4, used only if the cryptography package no longer provides it (slow but correct)."""

    def __init__(self, key):
        s = list(range(256)); j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) & 0xFF
            s[i], s[j] = s[j], s[i]
        self.s, self.i, self.j = s, 0, 0

    def update(self, data):
        s, i, j = self.s, self.i, self.j
        out = bytearray(data)
        for k in range(len(out)):
            i = (i + 1) & 0xFF; j = (j + s[i]) & 0xFF
            s[i], s[j] = s[j], s[i]
            out[k] ^= s[(s[i] + s[j]) & 0xFF]
        self.i, self.j = i, j
        return bytes(out)


def _arc4(key):
    try:                                           # cryptography >= 43
        from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
    except ImportError:
        try:                                       # cryptography 41-42 (deprecated location)
            ARC4 = algorithms.ARC4
        except AttributeError:
            return _PyARC4(key)
    return Cipher(ARC4(key), mode=None).decryptor()


def arc4_chunk_cipher(password, chunk_salt):
    """Inno 6.3 Extract.InitDecryption: ARC4(key = SHA1(chunk salt[8] + UTF-16LE(password))), first 1000
    keystream bytes discarded. The 8-byte salt follows the 'zlb'#26 marker."""
    key = hashlib.sha1(chunk_salt + password.encode("utf-16le")).digest()
    ctx = _arc4(key)
    ctx.update(b"\0" * 1000)
    return ctx


class KeyFinder63:
    """Inno 6.3 'key' is the password itself (each chunk derives its own ARC4 key)."""

    def __init__(self, header):
        self.header = header

    def try_passwords(self, candidates):
        for pw in candidates:
            if password_ok_63(pw, self.header):
                return pw, ("arc4", pw)
        return None, None


class KeyFinder:
    def __init__(self, variant, header):
        self.variant = variant
        self.salt = header["EncryptionKDFSalt"]
        self.iters = header["EncryptionKDFIterations"]
        self.nonce = Nonce(header["EncryptionBaseNonce"])
        self.ptest = header["PasswordTest"]

    def derive(self, password):
        if self.variant == "teamvr":
            return kdf_teamvr(password, self.salt)
        return kdf_stock(password, self.salt, self.iters)

    def try_passwords(self, candidates):
        for pw in candidates:
            k = self.derive(pw)
            if password_ok(k, self.nonce, self.ptest):
                return pw, k
        return None, None

    def bruteforce_teamvr(self, max_len=6, alphabet=None, progress=None):
        """Exploit the length bug: only len(pw) bytes of UTF-16 are hashed, i.e. ceil(len/2) characters
        (the last one only by its low byte when len is odd). Search those bytes directly."""
        if self.variant != "teamvr":
            raise ValueError("brute force is only practical for the Team V.R KDF")
        alphabet = alphabet or [chr(c) for c in range(32, 127)]
        for L in range(1, max_len + 1):
            full, half = divmod(L, 2)
            for combo in itertools.product(alphabet, repeat=full + half):
                msg = b"".join(c.encode("utf-16le") for c in combo)[:L]
                k = kdf_teamvr_bytes(msg, self.salt)
                if password_ok(k, self.nonce, self.ptest):
                    shown = "".join(combo[:full]) + (combo[full] if half else "")
                    return "<any %d-character password whose UTF-16 starts with %r, e.g. %r>" % (
                        L, msg, shown.ljust(L, "?")), k
            if progress:
                progress(L)
        return None, None
