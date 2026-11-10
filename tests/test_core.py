"""Unit tests (stdlib unittest). Run:  python -m unittest discover -s tests -v

Optional integration test: set TVR_SAMPLE to the path of an Inno Setup 6.4.x installer.
"""
import os
import random
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from teamvr_unpack.crypto import Nonce, hchacha20, kdf_teamvr, xchacha20  # noqa: E402
from teamvr_unpack.extract import safe_relpath  # noqa: E402
from teamvr_unpack.filters import transform_call_instructions  # noqa: E402


class TestCrypto(unittest.TestCase):
    def test_hchacha20_vector(self):
        # draft-irtf-cfrg-xchacha-03, section 2.2.1
        key = bytes(range(32))
        nonce = bytes.fromhex("000000090000004a0000000031415927")
        self.assertEqual(hchacha20(key, nonce).hex(),
                         "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")

    def test_xchacha20_roundtrip(self):
        key, nonce = os.urandom(32), os.urandom(24)
        msg = os.urandom(100000)
        ct = xchacha20(key, nonce).update(msg)
        self.assertNotEqual(ct, msg)
        self.assertEqual(xchacha20(key, nonce).update(ct), msg)

    def test_teamvr_kdf_length_bug(self):
        salt = os.urandom(64)
        # only len(pw) bytes of UTF-16 are hashed: 'Zet0'..'Zet9' all hash 'Z\0e\0'
        self.assertEqual(kdf_teamvr("Zet0", salt), kdf_teamvr("Zet9", salt))
        self.assertEqual(kdf_teamvr("Zet0", salt), kdf_teamvr("Zeus", salt))
        self.assertNotEqual(kdf_teamvr("Zet0", salt), kdf_teamvr("Zxt0", salt))
        self.assertEqual(len(kdf_teamvr("x", salt)), 32)

    def test_arc4_fallback_matches_library(self):
        from teamvr_unpack.crypto import _PyARC4, _arc4
        key, msg = os.urandom(20), os.urandom(5000)
        self.assertEqual(_PyARC4(key).update(msg), _arc4(key).update(msg))
        # RFC 6229 test vector: key 0102030405, first keystream bytes b2396305f03dc027ccc3524a0a1118a8
        self.assertEqual(_PyARC4(bytes([1, 2, 3, 4, 5])).update(b"\0" * 16).hex(), "b2396305f03dc027ccc3524a0a1118a8")

    def test_nonce_pack(self):
        raw = os.urandom(24)
        n = Nonce(raw)
        self.assertEqual(n.pack(0, 0), raw)
        self.assertEqual(Nonce(n.pack(12345, -1)).pack(12345, -1), raw)


class TestFilter(unittest.TestCase):
    def test_call_filter_roundtrip(self):
        rnd = random.Random(1)
        buf = bytearray(rnd.getrandbits(8) for _ in range(70000))
        for i in range(0, len(buf) - 5, 37):          # plant plausible CALL/JMP rel32 instructions
            buf[i] = 0xE8 if i % 2 else 0xE9
            buf[i + 4] = 0x00 if i % 3 else 0xFF
        for off in (0, 65536, 0xFFFFF0):
            enc = transform_call_instructions(bytes(buf), True, off)
            self.assertNotEqual(enc, bytes(buf))
            self.assertEqual(transform_call_instructions(enc, False, off), bytes(buf))


class TestPaths(unittest.TestCase):
    def test_no_traversal(self):
        p = safe_relpath("..\\..\\{app}\\..\\Windows\\evil.dll")
        self.assertFalse(p.startswith(".."))
        self.assertTrue(p.endswith("evil.dll"))
        self.assertNotIn(":", safe_relpath("C:\\x\\y.txt"))


@unittest.skipUnless(os.environ.get("TVR_SAMPLE"), "set TVR_SAMPLE to run the integration test")
class TestIntegration(unittest.TestCase):
    def test_extract(self):
        from teamvr_unpack.cli import main
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(main(["extract", os.environ["TVR_SAMPLE"], "-o", d]), 0)


if __name__ == "__main__":
    unittest.main()
