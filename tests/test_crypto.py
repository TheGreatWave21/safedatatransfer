import io
import os
import unittest

from safedatatransfer.common import crypto
from safedatatransfer.common.hashing import CHUNK_SIZE

KEY = os.urandom(32)
BID = os.urandom(crypto.BLOB_ID_LEN)


def _enc(data: bytes) -> bytes:
    out = io.BytesIO()
    crypto.encrypt_stream(io.BytesIO(data), out, KEY, BID)
    return out.getvalue()


def _dec(blob: bytes) -> bytes:
    out = io.BytesIO()
    crypto.decrypt_stream(io.BufferedReader(io.BytesIO(blob)), out, KEY)
    return out.getvalue()


class StreamTests(unittest.TestCase):
    def test_roundtrip_sizes(self):
        for n in (0, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, 3 * CHUNK_SIZE):
            data = os.urandom(n)
            self.assertEqual(_dec(_enc(data)), data, n)

    def test_truncation_detected(self):
        blob = _enc(os.urandom(3 * CHUNK_SIZE))
        one_chunk = crypto.HEADER_LEN + 4 + CHUNK_SIZE + 16
        with self.assertRaises(crypto.DecryptionError):
            _dec(blob[:one_chunk])  # drop the last chunks cleanly at a boundary

    def test_appended_data_detected(self):
        blob = _enc(b"hello")
        with self.assertRaises(crypto.DecryptionError):
            _dec(blob + blob[crypto.HEADER_LEN:])

    def test_wrong_key(self):
        blob = _enc(b"hello")
        out = io.BytesIO()
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt_stream(io.BufferedReader(io.BytesIO(blob)), out, os.urandom(32))

    def test_seal(self):
        sealed = crypto.seal(KEY, b"data", b"aad")
        self.assertEqual(crypto.unseal(KEY, sealed, b"aad"), b"data")
        with self.assertRaises(crypto.DecryptionError):
            crypto.unseal(KEY, sealed, b"other")


if __name__ == "__main__":
    unittest.main()
