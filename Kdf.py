
# ==========================================
#   KDF - Key Derivation Function
#   HKDF-SHA256 (RFC 5869)
#   Derives the 16-byte Camellia key from the
#   X25519 shared secret. Uses SHA-256 only
#   (hash), as allowed by the spec.
# ==========================================
 
import hashlib
import hmac
 
HASH_LEN = 32  # SHA-256 output size
 
 
def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()
 
 
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """Extract step: PRK = HMAC(salt, IKM)."""
    if not salt:
        salt = b"\x00" * HASH_LEN
    return _hmac_sha256(salt, ikm)
 
 
def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """Expand step: produce `length` bytes of output keying material."""
    if length > 255 * HASH_LEN:
        raise ValueError("length too large")
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = _hmac_sha256(prk, t + info + bytes([counter]))
        okm += t
        counter += 1
    return okm[:length]
 
 
def derive_camellia_key(shared_secret: bytes,
                        info: bytes = b"camellia-ctr key",
                        salt: bytes = b"",
                        length: int = 16) -> bytes:
    """
    Derive a Camellia key from the X25519 shared secret.
    Default length = 16 bytes (Camellia-128).
    """
    prk = hkdf_extract(salt, shared_secret)
    return hkdf_expand(prk, info, length)
 
 
if __name__ == "__main__":
    # RFC 5869 Test Case 1
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    prk = hkdf_extract(salt, ikm)
    expected_prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    print("PRK OK:", prk.hex() == expected_prk)
    okm = hkdf_expand(prk, info, 42)
    expected_okm = ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                    "34007208d5b887185865")
    print("OKM OK:", okm.hex() == expected_okm)
 
    # Demo: derive a 16-byte Camellia key from a dummy shared secret
    demo_secret = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    key = derive_camellia_key(demo_secret)
    print("Camellia key (16 bytes):", key.hex(), "len:", len(key))