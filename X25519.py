# ==========================================
#   X25519 Key Exchange - Pure Python
#   (Curve25519 Diffie-Hellman, RFC 7748)
#   External support used ONLY for os.urandom
#   (key generation), as allowed by the spec.
# ==========================================
 
import os
 
P = 2**255 - 19
A24 = 121665
BASE_U = 9
 
 
def _decode_scalar(k_bytes: bytes) -> int:
    """Clamp the 32-byte private key per RFC 7748."""
    k = bytearray(k_bytes)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")
 
 
def _decode_u(u_bytes: bytes) -> int:
    u = bytearray(u_bytes)
    u[31] &= 127
    return int.from_bytes(u, "little") % P
 
 
def _scalar_mult(scalar: int, u: int) -> int:
    """Montgomery ladder constant-iteration scalar multiplication."""
    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0
 
    for t in range(254, -1, -1):
        kt = (scalar >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
 
        A = (x2 + z2) % P
        AA = (A * A) % P
        B = (x2 - z2) % P
        BB = (B * B) % P
        E = (AA - BB) % P
        C = (x3 + z3) % P
        D = (x3 - z3) % P
        DA = (D * A) % P
        CB = (C * B) % P
        x3 = pow((DA + CB) % P, 2, P)
        z3 = (x1 * pow((DA - CB) % P, 2, P)) % P
        x2 = (AA * BB) % P
        z2 = (E * ((AA + A24 * E) % P)) % P
 
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
 
    return (x2 * pow(z2, P - 2, P)) % P
 
 
def x25519(private_bytes: bytes, public_bytes: bytes) -> bytes:
    """Core X25519 function: scalar * point. Both inputs 32 bytes."""
    scalar = _decode_scalar(private_bytes)
    u = _decode_u(public_bytes)
    result = _scalar_mult(scalar, u)
    return result.to_bytes(32, "little")
 
 
def generate_keypair():
    """Generate an X25519 keypair. Returns (private_bytes, public_bytes), each 32 bytes."""
    private_bytes = os.urandom(32)          # key generation - allowed
    base = BASE_U.to_bytes(32, "little")
    public_bytes = x25519(private_bytes, base)
    return private_bytes, public_bytes
 
 
def shared_secret(my_private: bytes, their_public: bytes) -> bytes:
    """Compute the shared secret from my private key and the peer's public key."""
    return x25519(my_private, their_public)
 
 
if __name__ == "__main__":
    # RFC 7748 section 6.1 test vector
    a_priv = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    a_pub  = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    b_priv = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    b_pub  = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    expected_shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
 
    # Public keys derived from privates must match
    assert generate_keypair  # exists
    pub_a = x25519(a_priv, BASE_U.to_bytes(32, "little"))
    pub_b = x25519(b_priv, BASE_U.to_bytes(32, "little"))
    print("pub_a OK:", pub_a.hex() == a_pub.hex())
    print("pub_b OK:", pub_b.hex() == b_pub.hex())
 
    s1 = shared_secret(a_priv, b_pub)
    s2 = shared_secret(b_priv, a_pub)
    print("shared match:", s1 == s2)
    print("shared OK:", s1.hex() == expected_shared)