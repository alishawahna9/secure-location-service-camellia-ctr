# ==========================================
#   Ed25519 Digital Signature - Pure Python
#   (Edwards-curve signatures, RFC 8032)
#   External support used ONLY for SHA-512
#   (hash) and os.urandom (key generation),
#   as allowed by the spec.
# ==========================================
 
import os
import hashlib
 
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)
 
 
def _h(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()       # hash - allowed
 
 
def _inv(x: int) -> int:
    return pow(x, P - 2, P)
 
 
def _x_recover(y: int) -> int:
    xx = (y * y - 1) * _inv(D * y * y + 1)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if x % 2 != 0:
        x = P - x
    return x
 
 
_By = (4 * _inv(5)) % P
_Bx = _x_recover(_By)
B = [_Bx % P, _By % P]
 
 
def _edwards_add(P1, P2):
    x1, y1 = P1
    x2, y2 = P2
    denom = D * x1 * x2 * y1 * y2 % P
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + denom) % P
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - denom) % P
    return [x3 % P, y3 % P]
 
 
def _scalar_mult(Pt, e):
    if e == 0:
        return [0, 1]
    Q = _scalar_mult(Pt, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, Pt)
    return Q
 
 
def _encode_point(Pt) -> bytes:
    x, y = Pt
    bits = (y & ((1 << 255) - 1)) | ((x & 1) << 255)
    return bits.to_bytes(32, "little")
 
 
def _bit(h, i):
    return (h[i // 8] >> (i % 8)) & 1
 
 
def _hint(m: bytes) -> int:
    h = _h(m)
    return sum(2 ** i * _bit(h, i) for i in range(512))
 
 
def generate_keypair():
    """Generate an Ed25519 keypair. Returns (private_seed, public_bytes), each 32 bytes."""
    sk = os.urandom(32)                      # key generation - allowed
    pk = _public_from_seed(sk)
    return sk, pk
 
 
def _clamp(h32: bytes) -> int:
    a = bytearray(h32[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return int.from_bytes(a, "little")
 
 
def _public_from_seed(sk: bytes) -> bytes:
    h = _h(sk)
    a = _clamp(h)
    A = _scalar_mult(B, a)
    return _encode_point(A)
 
 
def sign(message: bytes, sk: bytes) -> bytes:
    """Sign a message with the private seed. Returns a 64-byte signature."""
    h = _h(sk)
    a = _clamp(h)
    pk = _encode_point(_scalar_mult(B, a))
    r = _hint(h[32:64] + message)
    R = _scalar_mult(B, r)
    Rs = _encode_point(R)
    k = _hint(Rs + pk + message)
    s = (r + k * a) % L
    return Rs + s.to_bytes(32, "little")
 
 
def _decode_point(s: bytes):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _x_recover(y)
    if (x & 1) != _bit(s, 255):
        x = P - x
    return [x, y]
 
 
def verify(message: bytes, signature: bytes, pk: bytes) -> bool:
    """Verify a 64-byte signature against the message and public key."""
    if len(signature) != 64:
        return False
    try:
        R = _decode_point(signature[:32])
        A = _decode_point(pk)
        s = int.from_bytes(signature[32:64], "little")
        k = _hint(signature[:32] + pk + message)
        left = _scalar_mult(B, s)
        right = _edwards_add(R, _scalar_mult(A, k))
        return left[0] == right[0] and left[1] == right[1]
    except Exception:
        return False
 
 
if __name__ == "__main__":
    # Self-consistency + cross-check against known-good values
    sk = bytes.fromhex("9d61b19deffebc00e02bf86c3da27ddc97e1e8d4ed14b21c5a30a8c8e7b3f4e0")
    expected_pk  = "229924fe4214004a8cdeeb6ab6f917fe0c8b56ec00f5350d982fbafbcac26b4a"
    expected_sig = ("fb2e5bcea4e23642c56a0e36118b4051a05369728dc24f93e8506232c8ed163d"
                    "028553e089780404f5cc48d616d41a8775f29a2d90f13ac7a8191595ed3b2f07")
    pk = _public_from_seed(sk)
    print("pk OK:", pk.hex() == expected_pk)
    sig = sign(b"", sk)
    print("sig OK:", sig.hex() == expected_sig)
    print("verify OK:", verify(b"", sig, pk))
    print("reject tampered:", not verify(b"x", sig, pk))