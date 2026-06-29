# ==========================================
#   Private Location Sharing Service
#   Main application + sender/receiver demo
#
#   Crypto suite:  Camellia-CTR | X25519 | Ed25519
#   The "server" only relays the encrypted packet
#   and can never read the GPS data (end-to-end).
# ==========================================
 
import json
import os
 
import camellia
import X25519
import Ed25519
import Kdf
 
 
class User:
    """A user with a long-term Ed25519 identity and an ephemeral X25519 keypair."""
 
    def __init__(self, name: str):
        self.name = name
        # Long-term identity (Ed25519) - used to sign and authenticate
        self.id_private, self.id_public = Ed25519.generate_keypair()
        # Ephemeral key-exchange keypair (X25519) - per session
        self.eph_private, self.eph_public = X25519.generate_keypair()
 
    def sign_ephemeral(self) -> bytes:
        """Sign our X25519 public key with our Ed25519 identity (anti-MITM)."""
        return Ed25519.sign(self.eph_public, self.id_private)
 
 
def establish_session_key(me: User, peer_eph_public: bytes) -> bytes:
    """Run X25519 and derive a 16-byte Camellia key via HKDF."""
    secret = X25519.shared_secret(me.eph_private, peer_eph_public)
    return Kdf.derive_camellia_key(secret)
 
 
class ShareLocationApp:
    def __init__(self):
        print("\n[+] Initializing secure location sharing and generating keys...")
        self.alice = User("Alice")
        self.bob = User("Bob")
 
        # --- Anti-MITM: each side verifies the peer's ephemeral key signature ---
        # (each already knows the other's long-term Ed25519 identity key)
        if not Ed25519.verify(self.bob.eph_public,
                              self.bob.sign_ephemeral(),
                              self.bob.id_public):
            raise ValueError("Bob's ephemeral key signature is invalid!")
        if not Ed25519.verify(self.alice.eph_public,
                              self.alice.sign_ephemeral(),
                              self.alice.id_public):
            raise ValueError("Alice's ephemeral key signature is invalid!")
 
        # --- Key agreement: both sides derive the same Camellia key ---
        self.alice_key = establish_session_key(self.alice, self.bob.eph_public)
        self.bob_key   = establish_session_key(self.bob, self.alice.eph_public)
        assert self.alice_key == self.bob_key, "Key agreement failed!"
        print("[+] Session established. Shared Camellia key derived on both sides.")
 
    def run_console(self):
        print("=" * 60)
        print("        Secure Location Sharing Simulation")
        print("=" * 60)
        while True:
            print("\n--- Menu ---")
            print("1. Enter a new location and send it securely")
            print("2. Exit")
            choice = input("Choose (1-2): ").strip()
            if choice == "2":
                print("[!] Goodbye.")
                break
            if choice == "1":
                try:
                    lat = input("Latitude  (e.g. 32.1133): ").strip()
                    lon = input("Longitude (e.g. 34.8044): ").strip()
                    if not lat or not lon:
                        print("[X] Both values are required.")
                        continue
                    packet = self._sender(lat, lon)
                    self._print_packet(packet)
                    input("\nPress Enter to relay through the server to Bob...\n")
                    self._receiver(packet)
                except Exception as e:
                    print(f"[X] Error: {e}")
            else:
                print("[X] Invalid choice.")
 
    def _sender(self, lat, lon):
        """Alice: encrypt with Camellia-CTR, then sign the ciphertext with Ed25519."""
        print("\n--- [Sender: Alice] securing the location ---")
        location = json.dumps({"lat": lat, "lon": lon}).encode("utf-8")
 
        print("[+] Encrypting location with Camellia-CTR...")
        cipher = camellia.Camellia(self.alice_key)
        iv = os.urandom(16)  # fresh nonce per message
        ciphertext = cipher.camellia_ctr(location, iv)
 
        print("[+] Signing the ciphertext with Alice's Ed25519 identity...")
        signature = Ed25519.sign(iv + ciphertext, self.alice.id_private)
 
        return {"iv": iv, "ciphertext": ciphertext, "signature": signature}
 
    def _print_packet(self, packet):
        print("\n" + "=" * 18 + " Encrypted packet on the wire " + "=" * 18)
        print(f"  IV         : {packet['iv'].hex()}")
        print(f"  Ciphertext : {packet['ciphertext'].hex()}")
        print(f"  Signature  : {packet['signature'].hex()}")
        print("  (The server sees only this. It cannot read the GPS data.)")
        print("=" * 66)
 
    def _receiver(self, packet):
        """Bob: verify the signature first, then decrypt."""
        print("--- [Receiver: Bob] verifying then decrypting ---")
        iv = packet["iv"]
        ciphertext = packet["ciphertext"]
 
        print("[+] Verifying Alice's signature over the ciphertext...")
        ok = Ed25519.verify(iv + ciphertext, packet["signature"], self.alice.id_public)
        if not ok:
            print("[X] SECURITY WARNING: signature invalid! Data was forged or altered.")
            return
 
        print("[+] Signature valid. Decrypting with Camellia-CTR...")
        cipher = camellia.Camellia(self.bob_key)
        plaintext = cipher.camellia_ctr(ciphertext, iv)
        location = json.loads(plaintext.decode("utf-8"))
        print(f"[OK] Location recovered: lat {location['lat']}, lon {location['lon']}")
 
 
if __name__ == "__main__":
    app = ShareLocationApp()
    app.run_console()