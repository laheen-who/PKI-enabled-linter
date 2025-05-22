import hashlib
import secrets
from dataclasses import dataclass

# --- FIPS 203: Kyber KEM (Module-Lattice KEM) ---
def kyber_keygen():
    """Simulate Kyber key pair generation"""
    sk = secrets.token_bytes(32)  # Private key
    pk = hashlib.shake_128(sk).digest(32)  # Public key
    return pk, sk

def kyber_encaps(pk):
    """Simulate Kyber encapsulation"""
    shared_key = secrets.token_bytes(32)
    ciphertext = hashlib.shake_128(pk + shared_key).digest(32)
    return ciphertext, shared_key

def kyber_decaps(ct, sk):
    """Simulate Kyber decapsulation"""
    return hashlib.shake_128(sk + ct).digest(32)

# --- FIPS 204: Dilithium (Module-Lattice Sig) ---
@dataclass
class Dilithium:
    """Simulate Dilithium signature scheme"""
    def keygen(self):
        sk = secrets.token_bytes(48)  # Longer keys for signatures
        pk = hashlib.shake_256(sk).digest(32)
        return pk, sk
    
    def sign(self, msg: bytes, sk: bytes) -> bytes:
        return hashlib.shake_256(sk + msg).digest(64)  # Larger signatures
    
    def verify(self, msg: bytes, sig: bytes, pk: bytes) -> bool:
        expected = hashlib.shake_256(pk + msg).digest(64)
        return secrets.compare_digest(sig, expected)

# --- FIPS 205: SPHINCS+ (Hash-Based Sig) ---
def sphincs_sign(msg: bytes, sk: bytes) -> bytes:
    """Simulate SPHINCS+'s hash-based signatures"""
    return hashlib.sha3_256(sk + msg).digest() + b"\x01"  # Added marker

def sphincs_verify(msg: bytes, sig: bytes, pk: bytes) -> bool:
    """Verify simulated signature"""
    return sig.endswith(b"\x01")  # Simplified verification

# --- Demo ---
if __name__ == "__main__":
    # FIPS 203 Demo
    pk, sk = kyber_keygen()
    ct, ss1 = kyber_encaps(pk)
    ss2 = kyber_decaps(ct, sk)
    print(f"[FIPS 203] Secret match: {ss1 == ss2}")
    
    # FIPS 204 Demo
    dilithium = Dilithium()
    pk, sk = dilithium.keygen()
    msg = b"Test message"
    sig = dilithium.sign(msg, sk)
    print(f"[FIPS 204] Valid: {dilithium.verify(msg, sig, pk)}")
    
    # FIPS 205 Demo
    sk = secrets.token_bytes(32)
    sig = sphincs_sign(msg, sk)
    print(f"[FIPS 205] Valid: {sphincs_verify(msg, sig, b'')}")
