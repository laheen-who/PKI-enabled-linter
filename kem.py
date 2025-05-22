import os
import time
import oqs

def print_separator(title):
    """Print a separator with title."""
    print("\n" + "=" * 60)
    print(f" {title} ".center(60, "="))
    print("=" * 60)

def demonstrate_ml_kem():
    """
    Demonstrate FIPS 2023 (ML-KEM) - Kyber512.
    """
    print_separator("FIPS 2023: ML-KEM (Kyber)")
    print("Generating keypair...")
    start_time = time.time()
    kem = oqs.KeyEncapsulation("Kyber512")
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()
    key_gen_time = time.time() - start_time
    print(f"Key generation took {key_gen_time:.4f} seconds")

    print("\nEncrypting with public key...")
    start_time = time.time()
    ciphertext, shared_secret_1 = kem.encap_secret(public_key)
    encrypt_time = time.time() - start_time
    print(f"Encryption took {encrypt_time:.4f} seconds")
    print(f"Ciphertext size: {len(ciphertext)} bytes")
    print(f"Shared secret: {shared_secret_1.hex()[:20]}...")

    print("\nDecrypting with secret key...")
    start_time = time.time()
    shared_secret_2 = kem.decap_secret(ciphertext, secret_key)
    decrypt_time = time.time() - start_time
    print(f"Decryption took {decrypt_time:.4f} seconds")
    print(f"Recovered shared secret: {shared_secret_2.hex()[:20]}...")
    print(f"\nShared secrets match: {shared_secret_1 == shared_secret_2}")

def demonstrate_ml_dsa():
    """
    Demonstrate FIPS 2024 (ML-DSA) - Dilithium2.
    """
    print_separator("FIPS 2024: ML-DSA (Dilithium)")
    print("Generating keypair...")
    start_time = time.time()
    sig = oqs.Signature("Dilithium2")
    public_key = sig.generate_keypair()
    secret_key = sig.export_secret_key()
    print(f"Key generation took {time.time() - start_time:.4f} seconds")

    message = b"This message will be signed with ML-DSA"
    print(f"\nMessage to sign: {message.decode()}")

    print("\nSigning message...")
    start_time = time.time()
    signature = sig.sign(message, secret_key)
    print(f"Signing took {time.time() - start_time:.4f} seconds")
    print(f"Signature size: {len(signature)} bytes")

    print("\nVerifying signature...")
    start_time = time.time()
    is_valid = sig.verify(message, signature, public_key)
    print(f"Verification took {time.time() - start_time:.4f} seconds")
    print(f"Signature valid: {is_valid}")

    tampered_message = b"This message has been tampered with"
    print("\nVerifying with tampered message...")
    is_valid = sig.verify(tampered_message, signature, public_key)
    print(f"Tampered message signature valid (should be False): {is_valid}")

def demonstrate_slh_dsa():
    """
    Demonstrate FIPS 2025 (SLH-DSA) - SPHINCS+.
    """
    print_separator("FIPS 2025: SLH-DSA (SPHINCS+)")
    print("Generating keypair...")
    start_time = time.time()
    sig = oqs.Signature("SPHINCS+-SHA2-128s-simple")
    public_key = sig.generate_keypair()
    secret_key = sig.export_secret_key()
    print(f"Key generation took {time.time() - start_time:.4f} seconds")

    message = b"This message will be signed with SLH-DSA"
    print(f"\nMessage to sign: {message.decode()}")

    print("\nSigning message...")
    start_time = time.time()
    signature = sig.sign(message, secret_key)
    print(f"Signing took {time.time() - start_time:.4f} seconds")
    print(f"Signature size: {len(signature)} bytes")

    print("\nVerifying signature...")
    start_time = time.time()
    is_valid = sig.verify(message, signature, public_key)
    print(f"Verification took {time.time() - start_time:.4f} seconds")
    print(f"Signature valid: {is_valid}")

def compare_key_sizes():
    """Compare key and signature sizes of the PQC algorithms."""
    print_separator("Key and Signature Size Comparison")
    kem = oqs.KeyEncapsulation("Kyber512")
    kyber_pk = kem.generate_keypair()
    kyber_sk = kem.export_secret_key()
    kyber_ct, _ = kem.encap_secret(kyber_pk)

    sig_dil = oqs.Signature("Dilithium2")
    dilithium_pk = sig_dil.generate_keypair()
    dilithium_sk = sig_dil.export_secret_key()
    dilithium_sig = sig_dil.sign(b"test", dilithium_sk)

    sig_sph = oqs.Signature("SPHINCS+-SHA2-128s-simple")
    sphincs_pk = sig_sph.generate_keypair()
    sphincs_sk = sig_sph.export_secret_key()
    sphincs_sig = sig_sph.sign(b"test", sphincs_sk)

    print("Algorithm          | Public Key | Private Key | Ciphertext/Signature")
    print("-" * 65)
    print(f"ML-KEM (Kyber)     | {len(kyber_pk):10d} | {len(kyber_sk):11d} | {len(kyber_ct):19d}")
    print(f"ML-DSA (Dilithium) | {len(dilithium_pk):10d} | {len(dilithium_sk):11d} | {len(dilithium_sig):19d}")
    print(f"SLH-DSA (SPHINCS+) | {len(sphincs_pk):10d} | {len(sphincs_sk):11d} | {len(sphincs_sig):19d}")

def main():
    print("Post-Quantum Cryptography Demonstration of NIST FIPS 2023, 2024, and 2025")
    demonstrate_ml_kem()
    demonstrate_ml_dsa()
    demonstrate_slh_dsa()
    compare_key_sizes()

if __name__ == "__main__":
    main()
