# PKI-enabled-linter
Python script to check digital certificates against Bangladesh Root CA Certificate Policy
Bangladesh CA Certificate Linter
This repository contains a Python script to check digital certificates against the requirements specified in the Bangladesh Root CA Certificate Policy (CP) - Version 3.1, approved on 26 September 2023.
Purpose
The script verifies compliance of X.509 certificates issued by Bangladeshi Certificate Authorities (e.g., BCC-CA, BBCA, Dohatec CA) with the policy, checking aspects like version, serial number, signature algorithm, public key, validity period, and required extensions.
Dependencies

Python 3.9 or newer (Python Downloads)
cryptography library: Install with pip install cryptography

Installation

Clone the repository:git clone https://github.com/laheen-who/PKI-enabled-linter.git
cd Bangladesh-CA-Certificate-Linter


Install dependencies:pip install -r requirements.txt



Usage

Save your certificate in PEM format (e.g., certificate.pem).
Run the script:python linter.py certificate.pem


The script outputs whether the certificate complies and lists any issues found.

Checks Performed
The certificate_linter.py script verifies:

Certificate version is X.509 v3
Serial number is at least 64 bits and positive
Signature algorithm is SHA-256, SHA-384, or SHA-512 with RSA (OIDs: 1.2.840.113549.1.1.11, .12, .13)
Public key is RSA (≥2048 bits) or ECC (NIST P-256, P-384, P-521)
Validity period:
CA certificates: ≤10 years
Subscriber certificates: ≤825 days (post-1 March 2018) or ≤39 months (1 July 2016 to 1 March 2018)


certificatePolicies includes OID 2.16.50.1.2
keyUsage is critical, with:
CA: keyCertSign and cRLSign
Subscriber: At least one of digitalSignature, keyEncipherment, or dataEncipherment



Limitations

The script checks key requirements but not all policy aspects (e.g., detailed name formats or CA/Browser Forum compliance).
For Code Signing certificates, RSA keys should be 4096 bits, but the script uses a 2048-bit minimum as purpose isn’t determined.
Additional tools like pkilint may be needed for comprehensive validation.

# Module-Lattice-Based-Key-Encapsulation-Mechanism
NIST Post-Quantum Cryptography Demonstration
This project demonstrates NIST draft standards for post-quantum cryptography (PQC), designed to secure Public Key Infrastructure (PKI) systems against quantum computing threats. It implements:

FIPS 2023: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM) using Kyber512 for secure key exchange.
FIPS 2024: Module-Lattice-Based Digital Signature Algorithm (ML-DSA) using Dilithium2 for authentication.
FIPS 2025: Stateless Hash-Based Digital Signature Algorithm (SLH-DSA) using SPHINCS+ for digital signatures.

The script showcases key generation, encryption/decryption, signing/verification, and compares key and signature sizes, providing performance metrics for each operation.
Installation
Prerequisites

Python: Version 3.12 or newer, available at Python Downloads.
oqs-python: Library for post-quantum cryptography from the Open Quantum Safe project.
Operating Systems: Compatible with Linux, macOS, and Windows.

Installation Steps

Install Python:
Download and install Python 3.12 or newer from Python Downloads.
Ensure Python is added to your system PATH during installation.


Install oqs-python:
Open a command prompt or terminal.
Run:pip install oqs-python


Verify installation with pip show oqs-python.



Usage
Running the Script

Save the script as pqc_demonstration.py in your working directory.
Run the script using:python pqc_demonstration.py



What the Script Does
The script performs the following demonstrations:

ML-KEM (Kyber512):
Generates a public/private key pair.
Encrypts a shared secret using the public key and decrypts it with the private key.
Verifies that the shared secrets match.
Outputs performance metrics (e.g., key generation time, encryption/decryption time) and ciphertext size.


ML-DSA (Dilithium2):
Generates a key pair.
Signs a sample message ("This message will be signed with ML-DSA").
Verifies the signature and tests with a tampered message to show invalidation.
Outputs signing/verification times and signature size.


SLH-DSA (SPHINCS+):
Generates a key pair.
Signs a sample message ("This message will be signed with SLH-DSA").
Verifies the signature.
Outputs signing/verification times and signature size.


Size Comparison:
Displays a table comparing public key, private key, and ciphertext/signature sizes for all three algorithms.



Example Output
Running the script produces output like:
Post-Quantum Cryptography Demonstration of NIST FIPS 2023, 2024, and 2025

============================================================
 ============ FIPS 2023: ML-KEM (Kyber) ============
============================================================
Generating keypair...
Key generation took 0.0012 seconds
Encrypting with public key...
Encryption took 0.0009 seconds
Ciphertext size: 800 bytes
Shared secret: 0102030405060708090a...
Decrypting with secret key...
Decryption took 0.0008 seconds
Recovered shared secret: 0102030405060708090a...
Shared secrets match: True

============================================================
 ============ FIPS 2024: ML-DSA (Dilithium) ============
============================================================
Generating keypair...
Key generation took 0.0015 seconds
Message to sign: This message will be signed with ML-DSA
Signing message...
Signing took 0.0010 seconds
Signature size: 2420 bytes
Verifying signature...
Verification took 0.0009 seconds
Signature valid: True
Verifying with tampered message...
Tampered message signature valid (should be False): False

============================================================
 ============ FIPS 2025: SLH-DSA (SPHINCS+) ============
============================================================
Generating keypair...
Key generation took 0.0020 seconds
Message to sign: This message will be signed with SLH-DSA
Signing message...
Signing took 0.0018 seconds
Signature size: 41 bytes
Verifying signature...
Verification took 0.0012 seconds
Signature valid: True

============================================================
 ============ Key and Signature Size Comparison ============
============================================================
Algorithm          | Public Key | Private Key | Ciphertext/Signature
-------------------------------------------------------------
ML-KEM (Kyber)     |      800   |      1632   |            800
ML-DSA (Dilithium) |     1312   |      2560   |           2420
SLH-DSA (SPHINCS+) |     32     |      64     |            41

Contributors

Maliha Laheen
Ferdous Ara Fahima
Tamjeed Rahman
Department of Computer Science and Engineering, Jahangirnagar University

Additional Information
Documentation
For a detailed explanation of the script and its relevance to PKI, refer to the accompanying PDF (pki_2_a_ (2).pdf) in the repository. It includes:

Theoretical background on NIST PQC standards.
Detailed script functionality and performance analysis.
Context for PKI applications in a post-quantum world.

References

NIST Standards: Learn more about FIPS 2023 (ML-KEM), FIPS 2024 (ML-DSA), and FIPS 2025 (SLH-DSA) at NIST PQC.
Open Quantum Safe: The oqs-python library is part of the Open Quantum Safe project, available at Open Quantum Safe.

Purpose
This script is intended for educational and research purposes, demonstrating how post-quantum cryptographic algorithms can be implemented to secure PKI systems. It provides a practical example for developers transitioning to quantum-resistant cryptography.

License
MIT License
Contributing
Feel free to open issues or submit pull requests to improve the script or add features.

