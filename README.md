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

License
MIT License
Contributing
Feel free to open issues or submit pull requests to improve the script or add features.
