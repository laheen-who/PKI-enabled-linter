import sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from datetime import datetime

def check_certificate_compliance(cert_pem):
    try:
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        errors = []

        if cert.version != x509.Version.v3:
            errors.append(f"Invalid version: {cert.version}, expected v3")

        serial = cert.serial_number
        if serial <= 0 or serial.bit_length() < 64:
            errors.append(f"Invalid serial number: {serial}, must be positive and >= 64 bits")

        sig_alg = cert.signature_hash_algorithm
        allowed_hashes = (hashes.SHA256, hashes.SHA384, hashes.SHA512)
        if not isinstance(sig_alg, allowed_hashes):
            errors.append(f"Invalid signature algorithm: {sig_alg.name}, expected SHA-256/384/512")

        pub_key = cert.public_key()
        if hasattr(pub_key, 'key_size'):
            if pub_key.key_size < 2048:
                errors.append(f"RSA key size {pub_key.key_size} bits, expected >= 2048")
        else:
            errors.append("Unsupported key type or ECC curve not detected")

        now = datetime.utcnow()
        if now < cert.not_valid_before or now > cert.not_valid_after:
            errors.append("Certificate is not currently valid")

        try:
            policies = cert.extensions.get_extension_for_class(x509.CertificatePolicies)
            if not any(p.policy_identifier.dotted_string == "2.16.50.1.2" for p in policies.value):
                errors.append("Missing required policy OID 2.16.50.1.2")
        except x509.ExtensionNotFound:
            errors.append("Missing certificatePolicies extension")

        try:
            cert.extensions.get_extension_for_class(x509.KeyUsage)
        except x509.ExtensionNotFound:
            errors.append("Missing keyUsage extension")

        if errors:
            print("Certificate does not comply with the following requirements:")
            for error in errors:
                print(f"- {error}")
        else:
            print("Certificate complies with the checked requirements")
    except Exception as e:
        print(f"Error processing certificate: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pemlinter.py <certificate.pem>")
        sys.exit(1)
    try:
        with open(sys.argv[1], "rb") as f:
            cert_pem = f.read()
        check_certificate_compliance(cert_pem)
    except FileNotFoundError:
        print(f"File {sys.argv[1]} not found")
    except Exception as e:
        print(f"Error reading file: {str(e)}")
