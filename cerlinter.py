import sys
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

def check_certificate_compliance(cert_data):
    cert = x509.load_der_x509_certificate(cert_data, default_backend())
    errors = []

    # Check version
    if cert.version != x509.Version.v3:
        errors.append("Certificate version is not v3")

    # Check serial number
    serial = cert.serial_number
    if serial.bit_length() < 64 or serial <= 0:
        errors.append("Serial number is invalid")

    # Check signature algorithm
    allowed_oids = [
        "1.2.840.113549.1.1.11",  # SHA256withRSAEncryption
        "1.2.840.113549.1.1.12",  # SHA384withRSAEncryption
        "1.2.840.113549.1.1.13"   # SHA512withRSAEncryption
    ]
    if cert.signature_algorithm_oid.dotted_string not in allowed_oids:
        errors.append("Invalid or unsupported signature algorithm")

    # Check public key
    public_key = cert.public_key()
    if isinstance(public_key, RSAPublicKey):
        if public_key.key_size < 2048:
            errors.append("RSA key size too small (minimum 2048 bits)")
    elif isinstance(public_key, EllipticCurvePublicKey):
        curve = public_key.curve.name
        if curve not in ["secp256r1", "secp384r1", "secp521r1"]:
            errors.append("Unsupported ECC curve")
    else:
        errors.append("Unsupported key type")

    # Determine if it's a CA certificate
    try:
        basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        is_ca = basic_constraints.value.ca
    except x509.ExtensionNotFound:
        is_ca = False

    # Use timezone-aware datetime properties to avoid deprecation warnings
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    validity_days = (not_after - not_before).days

    if is_ca:
        if validity_days > 3650:  # Approximately 10 years
            errors.append("CA certificate validity period exceeds 10 years")
    else:
        if not_before >= datetime.datetime(2018, 3, 1, tzinfo=datetime.timezone.utc):
            if validity_days > 825:
                errors.append("Subscriber certificate validity period exceeds 825 days")
        elif not_before >= datetime.datetime(2016, 7, 1, tzinfo=datetime.timezone.utc):
            if validity_days > 1186:  # Approximately 39 months
                errors.append("Subscriber certificate validity period exceeds 39 months")

    # Check certificatePolicies extension
    try:
        cert_policies = cert.extensions.get_extension_for_class(x509.CertificatePolicies)
        policies = [policy.policy_identifier.dotted_string for policy in cert_policies.value]
        if "2.16.50.1.2" not in policies:
            errors.append("Missing required policy OID 2.16.50.1.2")
    except x509.ExtensionNotFound:
        errors.append("CertificatePolicies extension not found")

    # Check keyUsage extension
    try:
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
        if not key_usage.critical:
            errors.append("KeyUsage extension is not critical")
        if is_ca:
            if not (key_usage.value.key_cert_sign and key_usage.value.crl_sign):
                errors.append("Invalid KeyUsage for CA certificate: must have keyCertSign and cRLSign")
        else:
            if not any([key_usage.value.digital_signature, key_usage.value.key_encipherment, key_usage.value.data_encipherment]):
                errors.append("Invalid KeyUsage for subscriber certificate: must have at least one of digitalSignature, keyEncipherment, or dataEncipherment")
    except x509.ExtensionNotFound:
        errors.append("KeyUsage extension not found")

    if errors:
        print("Certificate does not comply with the following requirements:")
        for error in errors:
            print(f"- {error}")
    else:
        print("Certificate complies with the checked requirements")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python certificate_linter_cer.py <certificate.cer>")
        sys.exit(1)
    cert_file = sys.argv[1]
    try:
        with open(cert_file, "rb") as f:
            cert_data = f.read()
        check_certificate_compliance(cert_data)
    except FileNotFoundError:
        print(f"Error: Certificate file '{cert_file}' not found")
        sys.exit(1)
    except ValueError:
        print("Error: Invalid certificate format")
        sys.exit(1)
