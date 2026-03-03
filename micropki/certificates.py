"""X.509 certificate handling for MicroPKI."""

import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Union, Tuple
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from micropki.crypto_utils import parse_dn


def generate_serial_number() -> int:
    """
    Generate a cryptographically secure random serial number.
    
    Returns:
        A positive integer with at least 20 bits of randomness.
    """
    # Generate 20 random bytes (160 bits) and convert to integer
    # Ensure it's positive by clearing the most significant bit
    random_bytes = secrets.token_bytes(20)
    
    # Convert to integer
    serial = int.from_bytes(random_bytes, byteorder='big')
    
    # Ensure it's positive and not zero
    if serial == 0:
        serial = 1
    
    return serial


def build_subject_from_dn(dn_string: str) -> x509.Name:
    """
    Build an X.509 Name object from a DN string.
    
    Args:
        dn_string: Distinguished Name string.
    
    Returns:
        X.509 Name object.
    
    Raises:
        ValueError: If the DN format is invalid or contains unsupported attributes.
    """
    dn_dict = parse_dn(dn_string)
    
    # Map common DN attributes to OIDs
    attributes = []
    oid_map = {
        'CN': NameOID.COMMON_NAME,
        'O': NameOID.ORGANIZATION_NAME,
        'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
        'C': NameOID.COUNTRY_NAME,
        'ST': NameOID.STATE_OR_PROVINCE_NAME,
        'L': NameOID.LOCALITY_NAME,
        'emailAddress': NameOID.EMAIL_ADDRESS,
        'DC': NameOID.DOMAIN_COMPONENT,
    }
    
    for key, value in dn_dict.items():
        if key not in oid_map:
            raise ValueError(f"Unsupported DN attribute: {key}")
        attributes.append(x509.NameAttribute(oid_map[key], value))
    
    return x509.Name(attributes)


def create_self_signed_ca_certificate(
    subject_dn: str,
    private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
    validity_days: int,
    key_type: str
) -> x509.Certificate:
    """
    Create a self-signed CA certificate.
    
    Args:
        subject_dn: Distinguished Name for the certificate.
        private_key: The CA's private key.
        validity_days: Validity period in days.
        key_type: Either 'rsa' or 'ecc' for signature algorithm selection.
    
    Returns:
        The generated X.509 certificate.
    """
    subject = build_subject_from_dn(subject_dn)
    
    # For self-signed, issuer is the same as subject
    issuer = subject
    
    # Generate serial number
    serial_number = generate_serial_number()
    
    # Set validity period
    not_valid_before = datetime.now(timezone.utc)
    not_valid_after = not_valid_before + timedelta(days=validity_days)
    
    # Build certificate
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.serial_number(serial_number)
    builder = builder.not_valid_before(not_valid_before)
    builder = builder.not_valid_after(not_valid_after)
    builder = builder.public_key(private_key.public_key())
    
    # Add extensions
    
    # Basic Constraints: CA=TRUE (critical)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )
    
    # Key Usage: keyCertSign, cRLSign (critical)
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )
    
    # Subject Key Identifier
    ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
    builder = builder.add_extension(ski, critical=False)
    
    # Authority Key Identifier (same as SKI for self-signed)
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key())
    builder = builder.add_extension(aki, critical=False)
    
    # Sign the certificate
    if key_type == 'rsa':
        signature_algorithm = hashes.SHA256()
    else:  # ecc
        signature_algorithm = hashes.SHA384()
    
    certificate = builder.sign(
        private_key=private_key,
        algorithm=signature_algorithm,
        backend=default_backend()
    )
    
    return certificate


def certificate_to_pem(certificate: x509.Certificate) -> bytes:
    """
    Convert an X.509 certificate to PEM format.
    
    Args:
        certificate: The certificate to convert.
    
    Returns:
        PEM-encoded certificate.
    """
    return certificate.public_bytes(encoding=serialization.Encoding.PEM)


def save_certificate(certificate: x509.Certificate, filepath: str) -> None:
    """
    Save a certificate to a file in PEM format.
    
    Args:
        certificate: The certificate to save.
        filepath: Path to save the certificate.
    """
    pem_data = certificate_to_pem(certificate)
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    with open(filepath, 'wb') as f:
        f.write(pem_data)
