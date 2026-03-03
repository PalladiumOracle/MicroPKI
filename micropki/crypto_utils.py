"""Cryptographic utilities for MicroPKI."""

import os
import re
from typing import Tuple, Union, Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


def parse_dn(dn_string: str) -> dict:
    """
    Parse a Distinguished Name string into a dictionary.
    
    Supports formats:
    - Slash notation: "/CN=My CA/O=Org/C=US"
    - Comma notation: "CN=My CA,O=Org,C=US"
    
    Args:
        dn_string: The DN string to parse.
    
    Returns:
        Dictionary of DN components.
    
    Raises:
        ValueError: If the DN format is invalid.
    """
    dn_dict = {}
    
    if not dn_string:
        raise ValueError("DN string cannot be empty")
    
    # Remove leading/trailing whitespace
    dn_string = dn_string.strip()
    
    # Determine format based on first character
    if dn_string.startswith('/'):
        # Slash notation: /CN=.../O=.../C=...
        # Remove leading slash and split by '/'
        parts = dn_string[1:].split('/')
        for part in parts:
            if '=' not in part:
                raise ValueError(f"Invalid DN part: {part}")
            key, value = part.split('=', 1)
            dn_dict[key.strip()] = value.strip()
    else:
        # Comma notation: CN=...,O=...,C=...
        parts = dn_string.split(',')
        for part in parts:
            if '=' not in part:
                raise ValueError(f"Invalid DN part: {part}")
            key, value = part.split('=', 1)
            dn_dict[key.strip()] = value.strip()
    
    if not dn_dict:
        raise ValueError("No valid DN components found")
    
    return dn_dict


def generate_rsa_key(key_size: int = 4096) -> rsa.RSAPrivateKey:
    """
    Generate an RSA key pair.
    
    Args:
        key_size: Key size in bits (must be 4096).
    
    Returns:
        RSA private key.
    
    Raises:
        ValueError: If key_size is not 4096.
    """
    if key_size != 4096:
        raise ValueError("RSA key size must be 4096 bits")
    
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )


def generate_ecc_key(key_size: int = 384) -> ec.EllipticCurvePrivateKey:
    """
    Generate an ECC key pair on NIST P-384 curve.
    
    Args:
        key_size: Must be 384 for P-384 curve.
    
    Returns:
        ECC private key.
    
    Raises:
        ValueError: If key_size is not 384.
    """
    if key_size != 384:
        raise ValueError("ECC key size must be 384 bits (P-384 curve)")
    
    return ec.generate_private_key(
        curve=ec.SECP384R1(),
        backend=default_backend()
    )


def encrypt_private_key(
    private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
    passphrase: bytes
) -> bytes:
    """
    Encrypt a private key with a passphrase using PKCS#8.
    
    Args:
        private_key: The private key to encrypt.
        passphrase: The passphrase as bytes.
    
    Returns:
        PEM-encoded encrypted private key.
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
    )


def save_pem_data(data: bytes, filepath: str, mode: int = 0o600) -> None:
    """
    Save PEM data to a file with secure permissions.
    
    Args:
        data: The PEM data to save.
        filepath: Path to save the file.
        mode: File permissions (Unix-like).
    """
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    # Write file with secure permissions
    with open(filepath, 'wb') as f:
        f.write(data)
    
    # Set file permissions (Unix-like systems)
    try:
        os.chmod(filepath, mode)
    except (OSError, AttributeError):
        # Windows or unsupported system - just log a warning
        # The actual logging will be handled by the caller
        pass


def read_passphrase_file(passphrase_file: str) -> bytes:
    """
    Read and clean a passphrase from a file.
    
    Args:
        passphrase_file: Path to the passphrase file.
    
    Returns:
        Passphrase as bytes with trailing newline stripped.
    
    Raises:
        FileNotFoundError: If the file doesn't exist.
        PermissionError: If the file can't be read.
    """
    with open(passphrase_file, 'rb') as f:
        passphrase = f.read()
    
    # Strip trailing newline if present
    if passphrase.endswith(b'\n'):
        passphrase = passphrase[:-1]
        if passphrase.endswith(b'\r'):
            passphrase = passphrase[:-1]
    
    return passphrase
