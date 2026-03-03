"""Root CA operations for MicroPKI."""

import os
from typing import Optional
from datetime import datetime
from pathlib import Path

from micropki import crypto_utils
from micropki import certificates
from micropki.logger import setup_logger


class RootCA:
    """Root Certificate Authority."""
    
    def __init__(self, out_dir: str, log_file: Optional[str] = None):
        """
        Initialize the Root CA.
        
        Args:
            out_dir: Output directory for CA files.
            log_file: Optional path to log file.
        """
        self.out_dir = Path(out_dir)
        self.private_dir = self.out_dir / "private"
        self.certs_dir = self.out_dir / "certs"
        
        # Setup logger
        self.logger = setup_logger(log_file)
        
        # Will be set during initialization
        self.private_key = None
        self.certificate = None
        self.subject_dn = None
        self.key_type = None
        self.key_size = None
    
    def create_directories(self) -> None:
        """Create the required directory structure."""
        self.logger.info(f"Creating directories in {self.out_dir}")
        
        # Create directories with appropriate permissions
        self.private_dir.mkdir(parents=True, exist_ok=True)
        self.certs_dir.mkdir(parents=True, exist_ok=True)
        
        # Set private directory permissions to 0o700 (Unix-like)
        try:
            os.chmod(self.private_dir, 0o700)
        except (OSError, AttributeError):
            self.logger.warning(f"Could not set permissions on {self.private_dir}")
    
    def generate_key(self, key_type: str, key_size: int, passphrase: bytes) -> None:
        """
        Generate the CA's private key.
        
        Args:
            key_type: 'rsa' or 'ecc'.
            key_size: Key size in bits.
            passphrase: Passphrase for key encryption.
        
        Raises:
            ValueError: If key_type or key_size is invalid.
        """
        self.logger.info(f"Starting key generation: {key_type}-{key_size}")
        
        if key_type == "rsa":
            self.private_key = crypto_utils.generate_rsa_key(key_size)
        elif key_type == "ecc":
            self.private_key = crypto_utils.generate_ecc_key(key_size)
        else:
            raise ValueError(f"Unsupported key type: {key_type}")
        
        self.key_type = key_type
        self.key_size = key_size
        
        self.logger.info(f"Key generation completed successfully")
        
        # Encrypt and save the private key
        self._save_encrypted_key(passphrase)
    
    def _save_encrypted_key(self, passphrase: bytes) -> None:
        """
        Encrypt and save the private key.
        
        Args:
            passphrase: Passphrase for encryption.
        """
        key_path = self.private_dir / "ca.key.pem"
        
        self.logger.info(f"Encrypting private key with passphrase")
        
        # Encrypt the private key
        encrypted_key = crypto_utils.encrypt_private_key(self.private_key, passphrase)
        
        # Save with secure permissions (0o600)
        crypto_utils.save_pem_data(encrypted_key, str(key_path), mode=0o600)
        
        self.logger.info(f"Saved encrypted private key to {key_path}")
    
    def create_self_signed_certificate(self, subject_dn: str, validity_days: int) -> None:
        """
        Create a self-signed CA certificate.
        
        Args:
            subject_dn: Distinguished Name for the certificate.
            validity_days: Validity period in days.
        """
        self.logger.info(f"Starting certificate generation for subject: {subject_dn}")
        self.subject_dn = subject_dn
        
        # Create the certificate
        self.certificate = certificates.create_self_signed_ca_certificate(
            subject_dn=subject_dn,
            private_key=self.private_key,
            validity_days=validity_days,
            key_type=self.key_type
        )
        
        self.logger.info(f"Certificate generation completed successfully")
        
        # Save the certificate
        cert_path = self.certs_dir / "ca.cert.pem"
        certificates.save_certificate(self.certificate, str(cert_path))
        
        self.logger.info(f"Saved certificate to {cert_path}")
    
    def generate_policy_document(self) -> None:
        """Generate the policy.txt document."""
        policy_path = self.out_dir / "policy.txt"
        
        self.logger.info(f"Generating policy document at {policy_path}")
        
        # Extract certificate information
        subject = self.certificate.subject.rfc4514_string()
        serial_hex = format(self.certificate.serial_number, 'x').upper()
        not_before = self.certificate.not_valid_before_utc.isoformat()
        not_after = self.certificate.not_valid_after_utc.isoformat()
        
        # Format key algorithm description
        if self.key_type == "rsa":
            key_desc = f"RSA-{self.key_size}"
        else:
            key_desc = "ECC-P384 (NIST P-384)"
        
        # Current date for policy version
        creation_date = datetime.now().isoformat()
        
        policy_content = f"""CERTIFICATE POLICY DOCUMENT
==========================
Version: 1.0
Created: {creation_date}

CA Name (Subject DN):
  {subject}

Certificate Details:
  Serial Number (hex): {serial_hex}
  Valid From: {not_before}
  Valid To: {not_after}
  Key Algorithm: {key_desc}

Statement of Purpose:
  This Root CA is established for the MicroPKI demonstration project.
  It serves as the trust anchor for issuing intermediate and end-entity
  certificates in a controlled test environment.

Policy Constraints:
  - This CA does not issue certificates directly to end entities
  - All certificate issuance must follow the Certificate Practice Statement
  - Private keys are stored encrypted with AES-256-CBC + PBKDF2
  - Access to the Root CA private key requires physical presence or
    multi-person control (simulated)

This policy document is for demonstration purposes only.
For production use, a comprehensive Certificate Practice Statement (CPS)
would be required following RFC 3647 guidelines.
"""
        
        # Write policy document
        with open(policy_path, 'w') as f:
            f.write(policy_content)
        
        self.logger.info(f"Policy document generated successfully")
    
    def initialize(
        self,
        subject_dn: str,
        key_type: str,
        key_size: int,
        passphrase: bytes,
        validity_days: int
    ) -> None:
        """
        Initialize the Root CA.
        
        This method orchestrates the entire CA initialization process.
        
        Args:
            subject_dn: Distinguished Name for the CA.
            key_type: 'rsa' or 'ecc'.
            key_size: Key size in bits.
            passphrase: Passphrase for key encryption.
            validity_days: Validity period in days.
        """
        self.logger.info("Starting Root CA initialization")
        
        # Create directory structure
        self.create_directories()
        
        # Generate key pair
        self.generate_key(key_type, key_size, passphrase)
        
        # Create self-signed certificate
        self.create_self_signed_certificate(subject_dn, validity_days)
        
        # Generate policy document
        self.generate_policy_document()
        
        self.logger.info("Root CA initialization completed successfully")
