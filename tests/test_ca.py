"""Tests for CA operations."""

import os
import tempfile
import shutil
from pathlib import Path
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from micropki.ca import RootCA
from micropki.crypto_utils import read_passphrase_file


class TestRootCA:
    """Tests for RootCA class."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for tests."""
        dir_path = tempfile.mkdtemp()
        yield dir_path
        shutil.rmtree(dir_path)
    
    @pytest.fixture
    def passphrase_file(self, temp_dir):
        """Create a passphrase file."""
        pass_file = Path(temp_dir) / "passphrase.txt"
        with open(pass_file, 'wb') as f:
            f.write(b"test-passphrase")
        return str(pass_file)
    
    def test_ca_initialization_rsa(self, temp_dir, passphrase_file):
        """Test full CA initialization with RSA."""
        out_dir = Path(temp_dir) / "pki"
        passphrase = read_passphrase_file(passphrase_file)
        
        ca = RootCA(out_dir=str(out_dir))
        ca.initialize(
            subject_dn="/CN=Test Root CA/O=MicroPKI/C=US",
            key_type="rsa",
            key_size=4096,
            passphrase=passphrase,
            validity_days=365
        )
        
        # Check directory structure
        assert (out_dir / "private").exists()
        assert (out_dir / "certs").exists()
        
        # Check private key
        key_path = out_dir / "private" / "ca.key.pem"
        assert key_path.exists()
        
        # Verify key is encrypted
        with open(key_path, 'rb') as f:
            key_data = f.read()
        assert b"ENCRYPTED PRIVATE KEY" in key_data
        
        # Check certificate
        cert_path = out_dir / "certs" / "ca.cert.pem"
        assert cert_path.exists()
        
        # Verify certificate is valid PEM
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        assert b"BEGIN CERTIFICATE" in cert_data
        
        # Check policy document
        policy_path = out_dir / "policy.txt"
        assert policy_path.exists()
        assert policy_path.stat().st_size > 0
    
    def test_ca_initialization_ecc(self, temp_dir, passphrase_file):
        """Test full CA initialization with ECC."""
        out_dir = Path(temp_dir) / "pki"
        passphrase = read_passphrase_file(passphrase_file)
        
        ca = RootCA(out_dir=str(out_dir))
        ca.initialize(
            subject_dn="CN=ECC Test CA,O=MicroPKI,C=US",
            key_type="ecc",
            key_size=384,
            passphrase=passphrase,
            validity_days=365
        )
        
        # Basic checks
        assert (out_dir / "private" / "ca.key.pem").exists()
        assert (out_dir / "certs" / "ca.cert.pem").exists()
    
    def test_certificate_self_consistency(self, temp_dir, passphrase_file):
        """Test that the generated certificate is self-consistent."""
        out_dir = Path(temp_dir) / "pki"
        passphrase = read_passphrase_file(passphrase_file)
        
        ca = RootCA(out_dir=str(out_dir))
        ca.initialize(
            subject_dn="/CN=Test Root CA",
            key_type="rsa",
            key_size=4096,
            passphrase=passphrase,
            validity_days=365
        )
        
        # Load the certificate
        cert_path = out_dir / "certs" / "ca.cert.pem"
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        
        cert = x509.load_pem_x509_certificate(cert_data)
        
        # Verify it's a CA certificate
        basic_constraints = cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        )
        assert basic_constraints.value.ca is True
        
        # Verify key usage
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert key_usage.value.key_cert_sign is True
        assert key_usage.value.crl_sign is True
        
        # Verify subject and issuer are the same (self-signed)
        assert cert.subject == cert.issuer
        
        # Verify extensions
        assert cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        assert cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    
    def test_key_and_certificate_match(self, temp_dir, passphrase_file):
        """Test that the private key matches the certificate."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidSignature
        
        out_dir = Path(temp_dir) / "pki"
        passphrase = read_passphrase_file(passphrase_file)
        
        ca = RootCA(out_dir=str(out_dir))
        ca.initialize(
            subject_dn="/CN=Test Root CA",
            key_type="rsa",
            key_size=4096,
            passphrase=passphrase,
            validity_days=365
        )
        
        # Load the certificate
        cert_path = out_dir / "certs" / "ca.cert.pem"
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data)
        
        # Load the encrypted key
        key_path = out_dir / "private" / "ca.key.pem"
        with open(key_path, 'rb') as f:
            key_data = f.read()
        
        # Decrypt and load the key
        private_key = serialization.load_pem_private_key(
            key_data,
            password=passphrase
        )
        
        # Test signing with private key and verifying with certificate's public key
        test_message = b"Test message for signature"
        
        # Sign with private key
        if isinstance(private_key, rsa.RSAPrivateKey):
            signature = private_key.sign(
                test_message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            # Verify with public key from certificate
            cert.public_key().verify(
                signature,
                test_message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        else:
            # ECC signing
            signature = private_key.sign(
                test_message,
                ec.ECDSA(hashes.SHA384())
            )
            cert.public_key().verify(
                signature,
                test_message,
                ec.ECDSA(hashes.SHA384())
            )
        
        # If we get here without exception, the key pair matches
        assert True
