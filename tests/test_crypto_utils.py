"""Tests for crypto utilities."""

import os
import tempfile
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from micropki import crypto_utils


class TestParseDN:
    """Tests for DN parsing."""
    
    def test_parse_slash_notation(self):
        """Test parsing slash notation DN."""
        dn = "/CN=Test CA/O=Organization/C=US"
        result = crypto_utils.parse_dn(dn)
        assert result == {"CN": "Test CA", "O": "Organization", "C": "US"}
    
    def test_parse_comma_notation(self):
        """Test parsing comma notation DN."""
        dn = "CN=Test CA,O=Organization,C=US"
        result = crypto_utils.parse_dn(dn)
        assert result == {"CN": "Test CA", "O": "Organization", "C": "US"}
    
    def test_parse_with_spaces(self):
        """Test parsing DN with spaces."""
        dn = "CN=Test CA, O=Organization, C=US"
        result = crypto_utils.parse_dn(dn)
        assert result == {"CN": "Test CA", "O": "Organization", "C": "US"}
    
    def test_empty_dn(self):
        """Test empty DN raises error."""
        with pytest.raises(ValueError, match="cannot be empty"):
            crypto_utils.parse_dn("")
    
    def test_invalid_format(self):
        """Test invalid DN format."""
        with pytest.raises(ValueError, match="Invalid DN part"):
            crypto_utils.parse_dn("/CN=Test/O=Org/Invalid")


class TestKeyGeneration:
    """Tests for key generation."""
    
    def test_generate_rsa_key(self):
        """Test RSA key generation."""
        key = crypto_utils.generate_rsa_key(4096)
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 4096
    
    def test_rsa_invalid_size(self):
        """Test RSA key with invalid size."""
        with pytest.raises(ValueError, match="must be 4096"):
            crypto_utils.generate_rsa_key(2048)
    
    def test_generate_ecc_key(self):
        """Test ECC key generation."""
        key = crypto_utils.generate_ecc_key(384)
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert isinstance(key.curve, ec.SECP384R1)
    
    def test_ecc_invalid_size(self):
        """Test ECC key with invalid size."""
        with pytest.raises(ValueError, match="must be 384"):
            crypto_utils.generate_ecc_key(256)


class TestPassphraseFile:
    """Tests for passphrase file handling."""
    
    def test_read_passphrase_file(self):
        """Test reading passphrase from file."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"test-passphrase\n")
            temp_file = f.name
        
        try:
            passphrase = crypto_utils.read_passphrase_file(temp_file)
            assert passphrase == b"test-passphrase"
        finally:
            os.unlink(temp_file)
    
    def test_read_passphrase_no_newline(self):
        """Test reading passphrase without newline."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"test-passphrase")
            temp_file = f.name
        
        try:
            passphrase = crypto_utils.read_passphrase_file(temp_file)
            assert passphrase == b"test-passphrase"
        finally:
            os.unlink(temp_file)
    
    def test_file_not_found(self):
        """Test non-existent file."""
        with pytest.raises(FileNotFoundError):
            crypto_utils.read_passphrase_file("/nonexistent/passphrase.txt")
