"""
Тесты модуля генерации CSR.
"""

from cryptography.x509.oid import ExtensionOID

from micropki.crypto_utils import generate_private_key
from micropki.certificates import parse_subject_dn
from micropki.csr import build_intermediate_csr, serialize_csr_pem


def test_build_csr_rsa():
    """CSR для промежуточного CA с RSA-ключом содержит субъект и BasicConstraints."""
    key = generate_private_key("rsa", 4096)
    subject = parse_subject_dn("/CN=Test Intermediate/O=Test")
    csr = build_intermediate_csr(key, subject, path_length=0, key_type="rsa")

    assert csr.subject == subject
    assert csr.is_signature_valid is True

    bc_ext = csr.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    assert bc_ext.value.ca is True
    assert bc_ext.value.path_length == 0


def test_build_csr_ecc():
    """CSR для промежуточного CA с ECC-ключом."""
    key = generate_private_key("ecc", 384)
    subject = parse_subject_dn("CN=ECC Intermediate")
    csr = build_intermediate_csr(key, subject, path_length=1, key_type="ecc")

    assert csr.is_signature_valid is True
    bc_ext = csr.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    assert bc_ext.value.path_length == 1


def test_csr_pem_serialization():
    """CSR сериализуется в PEM с правильным заголовком."""
    key = generate_private_key("rsa", 4096)
    subject = parse_subject_dn("/CN=PEM Test")
    csr = build_intermediate_csr(key, subject, path_length=0, key_type="rsa")

    pem = serialize_csr_pem(csr)
    assert b"-----BEGIN CERTIFICATE REQUEST-----" in pem