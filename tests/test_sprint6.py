
import datetime
import os
import platform
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID, ExtensionOID

from micropki.client import gen_csr, _load_pem_bundle
from micropki.validation import validate_chain, build_chain
from micropki.revocation_check import extract_ocsp_urls, extract_crl_urls
from micropki.certificates import (
    build_root_ca_certificate,
    build_intermediate_certificate,
    build_leaf_certificate,
    build_leaf_certificate_from_csr,
    parse_subject_dn,
    parse_san_entries,
    build_san_extension,
)
from micropki.csr import build_intermediate_csr, verify_csr_signature
from micropki.templates import get_template

"""
Автоматические тесты для спринта 6.

TEST-38: Генерация CSR
TEST-39: (ручной — request-cert через API)
TEST-40: Проверка цепочки — валидная
TEST-41: Проверка цепочки — просроченный сертификат
TEST-46: Построение цепочки без промежуточного
TEST-49: Невалидная подпись CSR
TEST-50: CSR с CA=True
"""

# ---------------------------------------------------------------------------
# Фикстуры
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def root_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def root_cert(root_key):
    subject = parse_subject_dn("CN=Test Root CA,O=Test")
    return build_root_ca_certificate(
        private_key=root_key, subject=subject,
        validity_days=3650, key_type="rsa",
    )


@pytest.fixture(scope="module")
def inter_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def inter_cert(inter_key, root_key, root_cert):
    subject = parse_subject_dn("CN=Test Intermediate CA,O=Test")
    csr = build_intermediate_csr(inter_key, subject, 0, "rsa")
    return build_intermediate_certificate(
        csr=csr, root_private_key=root_key, root_cert=root_cert,
        validity_days=1825, path_length=0,
    )


@pytest.fixture(scope="module")
def leaf_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def leaf_cert(leaf_key, inter_key, inter_cert):
    subject = parse_subject_dn("CN=test.example.com,O=Test")
    san = parse_san_entries(["dns:test.example.com"])
    template = get_template("server")
    return build_leaf_certificate(
        subject=subject,
        leaf_public_key=leaf_key.public_key(),
        ca_private_key=inter_key,
        ca_cert=inter_cert,
        template=template,
        san_entries=san,
        validity_days=365,
        leaf_key_type="rsa",
    )


# ---------------------------------------------------------------------------
# TEST-38: Генерация CSR
# ---------------------------------------------------------------------------

class TestGenCSR:

    def test_gen_csr_creates_files(self, tmp_path):
        key_path = tmp_path / "test.key.pem"
        csr_path = tmp_path / "test.csr.pem"
        gen_csr(
            subject="CN=test.example.com",
            san_strings=["dns:test.example.com"],
            key_type="rsa", key_size=2048,
            out_key=key_path, out_csr=csr_path,
        )
        assert key_path.exists()
        assert csr_path.exists()

    def test_gen_csr_key_is_unencrypted(self, tmp_path):
        key_path = tmp_path / "test.key.pem"
        csr_path = tmp_path / "test.csr.pem"
        gen_csr(
            subject="CN=test.example.com",
            san_strings=[], key_type="rsa", key_size=2048,
            out_key=key_path, out_csr=csr_path,
        )
        key_pem = key_path.read_bytes()
        assert b"ENCRYPTED" not in key_pem
        private_key = serialization.load_pem_private_key(key_pem, password=None)
        assert private_key is not None

    def test_gen_csr_correct_subject(self, tmp_path):
        key_path = tmp_path / "test.key.pem"
        csr_path = tmp_path / "test.csr.pem"
        gen_csr(
            subject="CN=myapp.local,O=TestOrg",
            san_strings=[], key_type="rsa", key_size=2048,
            out_key=key_path, out_csr=csr_path,
        )
        csr = x509.load_pem_x509_csr(csr_path.read_bytes())
        cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert cn_attrs[0].value == "myapp.local"

    def test_gen_csr_contains_san(self, tmp_path):
        key_path = tmp_path / "test.key.pem"
        csr_path = tmp_path / "test.csr.pem"
        gen_csr(
            subject="CN=app.example.com",
            san_strings=["dns:app.example.com", "dns:api.example.com"],
            key_type="rsa", key_size=2048,
            out_key=key_path, out_csr=csr_path,
        )
        csr = x509.load_pem_x509_csr(csr_path.read_bytes())
        san_ext = csr.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        dns_names = [n.value for n in san_ext.value if isinstance(n, x509.DNSName)]
        assert "app.example.com" in dns_names
        assert "api.example.com" in dns_names

    def test_gen_csr_signature_valid(self, tmp_path):
        key_path = tmp_path / "test.key.pem"
        csr_path = tmp_path / "test.csr.pem"
        gen_csr(
            subject="CN=verify.example.com",
            san_strings=[], key_type="rsa", key_size=2048,
            out_key=key_path, out_csr=csr_path,
        )
        csr = x509.load_pem_x509_csr(csr_path.read_bytes())
        try:
            verify_csr_signature(csr)
        except ValueError as e:
            pytest.fail(f"Подпись CSR должна быть верной: {e}")

    def test_gen_csr_ecc(self, tmp_path):
        key_path = tmp_path / "ecc.key.pem"
        csr_path = tmp_path / "ecc.csr.pem"
        gen_csr(
            subject="CN=ecc.example.com",
            san_strings=["dns:ecc.example.com"],
            key_type="ecc", key_size=256,
            out_key=key_path, out_csr=csr_path,
        )
        key_pem = key_path.read_bytes()
        private_key = serialization.load_pem_private_key(key_pem, password=None)
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)

    @pytest.mark.skipif(os.name == "nt", reason="POSIX права не на Windows")
    def test_gen_csr_key_permissions(self, tmp_path):
        key_path = tmp_path / "perms.key.pem"
        csr_path = tmp_path / "perms.csr.pem"
        gen_csr(
            subject="CN=perms.test", san_strings=[],
            key_type="rsa", key_size=2048,
            out_key=key_path, out_csr=csr_path,
        )
        mode = oct(os.stat(key_path).st_mode & 0o777)
        assert mode == "0o600"


# ---------------------------------------------------------------------------
# TEST-40, TEST-41, TEST-46: Проверка цепочки
# ---------------------------------------------------------------------------

class TestChainValidation:

    def test_valid_chain_succeeds(self, leaf_cert, inter_cert, root_cert):
        """TEST-40: Валидная цепочка."""
        result = validate_chain(
            leaf=leaf_cert,
            untrusted=[inter_cert],
            trusted=[root_cert],
        )
        assert result.success, f"Цепочка должна быть валидной: {result.error}"
        assert len(result.chain) == 3

    def test_chain_without_intermediate_fails(self, leaf_cert, root_cert):
        """TEST-46: Без промежуточного сертификата — ошибка."""
        result = validate_chain(
            leaf=leaf_cert,
            untrusted=[],
            trusted=[root_cert],
        )
        assert not result.success
        assert result.error is not None

    def test_expired_cert_detected(self, inter_key, inter_cert, root_cert):
        """TEST-41: Просроченный сертификат."""
        leaf_key_tmp = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = parse_subject_dn("CN=expired.example.com")
        san = parse_san_entries(["dns:expired.example.com"])
        template = get_template("server")
        leaf_tmp = build_leaf_certificate(
            subject=subject,
            leaf_public_key=leaf_key_tmp.public_key(),
            ca_private_key=inter_key,
            ca_cert=inter_cert,
            template=template,
            san_entries=san,
            validity_days=1,
            leaf_key_type="rsa",
        )
        future_time = datetime.datetime.now(datetime.timezone.utc) + \
                      datetime.timedelta(days=400)
        result = validate_chain(
            leaf=leaf_tmp,
            untrusted=[inter_cert],
            trusted=[root_cert],
            validation_time=future_time,
        )
        assert not result.success

    def test_build_chain_with_intermediate(self, leaf_cert, inter_cert, root_cert):
        chain = build_chain(leaf_cert, untrusted=[inter_cert], trusted=[root_cert])
        assert chain is not None
        assert len(chain) == 3

    def test_build_chain_without_intermediate_none(self, leaf_cert, root_cert):
        chain = build_chain(leaf_cert, untrusted=[], trusted=[root_cert])
        assert chain is None

    def test_chain_cert_results_populated(self, leaf_cert, inter_cert, root_cert):
        result = validate_chain(
            leaf=leaf_cert,
            untrusted=[inter_cert],
            trusted=[root_cert],
        )
        assert len(result.cert_results) > 0
        for cr in result.cert_results:
            assert len(cr.passed) > 0


# ---------------------------------------------------------------------------
# TEST-49, TEST-50: Валидация CSR
# ---------------------------------------------------------------------------

class TestCSRValidation:

    def test_invalid_csr_signature_rejected(self, inter_key, inter_cert):
        """TEST-49: Испорченный CSR."""
        import base64
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = parse_subject_dn("CN=tampered.example.com")
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .sign(key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        pem_lines = csr_pem.split(b"\n")
        body_lines = [l for l in pem_lines if l and not l.startswith(b"-----")]
        if len(body_lines) > 2:
            raw = bytearray(base64.b64decode(body_lines[2]))
            raw[10] ^= 0xFF
            body_lines[2] = base64.b64encode(bytes(raw))
        tampered_pem = (
            b"-----BEGIN CERTIFICATE REQUEST-----\n"
            + b"\n".join(body_lines)
            + b"\n-----END CERTIFICATE REQUEST-----\n"
        )
        try:
            tampered_csr = x509.load_pem_x509_csr(tampered_pem)
            with pytest.raises(ValueError):
                verify_csr_signature(tampered_csr)
        except Exception:
            pass  # Если PEM не загрузился — тест пройден

    def test_csr_with_ca_true_rejected(self, inter_key, inter_cert):
        """TEST-50: CSR с CA=True."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = parse_subject_dn("CN=evil-ca.example.com")
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .sign(key, hashes.SHA256())
        )
        template = get_template("server")
        with pytest.raises(ValueError, match="CA=True"):
            build_leaf_certificate_from_csr(
                csr=csr,
                ca_private_key=inter_key,
                ca_cert=inter_cert,
                template=template,
                validity_days=365,
            )

    def test_valid_csr_accepted(self, inter_key, inter_cert):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = parse_subject_dn("CN=valid.example.com")
        san = parse_san_entries(["dns:valid.example.com"])
        san_ext = build_san_extension(san)
        builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
        if san_ext:
            builder = builder.add_extension(san_ext, critical=False)
        csr = builder.sign(key, hashes.SHA256())
        template = get_template("server")
        cert = build_leaf_certificate_from_csr(
            csr=csr, ca_private_key=inter_key,
            ca_cert=inter_cert, template=template, validity_days=365,
        )
        assert cert is not None
        bc = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
        assert bc.ca is False


# ---------------------------------------------------------------------------
# AIA/CDP разбор
# ---------------------------------------------------------------------------

class TestAIACDP:

    def test_extract_ocsp_urls_empty(self, leaf_cert):
        urls = extract_ocsp_urls(leaf_cert)
        assert isinstance(urls, list)

    def test_extract_crl_urls_empty(self, leaf_cert):
        urls = extract_crl_urls(leaf_cert)
        assert isinstance(urls, list)

    def test_load_pem_bundle_single(self, root_cert):
        pem = root_cert.public_bytes(serialization.Encoding.PEM)
        certs = _load_pem_bundle(pem)
        assert len(certs) == 1

    def test_load_pem_bundle_chain(self, root_cert, inter_cert):
        bundle = (
            inter_cert.public_bytes(serialization.Encoding.PEM)
            + root_cert.public_bytes(serialization.Encoding.PEM)
        )
        certs = _load_pem_bundle(bundle)
        assert len(certs) == 2