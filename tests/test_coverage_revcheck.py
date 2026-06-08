"""
Тесты для модуля revocation_check.py.
"""

import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes

from micropki.certificates import (
    build_root_ca_certificate,
    build_intermediate_certificate,
    build_leaf_certificate,
    parse_subject_dn,
    parse_san_entries,
)
from micropki.csr import build_intermediate_csr
from micropki.templates import get_template
from micropki.revocation_check import (
    extract_ocsp_urls,
    extract_crl_urls,
    check_crl,
    check_ocsp,
    check_revocation,
    RevocationStatus,
    _load_crl,
    _verify_crl_signature,
)
from micropki.crl import build_crl, serialize_crl_pem


@pytest.fixture(scope="module")
def root_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def root_cert(root_key):
    return build_root_ca_certificate(
        private_key=root_key,
        subject=parse_subject_dn("CN=RevCheck Root,O=Test"),
        validity_days=3650, key_type="rsa",
    )


@pytest.fixture(scope="module")
def inter_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def inter_cert(inter_key, root_key, root_cert):
    csr = build_intermediate_csr(
        inter_key,
        parse_subject_dn("CN=RevCheck Inter,O=Test"),
        0, "rsa",
    )
    return build_intermediate_certificate(
        csr=csr, root_private_key=root_key, root_cert=root_cert,
        validity_days=1825, path_length=0,
    )


class TestExtractURLs:

    def test_ocsp_urls_empty(self, inter_cert):
        urls = extract_ocsp_urls(inter_cert)
        assert isinstance(urls, list)

    def test_crl_urls_empty(self, inter_cert):
        urls = extract_crl_urls(inter_cert)
        assert isinstance(urls, list)


class TestCheckCRL:

    def test_crl_no_source(self, inter_cert, root_cert):
        result = check_crl(inter_cert, root_cert, crl_source=None)
        assert result.status == RevocationStatus.UNKNOWN

    def test_crl_nonexistent_file(self, inter_cert, root_cert):
        result = check_crl(
            inter_cert, root_cert,
            crl_source="/nonexistent/path/to.crl"
        )
        assert result.status == RevocationStatus.UNKNOWN

    def test_crl_valid_cert_good(
        self, tmp_path, inter_key, inter_cert
    ):
        leaf_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        leaf = build_leaf_certificate(
            subject=parse_subject_dn("CN=crl-good.test"),
            leaf_public_key=leaf_key.public_key(),
            ca_private_key=inter_key,
            ca_cert=inter_cert,
            template=get_template("server"),
            san_entries=parse_san_entries(["dns:crl-good.test"]),
            validity_days=365, leaf_key_type="rsa",
        )
        crl = build_crl(
            ca_cert=inter_cert,
            ca_private_key=inter_key,
            revoked_certs=[],
            next_update_days=7,
            crl_number=1,
        )
        crl_path = tmp_path / "test.crl.pem"
        crl_path.write_bytes(serialize_crl_pem(crl))

        result = check_crl(leaf, inter_cert, crl_source=str(crl_path))
        assert result.status == RevocationStatus.GOOD

    def test_crl_revoked_cert(self, tmp_path, inter_key, inter_cert):
        from micropki.serial import serial_to_hex
        leaf_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        leaf = build_leaf_certificate(
            subject=parse_subject_dn("CN=crl-revoked.test"),
            leaf_public_key=leaf_key.public_key(),
            ca_private_key=inter_key,
            ca_cert=inter_cert,
            template=get_template("server"),
            san_entries=parse_san_entries(["dns:crl-revoked.test"]),
            validity_days=365, leaf_key_type="rsa",
        )
        s_hex = serial_to_hex(leaf.serial_number)
        revoked = [{
            "serial_hex": s_hex,
            "revocation_date": "2026-01-01T00:00:00Z",
            "revocation_reason": "keycompromise",
        }]
        crl = build_crl(
            ca_cert=inter_cert,
            ca_private_key=inter_key,
            revoked_certs=revoked,
            next_update_days=7,
            crl_number=2,
        )
        crl_path = tmp_path / "revoked.crl.pem"
        crl_path.write_bytes(serialize_crl_pem(crl))

        result = check_crl(leaf, inter_cert, crl_source=str(crl_path))
        assert result.status == RevocationStatus.REVOKED
        assert result.reason is not None

    def test_verify_crl_signature_valid(self, inter_key, inter_cert):
        crl = build_crl(
            ca_cert=inter_cert,
            ca_private_key=inter_key,
            revoked_certs=[],
            next_update_days=7,
            crl_number=1,
        )
        assert _verify_crl_signature(crl, inter_cert)

    def test_verify_crl_signature_wrong_key(self, inter_key, inter_cert, root_cert):
        crl = build_crl(
            ca_cert=inter_cert,
            ca_private_key=inter_key,
            revoked_certs=[],
            next_update_days=7,
            crl_number=1,
        )
        assert not _verify_crl_signature(crl, root_cert)

    def test_load_crl_from_file(self, tmp_path, inter_key, inter_cert):
        crl = build_crl(
            ca_cert=inter_cert,
            ca_private_key=inter_key,
            revoked_certs=[], next_update_days=7, crl_number=1,
        )
        path = tmp_path / "load.crl.pem"
        path.write_bytes(serialize_crl_pem(crl))
        loaded = _load_crl(str(path))
        assert loaded is not None


class TestCheckOCSP:

    def test_ocsp_no_url(self, inter_cert, root_cert):
        result = check_ocsp(inter_cert, root_cert, ocsp_url=None)
        assert result.status == RevocationStatus.UNKNOWN

    def test_ocsp_unreachable_url(self, inter_cert, root_cert):
        result = check_ocsp(
            inter_cert, root_cert,
            ocsp_url="http://127.0.0.1:59999/ocsp"
        )
        assert result.status == RevocationStatus.UNKNOWN


class TestCheckRevocation:

    def test_no_sources_returns_unknown(self, inter_cert, root_cert):
        result = check_revocation(
            inter_cert, root_cert,
            ocsp_url=None, crl_source=None,
            prefer_ocsp=False,
        )
        assert result.status == RevocationStatus.UNKNOWN

    def test_fallback_ocsp_to_crl(
        self, tmp_path, inter_key, inter_cert
    ):
        leaf_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        leaf = build_leaf_certificate(
            subject=parse_subject_dn("CN=fallback.test"),
            leaf_public_key=leaf_key.public_key(),
            ca_private_key=inter_key,
            ca_cert=inter_cert,
            template=get_template("server"),
            san_entries=parse_san_entries(["dns:fallback.test"]),
            validity_days=365, leaf_key_type="rsa",
        )
        crl = build_crl(
            ca_cert=inter_cert,
            ca_private_key=inter_key,
            revoked_certs=[], next_update_days=7, crl_number=1,
        )
        crl_path = tmp_path / "fb.crl.pem"
        crl_path.write_bytes(serialize_crl_pem(crl))

        result = check_revocation(
            leaf, inter_cert,
            ocsp_url="http://127.0.0.1:59999/ocsp",
            crl_source=str(crl_path),
            prefer_ocsp=True,
        )
        assert result.status == RevocationStatus.GOOD
        assert result.fallback_used