"""
Тесты для модуля crl.py — генерация CRL.
"""

import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from micropki.certificates import (
    build_root_ca_certificate,
    build_intermediate_certificate,
    build_leaf_certificate,
    parse_subject_dn,
    parse_san_entries,
    serialize_certificate_pem,
)
from micropki.crl import (
    build_crl,
    serialize_crl_pem,
    generate_crl,
    get_crl_number,
    update_crl_metadata,
    _detect_key_type,
    _get_signing_hash,
    _dn_to_string,
)
from micropki.csr import build_intermediate_csr
from micropki.database import init_database
from micropki.repository import insert_certificate
from micropki.revocation import revoke_certificate
from micropki.serial import serial_to_hex
from micropki.templates import get_template


@pytest.fixture
def tmp_db(tmp_path):
    db = tmp_path / "crl_test.db"
    init_database(db)
    return db


@pytest.fixture(scope="module")
def root_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def root_cert(root_key):
    return build_root_ca_certificate(
        private_key=root_key,
        subject=parse_subject_dn("CN=CRL Root CA,O=Test"),
        validity_days=3650, key_type="rsa",
    )


@pytest.fixture(scope="module")
def inter_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def inter_cert(inter_key, root_key, root_cert):
    csr = build_intermediate_csr(
        inter_key,
        parse_subject_dn("CN=CRL Intermediate CA,O=Test"),
        0, "rsa",
    )
    return build_intermediate_certificate(
        csr=csr, root_private_key=root_key, root_cert=root_cert,
        validity_days=1825, path_length=0,
    )


def _issue_and_insert(db_path, inter_key, inter_cert, cn):
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = parse_subject_dn(f"CN={cn}")
    san = parse_san_entries([f"dns:{cn}"])
    cert = build_leaf_certificate(
        subject=subj,
        leaf_public_key=leaf_key.public_key(),
        ca_private_key=inter_key,
        ca_cert=inter_cert,
        template=get_template("server"),
        san_entries=san,
        validity_days=365, leaf_key_type="rsa",
    )
    s_hex = serial_to_hex(cert.serial_number)
    issuer = ", ".join(
        f"{a.oid._name}={a.value}" for a in inter_cert.subject
    )
    insert_certificate(
        db_path=db_path, serial_hex=s_hex,
        subject=f"commonName={cn}",
        issuer=issuer,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        cert_pem=serialize_certificate_pem(cert).decode(),
    )
    return s_hex


class TestCRL:

    def test_detect_key_type_rsa(self, root_key):
        assert _detect_key_type(root_key) == "rsa"

    def test_get_signing_hash_rsa(self):
        h = _get_signing_hash("rsa")
        assert h.name == "sha256"

    def test_get_signing_hash_ecc(self):
        h = _get_signing_hash("ecc")
        assert h.name == "sha384"

    def test_get_signing_hash_invalid(self):
        with pytest.raises(ValueError):
            _get_signing_hash("dsa")

    def test_dn_to_string(self, root_cert):
        s = _dn_to_string(root_cert.subject)
        assert "CRL Root CA" in s

    def test_build_crl_empty(self, inter_cert, inter_key):
        crl = build_crl(
            ca_cert=inter_cert,
            ca_private_key=inter_key,
            revoked_certs=[],
            next_update_days=7,
            crl_number=1,
        )
        assert crl is not None
        pem = serialize_crl_pem(crl)
        assert b"BEGIN X509 CRL" in pem

    def test_build_crl_with_revoked(self, inter_cert, inter_key):
        revoked = [{
            "serial_hex": "DEADBEEF00000001",
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
        pem = serialize_crl_pem(crl)
        assert b"BEGIN X509 CRL" in pem

    def test_crl_number_starts_at_zero(self, tmp_db, inter_cert):
        issuer = _dn_to_string(inter_cert.subject)
        num = get_crl_number(tmp_db, issuer)
        assert num == 0

    def test_update_and_get_crl_metadata(self, tmp_db, inter_cert):
        issuer = _dn_to_string(inter_cert.subject)
        now = datetime.datetime.now(datetime.timezone.utc)
        update_crl_metadata(tmp_db, issuer, 1, now, "/tmp/test.crl")
        num = get_crl_number(tmp_db, issuer)
        assert num == 1

        update_crl_metadata(tmp_db, issuer, 2, now, "/tmp/test2.crl")
        num2 = get_crl_number(tmp_db, issuer)
        assert num2 == 2

    def test_generate_crl_full(self, tmp_db, tmp_path, inter_key, inter_cert):
        cn = "crlgen.test.local"
        s_hex = _issue_and_insert(tmp_db, inter_key, inter_cert, cn)
        revoke_certificate(tmp_db, s_hex, "keycompromise")

        crl_path = generate_crl(
            ca_name="intermediate",
            ca_cert=inter_cert,
            ca_private_key=inter_key,
            db_path=tmp_db,
            out_dir=tmp_path,
            next_update_days=7,
        )
        assert crl_path.exists()
        content = crl_path.read_bytes()
        assert b"BEGIN X509 CRL" in content

    def test_generate_crl_increments_number(
        self, tmp_db, tmp_path, inter_key, inter_cert
    ):
        generate_crl(
            ca_name="intermediate",
            ca_cert=inter_cert,
            ca_private_key=inter_key,
            db_path=tmp_db,
            out_dir=tmp_path,
        )
        issuer = _dn_to_string(inter_cert.subject)
        n1 = get_crl_number(tmp_db, issuer)

        generate_crl(
            ca_name="intermediate",
            ca_cert=inter_cert,
            ca_private_key=inter_key,
            db_path=tmp_db,
            out_dir=tmp_path,
        )
        n2 = get_crl_number(tmp_db, issuer)
        assert n2 == n1 + 1

    def test_generate_crl_custom_outfile(
        self, tmp_db, tmp_path, inter_key, inter_cert
    ):
        out_file = tmp_path / "custom.crl.pem"
        path = generate_crl(
            ca_name="intermediate",
            ca_cert=inter_cert,
            ca_private_key=inter_key,
            db_path=tmp_db,
            out_dir=tmp_path,
            out_file=out_file,
        )
        assert path == out_file
        assert out_file.exists()

    def test_build_crl_missing_revocation_date(self, inter_cert, inter_key):
        revoked = [{
            "serial_hex": "AAAA000000000001",
            "revocation_date": "",
            "revocation_reason": "unspecified",
        }]
        crl = build_crl(
            ca_cert=inter_cert,
            ca_private_key=inter_key,
            revoked_certs=revoked,
            next_update_days=7,
            crl_number=99,
        )
        assert crl is not None