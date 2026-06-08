"""
Покрывает модули:
- revocation.py
- repository.py
- compromise.py
- crl.py
- chain.py
- crypto_utils.py
- config.py
- logger.py
- serial.py
- validation.py (дополнительно)
- certificates.py (дополнительно)
"""

import datetime
import os
import tempfile
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID, ExtensionOID

from micropki.database import init_database, get_connection, check_schema
from micropki.repository import (
    insert_certificate,
    get_certificate_by_serial,
    list_certificates,
    update_certificate_status,
    get_revoked_certificates,
)
from micropki.revocation import (
    validate_reason,
    get_reason_flag,
    get_supported_reasons,
    revoke_certificate,
)
from micropki.serial import (
    generate_serial,
    serial_to_hex,
    hex_to_serial,
    is_valid_hex,
    generate_unique_serial,
)
from micropki.certificates import (
    parse_subject_dn,
    parse_san_entries,
    build_san_extension,
    build_root_ca_certificate,
    build_intermediate_certificate,
    build_leaf_certificate,
    serialize_certificate_pem,
    build_ocsp_cert,
)
from micropki.csr import build_intermediate_csr, serialize_csr_pem, verify_csr_signature
from micropki.templates import (
    get_template,
    build_key_usage,
    validate_san_types,
    TEMPLATES,
)
from micropki.crypto_utils import (
    generate_private_key,
    serialize_private_key_pem,
    serialize_private_key_pem_unencrypted,
    save_key_file,
    read_passphrase,
    load_encrypted_private_key,
    load_certificate,
    get_cn_from_subject,
    sanitize_filename,
)
from micropki.config import load_config, Config
from micropki.logger import setup_logger
from micropki.chain import verify_signature, verify_validity, verify_basic_constraints
from micropki.compromise import (
    ensure_compromised_keys_table,
    record_compromised_key,
    is_key_compromised,
    check_csr_key_not_compromised,
    get_compromised_keys_list,
)
from micropki.policy import (
    get_public_key_hash,
    validate_key_size_for_cert_type,
    validate_csr_signature_algorithm,
    validate_csr_issuance,
    validate_san_in_csr,
)
from micropki.validation import (
    validate_chain,
    build_chain,
    check_signature,
    check_validity,
    check_basic_constraints as val_check_bc,
    check_path_len,
    check_key_usage_ca,
    check_key_usage_leaf,
    CertCheckResult,
    ValidationResult,
    _subject_str,
    _issuer_str,
    _cert_is_self_signed,
    _is_ca_cert,
    _get_path_len_constraint,
)
from micropki.audit import (
    AuditLogger,
    verify_audit_log,
    load_audit_log,
    query_audit_log,
    ZERO_HASH,
    compute_entry_hash,
    _canonical_json,
    _sha256,
    cert_fingerprint_sha256,
    init_audit_logger,
    get_audit_logger,
)
from micropki.ratelimit import (
    TokenBucket,
    RateLimiter,
    init_rate_limiter,
    get_rate_limiter,
)
from micropki.transparency import (
    get_cert_fingerprint,
    verify_ct_inclusion,
    query_ct_log,
)


# ---------------------------------------------------------------------------
# Фикстуры
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_db(tmp_path):
    db_path = tmp_path / "test.db"
    init_database(db_path)
    return db_path


@pytest.fixture(scope="module")
def root_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def root_cert(root_key):
    subj = parse_subject_dn("CN=Coverage Root CA,O=Test")
    return build_root_ca_certificate(
        private_key=root_key, subject=subj,
        validity_days=3650, key_type="rsa",
    )


@pytest.fixture(scope="module")
def inter_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def inter_cert(inter_key, root_key, root_cert):
    subj = parse_subject_dn("CN=Coverage Intermediate CA,O=Test")
    csr = build_intermediate_csr(inter_key, subj, 0, "rsa")
    return build_intermediate_certificate(
        csr=csr, root_private_key=root_key, root_cert=root_cert,
        validity_days=1825, path_length=0,
    )


def _make_leaf(inter_key, inter_cert, cn="test.cov.com", tmpl="server"):
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = parse_subject_dn(f"CN={cn}")
    san = parse_san_entries([f"dns:{cn}"])
    template = get_template(tmpl)
    cert = build_leaf_certificate(
        subject=subj,
        leaf_public_key=leaf_key.public_key(),
        ca_private_key=inter_key,
        ca_cert=inter_cert,
        template=template,
        san_entries=san,
        validity_days=365,
        leaf_key_type="rsa",
    )
    return cert, leaf_key


def _insert_test_cert(db_path, cert, issuer_str="CN=Issuer"):
    cert_pem = serialize_certificate_pem(cert).decode("utf-8")
    s_hex = serial_to_hex(cert.serial_number)
    subj = _subject_str(cert)
    insert_certificate(
        db_path=db_path, serial_hex=s_hex, subject=subj,
        issuer=issuer_str,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        cert_pem=cert_pem,
    )
    return s_hex


# ---------------------------------------------------------------------------
# repository.py
# ---------------------------------------------------------------------------

class TestRepository:

    def test_insert_and_get(self, tmp_db, inter_key, inter_cert):
        cert, _ = _make_leaf(inter_key, inter_cert, "repo1.test")
        s = _insert_test_cert(tmp_db, cert)
        data = get_certificate_by_serial(tmp_db, s)
        assert data is not None
        assert data["serial_hex"] == s

    def test_get_nonexistent_returns_none(self, tmp_db):
        assert get_certificate_by_serial(tmp_db, "DEADBEEF00000000") is None

    def test_list_all(self, tmp_db, inter_key, inter_cert):
        cert, _ = _make_leaf(inter_key, inter_cert, "list1.test")
        _insert_test_cert(tmp_db, cert)
        certs = list_certificates(tmp_db)
        assert len(certs) >= 1

    def test_list_filter_status(self, tmp_db, inter_key, inter_cert):
        cert, _ = _make_leaf(inter_key, inter_cert, "listf.test")
        _insert_test_cert(tmp_db, cert)
        valid = list_certificates(tmp_db, status="valid")
        for c in valid:
            assert c["status"] == "valid"

    def test_update_status(self, tmp_db, inter_key, inter_cert):
        cert, _ = _make_leaf(inter_key, inter_cert, "upd.test")
        s = _insert_test_cert(tmp_db, cert)
        ok = update_certificate_status(tmp_db, s, "revoked", "keyCompromise")
        assert ok
        data = get_certificate_by_serial(tmp_db, s)
        assert data["status"] == "revoked"

    def test_update_nonexistent(self, tmp_db):
        ok = update_certificate_status(tmp_db, "FFFF0000FFFF0000", "revoked")
        assert not ok

    def test_get_revoked(self, tmp_db):
        revoked = get_revoked_certificates(tmp_db)
        assert isinstance(revoked, list)

    def test_duplicate_serial_raises(self, tmp_db, inter_key, inter_cert):
        import sqlite3
        cert, _ = _make_leaf(inter_key, inter_cert, "dup.test")
        _insert_test_cert(tmp_db, cert)
        with pytest.raises(sqlite3.IntegrityError):
            _insert_test_cert(tmp_db, cert)


# ---------------------------------------------------------------------------
# revocation.py
# ---------------------------------------------------------------------------

class TestRevocation:

    def test_validate_reason_valid(self):
        assert validate_reason("keyCompromise") == "keycompromise"
        assert validate_reason("unspecified") == "unspecified"
        assert validate_reason("superseded") == "superseded"

    def test_validate_reason_invalid(self):
        with pytest.raises(ValueError, match="Неподдерживаемая"):
            validate_reason("nonexistent_reason")

    def test_get_reason_flag(self):
        flag = get_reason_flag("keycompromise")
        assert flag is not None

    def test_get_reason_flag_unknown(self):
        flag = get_reason_flag("unknown_reason")
        assert flag is None

    def test_get_supported_reasons(self):
        reasons = get_supported_reasons()
        assert "unspecified" in reasons
        assert "keycompromise" in reasons

    def test_revoke_not_found(self, tmp_db):
        result = revoke_certificate(tmp_db, "DEADBEEF00000001")
        assert result["status"] == "not_found"

    def test_revoke_success(self, tmp_db, inter_key, inter_cert):
        cert, _ = _make_leaf(inter_key, inter_cert, "rev.test")
        s = _insert_test_cert(tmp_db, cert)
        result = revoke_certificate(tmp_db, s, "keycompromise")
        assert result["status"] == "revoked"

    def test_revoke_already_revoked(self, tmp_db, inter_key, inter_cert):
        cert, _ = _make_leaf(inter_key, inter_cert, "rev2.test")
        s = _insert_test_cert(tmp_db, cert)
        revoke_certificate(tmp_db, s, "keycompromise")
        result = revoke_certificate(tmp_db, s, "superseded")
        assert result["status"] == "already_revoked"

    def test_revoke_invalid_serial(self, tmp_db):
        with pytest.raises(ValueError):
            revoke_certificate(tmp_db, "ZZZZ")

    def test_revoke_invalid_reason(self, tmp_db):
        with pytest.raises(ValueError):
            revoke_certificate(tmp_db, "DEADBEEF00000002", "bad_reason")


# ---------------------------------------------------------------------------
# chain.py (старый модуль)
# ---------------------------------------------------------------------------

class TestChainModule:

    def test_verify_signature_valid(self, root_cert):
        verify_signature(root_cert, root_cert)

    def test_verify_signature_invalid(self, root_cert, inter_cert):
        with pytest.raises(ValueError, match="НЕ соответствует"):
            verify_signature(root_cert, inter_cert)

    def test_verify_validity_valid(self, root_cert):
        assert verify_validity(root_cert) is True

    def test_verify_basic_constraints_ca_true(self, root_cert):
        assert verify_basic_constraints(root_cert, expect_ca=True) is True

    def test_verify_basic_constraints_ca_false_on_ca(self, root_cert):
        with pytest.raises(ValueError, match="CA="):
            verify_basic_constraints(root_cert, expect_ca=False)


# ---------------------------------------------------------------------------
# crypto_utils.py
# ---------------------------------------------------------------------------

class TestCryptoUtils:

    def test_generate_rsa_key(self):
        key = generate_private_key("rsa", 2048)
        assert isinstance(key, rsa.RSAPrivateKey)

    def test_generate_ecc_key_256(self):
        key = generate_private_key("ecc", 256)
        assert isinstance(key, ec.EllipticCurvePrivateKey)

    def test_generate_ecc_key_384(self):
        key = generate_private_key("ecc", 384)
        assert isinstance(key, ec.EllipticCurvePrivateKey)

    def test_generate_invalid_type(self):
        with pytest.raises(ValueError):
            generate_private_key("dsa", 2048)

    def test_generate_invalid_ecc_size(self):
        with pytest.raises(ValueError):
            generate_private_key("ecc", 128)

    def test_serialize_encrypted(self):
        key = generate_private_key("rsa", 2048)
        pem = serialize_private_key_pem(key, b"testpass")
        assert b"ENCRYPTED" in pem

    def test_serialize_unencrypted(self):
        key = generate_private_key("rsa", 2048)
        pem = serialize_private_key_pem_unencrypted(key)
        assert b"ENCRYPTED" not in pem
        assert b"BEGIN PRIVATE KEY" in pem

    def test_save_key_file(self, tmp_path):
        key = generate_private_key("rsa", 2048)
        pem = serialize_private_key_pem_unencrypted(key)
        path = tmp_path / "test.key.pem"
        save_key_file(pem, path)
        assert path.exists()
        assert path.read_bytes() == pem

    def test_read_passphrase(self, tmp_path):
        p = tmp_path / "pass.txt"
        p.write_bytes(b"mypassword\n")
        result = read_passphrase(p)
        assert result == b"mypassword"

    def test_load_encrypted_key(self, tmp_path):
        key = generate_private_key("rsa", 2048)
        pem = serialize_private_key_pem(key, b"pass123")
        path = tmp_path / "enc.key.pem"
        path.write_bytes(pem)
        loaded = load_encrypted_private_key(path, b"pass123")
        assert isinstance(loaded, rsa.RSAPrivateKey)

    def test_load_certificate(self, tmp_path, root_cert):
        path = tmp_path / "cert.pem"
        path.write_bytes(serialize_certificate_pem(root_cert))
        loaded = load_certificate(path)
        assert loaded.serial_number == root_cert.serial_number

    def test_get_cn_from_subject(self):
        subj = parse_subject_dn("CN=hello.world,O=Test")
        assert get_cn_from_subject(subj) == "hello.world"

    def test_get_cn_missing(self):
        subj = parse_subject_dn("O=Test")
        assert get_cn_from_subject(subj) == "unknown"

    def test_sanitize_filename(self):
        assert sanitize_filename("hello world!@#") == "hello_world___"
        assert sanitize_filename("test.com") == "test.com"
        assert sanitize_filename("a-b_c.d") == "a-b_c.d"


# ---------------------------------------------------------------------------
# config.py
# ---------------------------------------------------------------------------

class TestConfig:

    def test_default_config(self):
        cfg = load_config(None)
        assert isinstance(cfg, Config)
        assert cfg.port == 8080

    def test_load_nonexistent(self, tmp_path):
        cfg = load_config(tmp_path / "nonexistent.yaml")
        assert cfg.port == 8080


# ---------------------------------------------------------------------------
# logger.py
# ---------------------------------------------------------------------------

class TestLogger:

    def test_setup_logger_stderr(self):
        lgr = setup_logger(None)
        assert lgr.name == "micropki"
        assert len(lgr.handlers) > 0

    def test_setup_logger_file(self, tmp_path):
        log_file = tmp_path / "test.log"
        lgr = setup_logger(log_file)
        lgr.info("test message")
        assert log_file.exists()


# ---------------------------------------------------------------------------
# serial.py дополнительно
# ---------------------------------------------------------------------------

class TestSerialExtra:

    def test_hex_to_serial(self):
        val = hex_to_serial("FF")
        assert val == 255

    def test_hex_to_serial_invalid(self):
        with pytest.raises(ValueError):
            hex_to_serial("ZZZZ")

    def test_generate_serial_positive(self):
        for _ in range(100):
            s = generate_serial()
            assert s > 0

    def test_generate_unique_serial(self, tmp_db):
        s = generate_unique_serial(tmp_db)
        assert s > 0


# ---------------------------------------------------------------------------
# certificates.py дополнительно
# ---------------------------------------------------------------------------

class TestCertificatesExtra:

    def test_parse_dn_slash_format(self):
        name = parse_subject_dn("/CN=Test/O=Org/C=US")
        cn = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert cn[0].value == "Test"

    def test_parse_dn_comma_format(self):
        name = parse_subject_dn("CN=Test,O=Org")
        cn = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert cn[0].value == "Test"

    def test_parse_dn_empty_raises(self):
        with pytest.raises(ValueError):
            parse_subject_dn("")

    def test_parse_dn_no_equals_raises(self):
        with pytest.raises(ValueError):
            parse_subject_dn("INVALID")

    def test_parse_dn_unknown_key_raises(self):
        with pytest.raises(ValueError, match="Неизвестный"):
            parse_subject_dn("XX=Value")

    def test_parse_dn_empty_value_raises(self):
        with pytest.raises(ValueError):
            parse_subject_dn("CN=")

    def test_san_entries_parse(self):
        entries = parse_san_entries(["dns:a.com", "ip:1.2.3.4", "email:x@x.com"])
        assert len(entries) == 3

    def test_san_entries_empty_value_raises(self):
        with pytest.raises(ValueError):
            parse_san_entries(["dns:"])

    def test_build_san_extension_none_for_empty(self):
        assert build_san_extension([]) is None

    def test_build_ocsp_cert(self, inter_key, inter_cert):
        ocsp_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subj = parse_subject_dn("CN=OCSP Test")
        cert = build_ocsp_cert(
            subject=subj,
            ocsp_public_key=ocsp_key.public_key(),
            ca_private_key=inter_key,
            ca_cert=inter_cert,
            san_entries=[],
            validity_days=365,
        )
        bc = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
        assert bc.ca is False

    def test_serialize_certificate_pem(self, root_cert):
        pem = serialize_certificate_pem(root_cert)
        assert b"BEGIN CERTIFICATE" in pem


# ---------------------------------------------------------------------------
# csr.py дополнительно
# ---------------------------------------------------------------------------

class TestCSRExtra:

    def test_build_intermediate_csr_rsa(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subj = parse_subject_dn("CN=Test Inter CSR")
        csr = build_intermediate_csr(key, subj, 0, "rsa")
        assert csr.subject == subj

    def test_build_intermediate_csr_ecc(self):
        key = ec.generate_private_key(ec.SECP384R1())
        subj = parse_subject_dn("CN=Test ECC CSR")
        csr = build_intermediate_csr(key, subj, 0, "ecc")
        verify_csr_signature(csr)

    def test_serialize_csr_pem(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subj = parse_subject_dn("CN=Ser CSR")
        csr = build_intermediate_csr(key, subj, 0, "rsa")
        pem = serialize_csr_pem(csr)
        assert b"BEGIN CERTIFICATE REQUEST" in pem

    def test_invalid_key_type_raises(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subj = parse_subject_dn("CN=Bad")
        with pytest.raises(ValueError):
            build_intermediate_csr(key, subj, 0, "dsa")

    def test_verify_csr_ecc(self):
        key = ec.generate_private_key(ec.SECP256R1())
        subj = parse_subject_dn("CN=ECC Verify")
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subj)
            .sign(key, hashes.SHA256())
        )
        verify_csr_signature(csr)


# ---------------------------------------------------------------------------
# compromise.py дополнительно
# ---------------------------------------------------------------------------

class TestCompromiseExtra:

    def test_ensure_table_idempotent(self, tmp_db):
        ensure_compromised_keys_table(tmp_db)
        ensure_compromised_keys_table(tmp_db)  # второй раз — OK

    def test_not_compromised(self, tmp_db):
        ensure_compromised_keys_table(tmp_db)
        assert not is_key_compromised(tmp_db, "ffff" * 16)

    def test_check_csr_clean_key(self, tmp_db):
        ensure_compromised_keys_table(tmp_db)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(parse_subject_dn("CN=clean"))
            .sign(key, hashes.SHA256())
        )
        errors = check_csr_key_not_compromised(tmp_db, csr)
        assert not errors


# ---------------------------------------------------------------------------
# validation.py дополнительно
# ---------------------------------------------------------------------------

class TestValidationExtra:

    def test_subject_str(self, root_cert):
        s = _subject_str(root_cert)
        assert "Coverage Root CA" in s

    def test_issuer_str(self, root_cert):
        s = _issuer_str(root_cert)
        assert "Coverage Root CA" in s

    def test_self_signed(self, root_cert):
        assert _cert_is_self_signed(root_cert)

    def test_not_self_signed(self, inter_cert):
        assert not _cert_is_self_signed(inter_cert)

    def test_is_ca_cert_true(self, root_cert):
        assert _is_ca_cert(root_cert)

    def test_is_ca_cert_false(self, inter_key, inter_cert):
        leaf, _ = _make_leaf(inter_key, inter_cert, "notca.test")
        assert not _is_ca_cert(leaf)

    def test_get_path_len_root(self, root_cert):
        pl = _get_path_len_constraint(root_cert)
        assert pl is None  # root не имеет pathLen

    def test_get_path_len_inter(self, inter_cert):
        pl = _get_path_len_constraint(inter_cert)
        assert pl == 0

    def test_check_signature_result(self, root_cert):
        cr = CertCheckResult(subject="test")
        ok = check_signature(root_cert, root_cert, cr)
        assert ok
        assert len(cr.passed) > 0

    def test_check_validity_result(self, root_cert):
        cr = CertCheckResult(subject="test")
        ok = check_validity(root_cert, cr)
        assert ok

    def test_check_validity_future_fails(self, inter_key, inter_cert):
        leaf, _ = _make_leaf(inter_key, inter_cert, "fut.test")
        cr = CertCheckResult(subject="test")
        future = datetime.datetime.now(datetime.timezone.utc) + \
                 datetime.timedelta(days=400)
        ok = check_validity(leaf, cr, validation_time=future)
        assert not ok
        assert len(cr.failed) > 0

    def test_check_bc_ca_true(self, root_cert):
        cr = CertCheckResult(subject="test")
        ok = val_check_bc(root_cert, True, cr)
        assert ok

    def test_check_bc_ca_false_mismatch(self, root_cert):
        cr = CertCheckResult(subject="test")
        ok = val_check_bc(root_cert, False, cr)
        assert not ok

    def test_check_path_len_ok(self, inter_cert):
        cr = CertCheckResult(subject="test")
        ok = check_path_len(inter_cert, 0, cr)
        assert ok

    def test_check_path_len_violation(self, inter_cert):
        cr = CertCheckResult(subject="test")
        ok = check_path_len(inter_cert, 1, cr)
        assert not ok

    def test_check_key_usage_ca(self, root_cert):
        cr = CertCheckResult(subject="test")
        ok = check_key_usage_ca(root_cert, cr)
        assert ok

    def test_check_key_usage_leaf(self, inter_key, inter_cert):
        leaf, _ = _make_leaf(inter_key, inter_cert, "ku.test")
        cr = CertCheckResult(subject="test")
        ok = check_key_usage_leaf(leaf, cr)
        assert ok

    def test_validation_result_summary(self):
        vr = ValidationResult(success=True, chain=["A", "B"])
        s = vr.summary()
        assert "УСПЕХ" in s

    def test_validation_result_failure(self):
        vr = ValidationResult(success=False, error="test error")
        s = vr.summary()
        assert "ОШИБКА" in s


# ---------------------------------------------------------------------------
# policy.py дополнительно
# ---------------------------------------------------------------------------

class TestPolicyExtra:

    def test_validate_key_size_rsa_pub(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        errors = validate_key_size_for_cert_type(key.public_key(), "leaf")
        assert not errors

    def test_validate_key_size_ecc_pub(self):
        key = ec.generate_private_key(ec.SECP256R1())
        errors = validate_key_size_for_cert_type(key.public_key(), "leaf")
        assert not errors

    def test_validate_key_size_ecc_pub_root_fail(self):
        key = ec.generate_private_key(ec.SECP256R1())
        errors = validate_key_size_for_cert_type(key.public_key(), "root_ca")
        assert errors

    def test_validate_csr_sig_algo_sha256_ok(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(parse_subject_dn("CN=test"))
            .sign(key, hashes.SHA256())
        )
        errors = validate_csr_signature_algorithm(csr)
        assert not errors

    def test_validate_san_in_csr_empty(self, inter_key, inter_cert):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(parse_subject_dn("CN=nosan"))
            .sign(key, hashes.SHA256())
        )
        errors = validate_san_in_csr(csr, "server")
        assert not errors  # пустой SAN — не ошибка политики SAN


# ---------------------------------------------------------------------------
# audit.py дополнительно
# ---------------------------------------------------------------------------

class TestAuditExtra:

    def test_canonical_json_sorted(self):
        j = _canonical_json({"b": 1, "a": 2})
        assert j.index('"a"') < j.index('"b"')

    def test_sha256(self):
        h = _sha256("hello")
        assert len(h) == 64

    def test_compute_entry_hash_deterministic(self):
        entry = {"a": 1, "integrity": {"prev_hash": ZERO_HASH}}
        h1 = compute_entry_hash(entry)
        h2 = compute_entry_hash(entry)
        assert h1 == h2

    def test_audit_logger_log_issue(self, tmp_path):
        al = AuditLogger(audit_dir=tmp_path / "al1")
        al.log_issue("DEAD0001", "CN=test", "server")
        entries = load_audit_log(tmp_path / "al1" / "audit.log")
        ops = [e["operation"] for e in entries]
        assert "issue_certificate" in ops

    def test_audit_logger_log_revoke(self, tmp_path):
        al = AuditLogger(audit_dir=tmp_path / "al2")
        al.log_revoke("DEAD0002", "CN=rev", "keyCompromise")
        entries = load_audit_log(tmp_path / "al2" / "audit.log")
        ops = [e["operation"] for e in entries]
        assert "revoke_certificate" in ops

    def test_audit_logger_log_ca_init(self, tmp_path):
        al = AuditLogger(audit_dir=tmp_path / "al3")
        al.log_ca_init("root", "CN=Root")
        entries = load_audit_log(tmp_path / "al3" / "audit.log")
        ops = [e["operation"] for e in entries]
        assert "ca_init" in ops

    def test_audit_logger_log_crl(self, tmp_path):
        al = AuditLogger(audit_dir=tmp_path / "al4")
        al.log_crl_generation("intermediate", 1, 5)
        entries = load_audit_log(tmp_path / "al4" / "audit.log")
        ops = [e["operation"] for e in entries]
        assert "generate_crl" in ops

    def test_audit_logger_policy_violation(self, tmp_path):
        al = AuditLogger(audit_dir=tmp_path / "al5")
        al.log_policy_violation("issue", "RSA too small")
        entries = load_audit_log(tmp_path / "al5" / "audit.log")
        ops = [e["operation"] for e in entries]
        assert "policy_violation" in ops

    def test_audit_logger_compromise(self, tmp_path):
        al = AuditLogger(audit_dir=tmp_path / "al6")
        al.log_compromise("DEAD0003", "CN=comp", "abc123")
        entries = load_audit_log(tmp_path / "al6" / "audit.log")
        ops = [e["operation"] for e in entries]
        assert "key_compromise" in ops

    def test_audit_logger_ocsp_server(self, tmp_path):
        al = AuditLogger(audit_dir=tmp_path / "al7")
        al.log_ocsp_server("start", "127.0.0.1", 8081)

    def test_cert_fingerprint(self, root_cert):
        pem = serialize_certificate_pem(root_cert)
        fp = cert_fingerprint_sha256(pem)
        assert len(fp) == 64

    def test_init_and_get_global(self, tmp_path):
        al = init_audit_logger(tmp_path / "global_test")
        assert get_audit_logger() is al

    def test_verify_empty_log(self, tmp_path):
        log = tmp_path / "empty.log"
        log.touch()
        ok, errors = verify_audit_log(log)
        assert ok

    def test_query_with_serial_filter(self, tmp_path):
        al = AuditLogger(audit_dir=tmp_path / "q1")
        al.log(
            operation="issue_certificate",
            status="success",
            message="test",
            metadata={"serial": "AABB0001"},
        )
        results = query_audit_log(
            tmp_path / "q1" / "audit.log",
            serial="AABB0001",
        )
        assert len(results) >= 1


# ---------------------------------------------------------------------------
# ratelimit.py дополнительно
# ---------------------------------------------------------------------------

class TestRateLimitExtra:

    def test_init_rate_limiter_zero(self):
        rl = init_rate_limiter(0, 10)
        assert rl is None

    def test_init_rate_limiter_positive(self):
        rl = init_rate_limiter(5, 10)
        assert rl is not None
        assert rl.enabled

    def test_get_rate_limiter(self):
        init_rate_limiter(1, 5)
        rl = get_rate_limiter()
        assert rl is not None


# ---------------------------------------------------------------------------
# transparency.py дополнительно
# ---------------------------------------------------------------------------

class TestTransparencyExtra:

    def test_get_cert_fingerprint(self, root_cert):
        fp = get_cert_fingerprint(root_cert)
        assert len(fp) == 64

    def test_query_ct_log_by_subject(self, tmp_path):
        ct = tmp_path / "ct.log"
        ct.write_text(
            "2026-01-01T00:00:00Z\tAABB0001\tCN=hello\tabcdef\tCN=Issuer\n"
        )
        results = query_ct_log(ct, subject="hello")
        assert len(results) == 1

    def test_query_ct_nonexistent(self, tmp_path):
        results = query_ct_log(tmp_path / "nope.log")
        assert results == []

    def test_verify_ct_nonexistent(self, tmp_path):
        assert not verify_ct_inclusion(tmp_path / "nope.log", "DEAD")


# ---------------------------------------------------------------------------
# database.py дополнительно
# ---------------------------------------------------------------------------

class TestDatabaseExtra:

    def test_init_idempotent(self, tmp_path):
        db = tmp_path / "idem.db"
        init_database(db)
        init_database(db)  # второй раз — OK

    def test_check_schema_nonexistent(self, tmp_path):
        assert not check_schema(tmp_path / "nonexistent.db")

    def test_check_schema_valid(self, tmp_db):
        assert check_schema(tmp_db)

    def test_get_connection_wal(self, tmp_db):
        conn = get_connection(tmp_db)
        cursor = conn.execute("PRAGMA journal_mode")
        mode = cursor.fetchone()[0]
        assert mode == "wal"
        conn.close()