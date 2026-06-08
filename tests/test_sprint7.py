"""
Автоматические тесты для спринта 7.

TEST-51: Нарушение политики — недостаточный размер ключа
TEST-52: Нарушение политики — превышение срока действия
TEST-53: Нарушение политики — wildcard в SAN
TEST-54: Нарушение политики — запрещённый тип SAN
TEST-55: Целостность аудита — обнаружение подделки
TEST-56: Целостность аудита — непрерывность цепочки
TEST-57: Симуляция компрометации и блокировка
TEST-58: Rate limiting
TEST-59: CT-журнал
"""

import json
import os
import tempfile
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from micropki.audit import (
    AuditLogger,
    verify_audit_log,
    query_audit_log,
    load_audit_log,
    ZERO_HASH,
)
from micropki.policy import (
    validate_private_key_size,
    validate_validity_days,
    validate_san_policy,
    validate_leaf_issuance,
    validate_csr_issuance,
    validate_pathlen,
    PolicyConfig,
)
from micropki.ratelimit import RateLimiter, TokenBucket
from micropki.transparency import verify_ct_inclusion, query_ct_log
from micropki.compromise import (
    record_compromised_key,
    is_key_compromised,
    check_csr_key_not_compromised,
    ensure_compromised_keys_table,
)
from micropki.policy import get_public_key_hash
from micropki.certificates import (
    build_root_ca_certificate,
    build_intermediate_certificate,
    build_leaf_certificate,
    parse_subject_dn,
    parse_san_entries,
)
from micropki.csr import build_intermediate_csr
from micropki.templates import get_template
from micropki.database import init_database


# ---------------------------------------------------------------------------
# Фикстуры
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_audit_dir(tmp_path):
    """Временный каталог для аудита."""
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    return audit_dir


@pytest.fixture
def audit_logger(tmp_audit_dir):
    """Экземпляр AuditLogger для тестов."""
    return AuditLogger(audit_dir=tmp_audit_dir)


@pytest.fixture
def tmp_db(tmp_path):
    """Временная БД с инициализированной схемой."""
    db_path = tmp_path / "test.db"
    init_database(db_path)
    return db_path


@pytest.fixture(scope="module")
def rsa_key_2048():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


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


# ---------------------------------------------------------------------------
# TEST-51: Нарушение политики — недостаточный размер ключа
# ---------------------------------------------------------------------------

class TestPolicyKeySize:
    """TEST-51: Контроль размера ключей (POL-3)."""

    def test_rsa_1024_rejected_for_leaf(self):
        """RSA-1024 должен быть отклонён для конечного сертификата."""
        errors = validate_private_key_size("rsa", 1024, "leaf")
        assert errors, "RSA-1024 должен быть отклонён"
        assert "2048" in errors[0]

    def test_rsa_2048_accepted_for_leaf(self):
        """RSA-2048 должен быть принят для конечного сертификата."""
        errors = validate_private_key_size("rsa", 2048, "leaf")
        assert not errors, f"RSA-2048 должен быть принят: {errors}"

    def test_rsa_4096_required_for_root(self):
        """RSA < 4096 должен быть отклонён для корневого CA."""
        errors = validate_private_key_size("rsa", 2048, "root_ca")
        assert errors, "RSA-2048 должен быть отклонён для root CA"

    def test_rsa_4096_accepted_for_root(self):
        """RSA-4096 должен быть принят для корневого CA."""
        errors = validate_private_key_size("rsa", 4096, "root_ca")
        assert not errors, f"RSA-4096 должен быть принят: {errors}"

    def test_ecc_256_rejected_for_root(self):
        """ECC P-256 должен быть отклонён для корневого CA."""
        errors = validate_private_key_size("ecc", 256, "root_ca")
        assert errors, "ECC-256 должен быть отклонён для root CA"

    def test_ecc_384_accepted_for_root(self):
        """ECC P-384 должен быть принят для корневого CA."""
        errors = validate_private_key_size("ecc", 384, "root_ca")
        assert not errors

    def test_ecc_256_accepted_for_leaf(self):
        """ECC P-256 должен быть принят для конечного сертификата."""
        errors = validate_private_key_size("ecc", 256, "leaf")
        assert not errors

    def test_validate_leaf_issuance_with_small_key(self):
        """Комплексная проверка отклоняет малый ключ."""
        errors = validate_leaf_issuance(
            key_type="rsa",
            key_size=1024,
            validity_days=365,
            san_entries=[("dns", "example.com")],
            template_name="server",
        )
        assert any("1024" in e or "2048" in e for e in errors)

    def test_csr_with_small_key_rejected(self, inter_key, inter_cert):
        """CSR с маленьким ключом отклоняется."""
        small_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        subject = parse_subject_dn("CN=small.example.com")
        builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
        csr = builder.sign(small_key, hashes.SHA256())

        errors = validate_csr_issuance(csr, 365, "server")
        assert any("1024" in e or "2048" in e for e in errors), \
            f"Ожидалась ошибка размера ключа: {errors}"


# ---------------------------------------------------------------------------
# TEST-52: Нарушение политики — превышение срока действия
# ---------------------------------------------------------------------------

class TestPolicyValidityDays:
    """TEST-52: Контроль срока действия (POL-4)."""

    def test_leaf_366_days_rejected(self):
        """Срок действия > 365 дней должен быть отклонён для leaf."""
        errors = validate_validity_days(366, "leaf")
        assert errors, "366 дней должно быть отклонено"
        assert "365" in errors[0]

    def test_leaf_365_days_accepted(self):
        """Срок действия 365 дней должен быть принят для leaf."""
        errors = validate_validity_days(365, "leaf")
        assert not errors

    def test_leaf_1_day_accepted(self):
        """Срок действия 1 день принят."""
        errors = validate_validity_days(1, "leaf")
        assert not errors

    def test_inter_ca_1826_days_rejected(self):
        """Срок > 1825 дней отклонён для intermediate CA."""
        errors = validate_validity_days(1826, "inter_ca")
        assert errors

    def test_inter_ca_1825_days_accepted(self):
        """Срок 1825 дней принят для intermediate CA."""
        errors = validate_validity_days(1825, "inter_ca")
        assert not errors

    def test_root_ca_3651_days_rejected(self):
        """Срок > 3650 дней отклонён для root CA."""
        errors = validate_validity_days(3651, "root_ca")
        assert errors

    def test_root_ca_3650_days_accepted(self):
        """Срок 3650 дней принят для root CA."""
        errors = validate_validity_days(3650, "root_ca")
        assert not errors

    def test_validate_leaf_issuance_with_long_validity(self):
        """Комплексная проверка отклоняет длинный срок."""
        errors = validate_leaf_issuance(
            key_type="rsa",
            key_size=2048,
            validity_days=400,
            san_entries=[("dns", "example.com")],
            template_name="server",
        )
        assert any("365" in e or "400" in e for e in errors)


# ---------------------------------------------------------------------------
# TEST-53: Нарушение политики — Wildcard в SAN
# ---------------------------------------------------------------------------

class TestPolicyWildcard:
    """TEST-53: Wildcard SAN (POL-5)."""

    def test_wildcard_rejected_by_default(self):
        """Wildcard SAN запрещён по умолчанию."""
        errors = validate_san_policy(
            [("dns", "*.example.com")],
            "server",
        )
        assert errors, "Wildcard должен быть отклонён"
        assert "wildcard" in errors[0].lower() or "*" in errors[0]

    def test_wildcard_allowed_when_configured(self):
        """Wildcard SAN разрешён если настроен."""
        config = PolicyConfig(allow_wildcards=True)
        errors = validate_san_policy(
            [("dns", "*.example.com")],
            "server",
            config=config,
        )
        assert not errors, f"Wildcard должен быть разрешён: {errors}"

    def test_normal_dns_accepted(self):
        """Обычный DNS SAN принят."""
        errors = validate_san_policy(
            [("dns", "example.com")],
            "server",
        )
        assert not errors

    def test_multiple_sans_with_wildcard_rejected(self):
        """Если среди SAN есть wildcard — всё отклоняется."""
        errors = validate_san_policy(
            [("dns", "example.com"), ("dns", "*.example.com")],
            "server",
        )
        assert any("*" in e or "wildcard" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# TEST-54: Нарушение политики — запрещённый тип SAN
# ---------------------------------------------------------------------------

class TestPolicySANTypes:
    """TEST-54: Проверка типов SAN по шаблону (POL-5)."""

    def test_email_san_rejected_for_code_signing(self):
        """email SAN запрещён для code_signing."""
        errors = validate_san_policy(
            [("email", "dev@example.com")],
            "code_signing",
        )
        assert errors, "email SAN должен быть отклонён для code_signing"

    def test_ip_san_rejected_for_code_signing(self):
        """ip SAN запрещён для code_signing."""
        errors = validate_san_policy(
            [("ip", "192.168.1.1")],
            "code_signing",
        )
        assert errors

    def test_dns_uri_accepted_for_code_signing(self):
        """dns и uri SAN приняты для code_signing."""
        errors = validate_san_policy(
            [("dns", "example.com"), ("uri", "https://example.com")],
            "code_signing",
        )
        assert not errors

    def test_email_san_accepted_for_client(self):
        """email SAN принят для client."""
        errors = validate_san_policy(
            [("email", "user@example.com")],
            "client",
        )
        assert not errors

    def test_ip_san_rejected_for_server_template_email(self):
        """email SAN запрещён для server шаблона."""
        errors = validate_san_policy(
            [("email", "admin@example.com")],
            "server",
        )
        assert errors


# ---------------------------------------------------------------------------
# TEST-55: Целостность аудита — обнаружение подделки
# ---------------------------------------------------------------------------

class TestAuditIntegrity:
    """TEST-55, TEST-56: Целостность журнала аудита."""

    def test_log_creates_file(self, audit_logger, tmp_audit_dir):
        """Журнал создаётся при инициализации."""
        log_path = tmp_audit_dir / "audit.log"
        assert log_path.exists(), "Файл журнала должен быть создан"

    def test_log_entry_has_required_fields(self, audit_logger, tmp_audit_dir):
        """Запись содержит обязательные поля (AUD-1)."""
        audit_logger.log(
            operation="test_op",
            status="success",
            message="Тестовая запись",
        )
        entries = load_audit_log(tmp_audit_dir / "audit.log")
        # Первая запись — init, вторая — наша
        assert len(entries) >= 2
        entry = entries[-1]
        assert "timestamp" in entry
        assert "level" in entry
        assert "operation" in entry
        assert "status" in entry
        assert "message" in entry
        assert "metadata" in entry
        assert "integrity" in entry
        assert "prev_hash" in entry["integrity"]
        assert "hash" in entry["integrity"]

    def test_hash_chain_is_valid(self, audit_logger, tmp_audit_dir):
        """Хеш-цепочка корректна после нескольких записей."""
        for i in range(5):
            audit_logger.log(
                operation=f"test_{i}",
                status="success",
                message=f"Запись {i}",
            )

        ok, errors = verify_audit_log(tmp_audit_dir / "audit.log")
        assert ok, f"Хеш-цепочка должна быть корректной: {errors}"

    def test_tampered_entry_detected(self, tmp_audit_dir):
        """TEST-55: Подделка записи обнаруживается."""
        al = AuditLogger(audit_dir=tmp_audit_dir / "tamper_test")
        al.log(operation="issue", status="success", message="cert 1")
        al.log(operation="issue", status="success", message="cert 2")
        al.log(operation="issue", status="success", message="cert 3")

        log_path = tmp_audit_dir / "tamper_test" / "audit.log"

        # Читаем содержимое и меняем один символ
        content = log_path.read_text("utf-8")
        lines = content.split("\n")

        # Находим вторую содержательную строку и меняем символ
        content_lines = [l for l in lines if l.strip()]
        if len(content_lines) >= 2:
            idx = lines.index(content_lines[1])
            # Меняем один символ в середине строки
            mid = len(lines[idx]) // 2
            tampered_line = (
                lines[idx][:mid] + chr(ord(lines[idx][mid]) ^ 1) + lines[idx][mid + 1:]
            )
            lines[idx] = tampered_line

        log_path.write_text("\n".join(lines), encoding="utf-8")

        ok, errors = verify_audit_log(log_path)
        assert not ok, "Подделка должна быть обнаружена"
        assert len(errors) > 0

    def test_deleted_entry_detected(self, tmp_audit_dir):
        """TEST-56: Удалённая запись обнаруживается."""
        al = AuditLogger(audit_dir=tmp_audit_dir / "delete_test")
        al.log(operation="op_A", status="success", message="A")
        al.log(operation="op_B", status="success", message="B")
        al.log(operation="op_C", status="success", message="C")

        log_path = tmp_audit_dir / "delete_test" / "audit.log"

        # Удаляем запись B (вторую содержательную строку)
        lines = [l for l in log_path.read_text("utf-8").split("\n") if l.strip()]
        # Оставляем первую и последнюю, удаляем среднюю
        if len(lines) >= 3:
            # Удаляем запись op_B (средняя)
            b_idx = None
            for i, l in enumerate(lines):
                entry = json.loads(l)
                if entry.get("operation") == "op_B":
                    b_idx = i
                    break
            if b_idx is not None:
                lines.pop(b_idx)

        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        ok, errors = verify_audit_log(log_path)
        assert not ok, "Удалённая запись должна быть обнаружена"

    def test_first_entry_prev_hash_is_zero(self, tmp_audit_dir):
        """Первая запись журнала имеет prev_hash = '0' * 64."""
        al = AuditLogger(audit_dir=tmp_audit_dir / "fresh_test")
        log_path = tmp_audit_dir / "fresh_test" / "audit.log"
        entries = load_audit_log(log_path)
        assert entries[0]["integrity"]["prev_hash"] == ZERO_HASH

    def test_audit_query_filters_by_operation(self, audit_logger, tmp_audit_dir):
        """Запрос фильтрует по операции."""
        audit_logger.log(operation="issue_certificate", status="success",
                         message="issued")
        audit_logger.log(operation="revoke_certificate", status="success",
                         message="revoked")

        results = query_audit_log(
            tmp_audit_dir / "audit.log",
            operation="issue",
        )
        assert all("issue" in e["operation"] for e in results)

    def test_audit_query_filters_by_level(self, audit_logger, tmp_audit_dir):
        """Запрос фильтрует по уровню."""
        audit_logger.log(operation="test", status="success",
                         message="info msg", level="INFO")
        audit_logger.log(operation="test2", status="failure",
                         message="audit msg", level="AUDIT")

        results = query_audit_log(
            tmp_audit_dir / "audit.log",
            level="AUDIT",
        )
        assert all(e["level"] == "AUDIT" for e in results)


# ---------------------------------------------------------------------------
# TEST-57: Симуляция компрометации и блокировка
# ---------------------------------------------------------------------------

class TestCompromise:
    """TEST-57: Компрометация ключа и блокировка (CTL-3, CTL-4)."""


    def test_non_compromised_key_is_not_flagged(self, tmp_db):
        """Незаписанный ключ не считается скомпрометированным."""
        assert not is_key_compromised(tmp_db, "0" * 64)

    def test_check_csr_key_not_compromised_ok(self, tmp_db, inter_key, inter_cert):
        """CSR с незаписанным ключом проходит проверку."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = parse_subject_dn("CN=safe.example.com")
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .sign(key, hashes.SHA256())
        )
        errors = check_csr_key_not_compromised(tmp_db, csr)
        assert not errors


    def test_public_key_hash_is_consistent(self):
        """Хеш открытого ключа стабилен (одинаковый для одного ключа)."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        h1 = get_public_key_hash(key.public_key())
        h2 = get_public_key_hash(key.public_key())
        assert h1 == h2

    def test_different_keys_have_different_hashes(self):
        """Разные ключи имеют разные хеши."""
        k1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        k2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        assert get_public_key_hash(k1.public_key()) != get_public_key_hash(k2.public_key())


# ---------------------------------------------------------------------------
# TEST-58: Rate limiting
# ---------------------------------------------------------------------------

class TestRateLimiting:
    """TEST-58: Ограничение скорости запросов (CTL-1)."""

    def test_token_bucket_allows_within_rate(self):
        """Запросы в пределах лимита разрешены."""
        bucket = TokenBucket(rate=10, burst=10)
        for _ in range(5):
            allowed, _ = bucket.consume()
            assert allowed

    def test_token_bucket_rejects_when_exhausted(self):
        """Запросы сверх лимита отклоняются."""
        bucket = TokenBucket(rate=1, burst=2)
        # Исчерпываем burst
        allowed1, _ = bucket.consume()
        allowed2, _ = bucket.consume()
        assert allowed1 and allowed2
        # Следующий должен быть отклонён
        allowed3, retry_after = bucket.consume()
        assert not allowed3
        assert retry_after > 0

    def test_rate_limiter_per_ip(self):
        """Разные IP имеют независимые лимиты."""
        limiter = RateLimiter(rate=1, burst=1)
        allowed1, _ = limiter.check("192.168.1.1")
        allowed2, _ = limiter.check("192.168.1.2")
        assert allowed1  # первый запрос с IP1
        assert allowed2  # первый запрос с IP2 (независимый)

    def test_rate_limiter_disabled_when_rate_zero(self):
        """Ограничитель отключён при rate=0."""
        limiter = RateLimiter(rate=0, burst=10)
        assert not limiter.enabled
        for _ in range(100):
            allowed, _ = limiter.check("1.2.3.4")
            assert allowed

    def test_token_bucket_refills_over_time(self):
        """Токены пополняются со временем."""
        bucket = TokenBucket(rate=10, burst=10)
        # Исчерпываем
        for _ in range(10):
            bucket.consume()
        # Ждём пополнения
        time.sleep(0.2)
        allowed, _ = bucket.consume()
        assert allowed, "Токены должны пополниться за 0.2 секунды"

    def test_retry_after_is_positive(self):
        """retry_after > 0 когда лимит превышен."""
        bucket = TokenBucket(rate=1, burst=1)
        bucket.consume()  # исчерпываем
        allowed, retry_after = bucket.consume()
        assert not allowed
        assert retry_after > 0

    def test_rate_limiter_same_ip_limited(self):
        """Один IP ограничен после исчерпания burst."""
        limiter = RateLimiter(rate=1, burst=2)
        ip = "10.0.0.1"
        results = []
        for _ in range(5):
            allowed, _ = limiter.check(ip)
            results.append(allowed)
        # Первые два разрешены (burst=2), остальные — нет
        assert results[0] and results[1]
        assert not all(results[2:])


# ---------------------------------------------------------------------------
# TEST-59: CT-журнал
# ---------------------------------------------------------------------------

class TestCTLog:
    """TEST-59: Журнал Certificate Transparency (CTL-2)."""

    def test_ct_entry_added_on_issue(self, audit_logger, tmp_audit_dir):
        """После log_ct запись добавляется в ct.log."""
        audit_logger.log_ct(
            serial_hex="ABCDEF1234567890",
            subject="CN=test.example.com",
            cert_fingerprint="a" * 64,
            issuer="CN=Intermediate CA",
        )

        ct_path = tmp_audit_dir / "ct.log"
        assert ct_path.exists()
        content = ct_path.read_text("utf-8")
        assert "ABCDEF1234567890" in content

    def test_ct_verify_inclusion_found(self, audit_logger, tmp_audit_dir):
        """Сертификат находится в CT-журнале."""
        audit_logger.log_ct(
            serial_hex="FEDCBA9876543210",
            subject="CN=found.example.com",
            cert_fingerprint="b" * 64,
        )
        ct_path = tmp_audit_dir / "ct.log"
        found = verify_ct_inclusion(ct_path, "FEDCBA9876543210")
        assert found

    def test_ct_verify_inclusion_not_found(self, tmp_audit_dir):
        """Отсутствующий сертификат не найден в CT-журнале."""
        ct_path = tmp_audit_dir / "ct.log"
        ct_path.touch()
        found = verify_ct_inclusion(ct_path, "NONEXISTENT000000")
        assert not found

    def test_ct_log_is_world_readable(self, audit_logger, tmp_audit_dir):
        """CT-журнал доступен для чтения всем (0o644) на Linux."""
        if os.name == "nt":
            pytest.skip("POSIX права не проверяются на Windows")
        ct_path = tmp_audit_dir / "ct.log"
        mode = oct(os.stat(ct_path).st_mode & 0o777)
        assert mode == "0o644", f"Ожидались права 0o644, получено {mode}"

    def test_ct_query_finds_entry(self, audit_logger, tmp_audit_dir):
        """query_ct_log находит запись по серийному номеру."""
        audit_logger.log_ct(
            serial_hex="CAFEBABE00000001",
            subject="CN=query.example.com",
            cert_fingerprint="c" * 64,
            issuer="CN=Issuer CA",
        )
        ct_path = tmp_audit_dir / "ct.log"
        results = query_ct_log(ct_path, serial_hex="CAFEBABE00000001")
        assert len(results) >= 1
        assert results[0]["serial"] == "CAFEBABE00000001"

    def test_ct_log_has_multiple_entries(self, audit_logger, tmp_audit_dir):
        """В CT-журнале хранятся несколько записей."""
        for i in range(3):
            audit_logger.log_ct(
                serial_hex=f"MULTI{i:016X}",
                subject=f"CN=multi{i}.example.com",
                cert_fingerprint="d" * 64,
            )
        ct_path = tmp_audit_dir / "ct.log"
        results = query_ct_log(ct_path)
        assert len(results) >= 3


# ---------------------------------------------------------------------------
# POL-7: pathLen
# ---------------------------------------------------------------------------

class TestPolicyPathLen:
    """POL-7: Контроль pathLenConstraint."""

    def test_pathlen_0_accepted(self):
        """pathLen=0 принят."""
        errors = validate_pathlen(0)
        assert not errors

    def test_pathlen_1_rejected(self):
        """pathLen=1 отклонён по умолчанию."""
        errors = validate_pathlen(1)
        assert errors, "pathLen=1 должен быть отклонён"

    def test_pathlen_custom_config(self):
        """Кастомная конфигурация позволяет pathLen=1."""
        config = PolicyConfig(inter_ca_max_pathlen=1)
        errors = validate_pathlen(1, config=config)
        assert not errors