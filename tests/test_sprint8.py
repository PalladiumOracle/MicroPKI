"""
Автоматические тесты для спринта 8.

TEST-62: Граничные случаи — просроченные сертификаты
TEST-63: Граничные случаи — неверное использование ключа (EKU)
TEST-64: Граничные случаи — некорректные входные данные
TEST-65: Тест производительности — 1000 сертификатов (метка perf)
"""

import datetime
import json
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID

from micropki.audit import AuditLogger, verify_audit_log, load_audit_log
from micropki.certificates import (
    build_root_ca_certificate,
    build_intermediate_certificate,
    build_leaf_certificate,
    parse_subject_dn,
    parse_san_entries,
)
from micropki.csr import build_intermediate_csr, verify_csr_signature
from micropki.database import init_database
from micropki.policy import validate_leaf_issuance, validate_validity_days
from micropki.repository import insert_certificate
from micropki.serial import generate_unique_serial, serial_to_hex
from micropki.templates import get_template
from micropki.validation import validate_chain


# ---------------------------------------------------------------------------
# Фикстуры (модульные — создаются один раз)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def root_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def root_cert(root_key):
    return build_root_ca_certificate(
        private_key=root_key,
        subject=parse_subject_dn("CN=Perf Root CA,O=Test"),
        validity_days=3650,
        key_type="rsa",
    )


@pytest.fixture(scope="module")
def inter_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def inter_cert(inter_key, root_key, root_cert):
    subject = parse_subject_dn("CN=Perf Intermediate CA,O=Test")
    csr = build_intermediate_csr(inter_key, subject, 0, "rsa")
    return build_intermediate_certificate(
        csr=csr,
        root_private_key=root_key,
        root_cert=root_cert,
        validity_days=1825,
        path_length=0,
    )


@pytest.fixture
def tmp_db(tmp_path):
    db_path = tmp_path / "test.db"
    init_database(db_path)
    return db_path


# ---------------------------------------------------------------------------
# TEST-62: Просроченные сертификаты
# ---------------------------------------------------------------------------

class TestExpiredCertificates:
    """TEST-62: Граничные случаи с просроченными сертификатами."""

    def test_expired_cert_fails_validation(self, inter_key, inter_cert, root_cert):
        """Просроченный сертификат не проходит проверку."""
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = parse_subject_dn("CN=expired.example.com")
        san = parse_san_entries(["dns:expired.example.com"])
        leaf_cert = build_leaf_certificate(
            subject=subject,
            leaf_public_key=leaf_key.public_key(),
            ca_private_key=inter_key,
            ca_cert=inter_cert,
            template=get_template("server"),
            san_entries=san,
            validity_days=1,
            leaf_key_type="rsa",
        )
        # Проверяем "через 400 дней" — сертификат просрочен
        future = datetime.datetime.now(datetime.timezone.utc) + \
                 datetime.timedelta(days=400)
        result = validate_chain(
            leaf=leaf_cert,
            untrusted=[inter_cert],
            trusted=[root_cert],
            validation_time=future,
        )
        assert not result.success
        # Убеждаемся что ошибка о сроке
        error_text = result.error or ""
        cert_errors = " ".join(f for cr in result.cert_results for f in cr.failed)
        combined = (error_text + cert_errors).lower()
        assert "просрочен" in combined or "notafter" in combined

    def test_not_yet_valid_cert_fails(self, inter_key, inter_cert, root_cert):
        """Сертификат ещё не вступивший в силу не проходит проверку."""
        from cryptography.x509.oid import ExtensionOID as EOI
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = parse_subject_dn("CN=future.example.com")

        # Создаём сертификат с notBefore в будущем вручную
        now = datetime.datetime.now(datetime.timezone.utc)
        future_start = now + datetime.timedelta(days=30)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(inter_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(future_start)
            .not_valid_after(future_start + datetime.timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_encipherment=True,
                    content_commitment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False,
                ), critical=True
            )
        )
        leaf_cert = builder.sign(inter_key, hashes.SHA256())

        # Проверяем с текущим временем — сертификат ещё не действует
        result = validate_chain(
            leaf=leaf_cert,
            untrusted=[inter_cert],
            trusted=[root_cert],
            validation_time=now,
        )
        assert not result.success
        cert_errors = " ".join(f for cr in result.cert_results for f in cr.failed)
        assert "вступил" in cert_errors.lower() or "notbefore" in cert_errors.lower()

    def test_valid_cert_passes_at_issuance_time(self, inter_key, inter_cert, root_cert):
        """Сертификат проходит проверку во время выпуска."""
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = parse_subject_dn("CN=current.example.com")
        san = parse_san_entries(["dns:current.example.com"])
        leaf_cert = build_leaf_certificate(
            subject=subject,
            leaf_public_key=leaf_key.public_key(),
            ca_private_key=inter_key,
            ca_cert=inter_cert,
            template=get_template("server"),
            san_entries=san,
            validity_days=365,
            leaf_key_type="rsa",
        )
        result = validate_chain(
            leaf=leaf_cert,
            untrusted=[inter_cert],
            trusted=[root_cert],
        )
        assert result.success

    def test_validation_time_parameter_works(self, inter_key, inter_cert, root_cert):
        """Параметр validation_time корректно применяется."""
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = parse_subject_dn("CN=timetest.example.com")
        san = parse_san_entries(["dns:timetest.example.com"])
        leaf_cert = build_leaf_certificate(
            subject=subject,
            leaf_public_key=leaf_key.public_key(),
            ca_private_key=inter_key,
            ca_cert=inter_cert,
            template=get_template("server"),
            san_entries=san,
            validity_days=365,
            leaf_key_type="rsa",
        )
        # Текущее время — должно пройти
        result_now = validate_chain(
            leaf=leaf_cert,
            untrusted=[inter_cert],
            trusted=[root_cert],
            validation_time=datetime.datetime.now(datetime.timezone.utc),
        )
        assert result_now.success

        # Будущее время — должно упасть
        result_future = validate_chain(
            leaf=leaf_cert,
            untrusted=[inter_cert],
            trusted=[root_cert],
            validation_time=datetime.datetime.now(datetime.timezone.utc) +
                            datetime.timedelta(days=400),
        )
        assert not result_future.success


# ---------------------------------------------------------------------------
# TEST-63: Неверное использование ключа (EKU)
# ---------------------------------------------------------------------------

class TestKeyUsageMismatch:
    """TEST-63: Граничные случаи — неверное использование ключа."""

    def test_client_cert_has_client_eku(self, inter_key, inter_cert):
        """Клиентский сертификат имеет EKU clientAuth."""
        from cryptography.x509.oid import ExtendedKeyUsageOID
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = parse_subject_dn("CN=client.example.com")
        san = parse_san_entries(["email:client@example.com"])
        leaf_cert = build_leaf_certificate(
            subject=subject,
            leaf_public_key=leaf_key.public_key(),
            ca_private_key=inter_key,
            ca_cert=inter_cert,
            template=get_template("client"),
            san_entries=san,
            validity_days=365,
            leaf_key_type="rsa",
        )
        eku = leaf_cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        ).value
        eku_oids = list(eku)
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku_oids
        assert ExtendedKeyUsageOID.SERVER_AUTH not in eku_oids

    def test_server_cert_has_server_eku(self, inter_key, inter_cert):
        """Серверный сертификат имеет EKU serverAuth."""
        from cryptography.x509.oid import ExtendedKeyUsageOID
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = parse_subject_dn("CN=server.example.com")
        san = parse_san_entries(["dns:server.example.com"])
        leaf_cert = build_leaf_certificate(
            subject=subject,
            leaf_public_key=leaf_key.public_key(),
            ca_private_key=inter_key,
            ca_cert=inter_cert,
            template=get_template("server"),
            san_entries=san,
            validity_days=365,
            leaf_key_type="rsa",
        )
        eku = leaf_cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        ).value
        assert ExtendedKeyUsageOID.SERVER_AUTH in list(eku)

    def test_code_signing_cert_has_correct_eku(self, inter_key, inter_cert):
        """Code signing сертификат имеет EKU codeSigning."""
        from cryptography.x509.oid import ExtendedKeyUsageOID
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = parse_subject_dn("CN=signer.example.com")
        leaf_cert = build_leaf_certificate(
            subject=subject,
            leaf_public_key=leaf_key.public_key(),
            ca_private_key=inter_key,
            ca_cert=inter_cert,
            template=get_template("code_signing"),
            san_entries=[],
            validity_days=365,
            leaf_key_type="rsa",
        )
        eku = leaf_cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        ).value
        assert ExtendedKeyUsageOID.CODE_SIGNING in list(eku)

    def test_client_cert_not_ca(self, inter_key, inter_cert):
        """Клиентский сертификат имеет CA=False."""
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = parse_subject_dn("CN=notca.example.com")
        leaf_cert = build_leaf_certificate(
            subject=subject,
            leaf_public_key=leaf_key.public_key(),
            ca_private_key=inter_key,
            ca_cert=inter_cert,
            template=get_template("client"),
            san_entries=[("email", "test@test.com")],
            validity_days=365,
            leaf_key_type="rsa",
        )
        bc = leaf_cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
        assert bc.ca is False


# ---------------------------------------------------------------------------
# TEST-64: Некорректные входные данные
# ---------------------------------------------------------------------------

class TestInvalidInputs:
    """TEST-64: Граничные случаи с некорректными данными."""

    def test_corrupted_pem_raises_error(self):
        """Повреждённый PEM вызывает исключение."""
        corrupted = b"-----BEGIN CERTIFICATE-----\nINVALID_BASE64_DATA!!!\n-----END CERTIFICATE-----\n"
        with pytest.raises(Exception):
            x509.load_pem_x509_certificate(corrupted)

    def test_empty_pem_raises_error(self):
        """Пустые данные вызывают исключение."""
        with pytest.raises(Exception):
            x509.load_pem_x509_certificate(b"")

    def test_csr_with_invalid_subject_raises(self):
        """Некорректный субъект вызывает ValueError."""
        from micropki.certificates import parse_subject_dn
        with pytest.raises(ValueError):
            parse_subject_dn("INVALID_DN_FORMAT")

    def test_csr_with_empty_subject_raises(self):
        """Пустой субъект вызывает ValueError."""
        from micropki.certificates import parse_subject_dn
        with pytest.raises(ValueError):
            parse_subject_dn("")

    def test_invalid_san_format_raises(self):
        """Некорректный формат SAN вызывает ValueError."""
        from micropki.certificates import parse_san_entries
        with pytest.raises(ValueError):
            parse_san_entries(["invalid_without_colon"])

    def test_unsupported_san_type_raises(self):
        """Неподдерживаемый тип SAN вызывает ValueError."""
        from micropki.certificates import parse_san_entries
        with pytest.raises(ValueError):
            parse_san_entries(["ftp:ftp.example.com"])

    def test_invalid_ip_in_san_raises(self):
        """Некорректный IP в SAN вызывает ValueError."""
        from micropki.certificates import parse_san_entries, build_san_extension
        entries = parse_san_entries(["ip:999.999.999.999"])
        with pytest.raises(ValueError):
            build_san_extension(entries)

    def test_corrupted_audit_log_detected(self, tmp_path):
        """Повреждённый журнал аудита обнаруживается."""
        audit_dir = tmp_path / "audit"
        al = AuditLogger(audit_dir=audit_dir)
        al.log(operation="test", status="success", message="msg1")
        al.log(operation="test", status="success", message="msg2")

        log_path = audit_dir / "audit.log"
        content = log_path.read_bytes()
        # Портим байт
        data = bytearray(content)
        data[len(data) // 2] ^= 0xFF
        log_path.write_bytes(bytes(data))

        ok, errors = verify_audit_log(log_path)
        assert not ok
        assert len(errors) > 0

    def test_nonexistent_template_raises(self):
        """Несуществующий шаблон вызывает ValueError."""
        from micropki.templates import get_template
        with pytest.raises(ValueError):
            get_template("nonexistent_template")

    def test_invalid_key_type_raises(self):
        """Некорректный тип ключа вызывает ValueError."""
        from micropki.crypto_utils import generate_private_key
        with pytest.raises((ValueError, Exception)):
            generate_private_key("dsa", 2048)

    def test_invalid_hex_serial_returns_false(self):
        """Некорректный hex серийного номера возвращает False."""
        from micropki.serial import is_valid_hex
        assert not is_valid_hex("ZZZZ")
        assert not is_valid_hex("")
        assert not is_valid_hex("XYZ123")

    def test_valid_hex_serial_returns_true(self):
        """Валидный hex серийного номера возвращает True."""
        from micropki.serial import is_valid_hex
        assert is_valid_hex("DEADBEEF")
        assert is_valid_hex("0")
        assert is_valid_hex("6A2042C281B469D7")

    def test_policy_rejects_invalid_san_type(self):
        """Политика отклоняет запрещённый тип SAN."""
        from micropki.policy import validate_san_policy
        errors = validate_san_policy([("email", "test@test.com")], "server")
        assert errors

    def test_parse_invalid_dn_key_raises(self):
        """Неизвестный ключ DN вызывает ValueError."""
        from micropki.certificates import parse_subject_dn
        with pytest.raises(ValueError, match="Неизвестный атрибут"):
            parse_subject_dn("XX=Something")


# ---------------------------------------------------------------------------
# TEST-65: Производительность — 1000 сертификатов
# ---------------------------------------------------------------------------

@pytest.mark.perf
class TestPerformance:
    """TEST-65: Тест производительности — 1000 сертификатов."""

    def test_issue_1000_certs(self, inter_key, inter_cert, tmp_db):
        """Выпуск и вставка 1000 сертификатов в БД."""
        template = get_template("server")
        count = 1000
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        start = time.perf_counter()

        for i in range(count):
            subject = parse_subject_dn(f"CN=perf{i}.example.com")
            san = parse_san_entries([f"dns:perf{i}.example.com"])
            serial_number = generate_unique_serial(tmp_db)

            cert = build_leaf_certificate(
                subject=subject,
                leaf_public_key=leaf_key.public_key(),
                ca_private_key=inter_key,
                ca_cert=inter_cert,
                template=template,
                san_entries=san,
                validity_days=365,
                leaf_key_type="rsa",
                serial_number=serial_number,
            )

            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            serial_hex = serial_to_hex(cert.serial_number)

            insert_certificate(
                db_path=tmp_db,
                serial_hex=serial_hex,
                subject=f"CN=perf{i}.example.com",
                issuer="CN=Perf Intermediate CA,O=Test",
                not_before=cert.not_valid_before_utc,
                not_after=cert.not_valid_after_utc,
                cert_pem=cert_pem.decode("utf-8"),
            )

        elapsed = time.perf_counter() - start
        rate = count / elapsed

        print(f"\n{'='*50}")
        print(f"Производительность выпуска сертификатов:")
        print(f"  Количество: {count}")
        print(f"  Время:      {elapsed:.2f} сек")
        print(f"  Скорость:   {rate:.1f} сертификатов/сек")
        print(f"{'='*50}")

        # Минимальная скорость: 10 сертификатов/сек
        assert rate > 10, \
            f"Скорость {rate:.1f} серт/сек ниже минимума 10 серт/сек"
        assert elapsed < 300, \
            f"1000 сертификатов заняли {elapsed:.1f}с (максимум 300с)"

    def test_validate_1000_certs(self, inter_key, inter_cert, root_cert):
        """Верификация 1000 сертификатов."""
        template = get_template("server")
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        count = 1000

        # Создаём сертификаты
        certs = []
        for i in range(count):
            subject = parse_subject_dn(f"CN=val{i}.example.com")
            san = parse_san_entries([f"dns:val{i}.example.com"])
            cert = build_leaf_certificate(
                subject=subject,
                leaf_public_key=leaf_key.public_key(),
                ca_private_key=inter_key,
                ca_cert=inter_cert,
                template=template,
                san_entries=san,
                validity_days=365,
                leaf_key_type="rsa",
            )
            certs.append(cert)

        # Верифицируем
        start = time.perf_counter()
        success_count = 0
        for cert in certs:
            result = validate_chain(
                leaf=cert,
                untrusted=[inter_cert],
                trusted=[root_cert],
            )
            if result.success:
                success_count += 1
        elapsed = time.perf_counter() - start
        rate = count / elapsed

        print(f"\n{'='*50}")
        print(f"Производительность верификации цепочки:")
        print(f"  Количество: {count}")
        print(f"  Успешно:    {success_count}")
        print(f"  Время:      {elapsed:.2f} сек")
        print(f"  Скорость:   {rate:.1f} верификаций/сек")
        print(f"{'='*50}")

        assert success_count == count, \
            f"Не все сертификаты прошли верификацию: {success_count}/{count}"
        assert rate > 5, \
            f"Скорость верификации {rate:.1f}/сек ниже минимума 5/сек"