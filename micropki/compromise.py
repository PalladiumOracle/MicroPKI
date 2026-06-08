"""
Модуль симуляции компрометации закрытого ключа (CTL-3, CLI-33).

Реализует:
- немедленный отзыв с причиной keyCompromise
- запись в таблицу compromised_keys
- создание аудит-записи высокой критичности
- опциональное обновление CRL
"""

import datetime
import logging
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from micropki.database import get_connection, check_schema
from micropki.revocation import revoke_certificate
from micropki.policy import get_public_key_hash
from micropki.serial import is_valid_hex

logger = logging.getLogger("micropki")


# ---------------------------------------------------------------------------
# База данных: compromised_keys
# ---------------------------------------------------------------------------

CREATE_COMPROMISED_KEYS_TABLE = """
CREATE TABLE IF NOT EXISTS compromised_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_key_hash TEXT UNIQUE NOT NULL,
    certificate_serial TEXT NOT NULL,
    compromise_date TEXT NOT NULL,
    compromise_reason TEXT NOT NULL,
    FOREIGN KEY (certificate_serial) REFERENCES certificates(serial_hex)
);
"""

CREATE_COMPROMISED_KEYS_INDEX = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_compromised_key_hash
ON compromised_keys(public_key_hash);
"""


def ensure_compromised_keys_table(db_path) -> None:
    """Создаёт таблицу compromised_keys если не существует."""
    conn = get_connection(db_path)
    try:
        conn.executescript(
            CREATE_COMPROMISED_KEYS_TABLE + CREATE_COMPROMISED_KEYS_INDEX
        )
        conn.commit()
    finally:
        conn.close()


def record_compromised_key(
    db_path,
    public_key_hash: str,
    certificate_serial: str,
    reason: str = "keyCompromise",
) -> None:
    """
    Записывает информацию о скомпрометированном ключе в БД (DB-10).

    :param db_path: путь к БД
    :param public_key_hash: SHA-256 хеш открытого ключа (DER SPKI)
    :param certificate_serial: серийный номер сертификата
    :param reason: причина компрометации
    """
    ensure_compromised_keys_table(db_path)
    now = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    conn = get_connection(db_path)
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO compromised_keys
                (public_key_hash, certificate_serial, compromise_date, compromise_reason)
            VALUES (?, ?, ?, ?)
            """,
            (public_key_hash, certificate_serial.upper(), now, reason),
        )
        conn.commit()
        logger.info(
            "Ключ помечен как скомпрометированный: serial=%s hash=%s",
            certificate_serial, public_key_hash[:16] + "...",
        )
    finally:
        conn.close()


def is_key_compromised(db_path, public_key_hash: str) -> bool:
    """
    Проверяет, является ли ключ скомпрометированным (CTL-4).

    :param db_path: путь к БД
    :param public_key_hash: SHA-256 хеш открытого ключа
    :return: True если ключ скомпрометирован
    """
    if not check_schema(db_path):
        return False

    conn = get_connection(db_path)
    try:
        # Проверяем существование таблицы
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='compromised_keys'"
        )
        if cursor.fetchone() is None:
            return False

        cursor.execute(
            "SELECT 1 FROM compromised_keys WHERE public_key_hash = ?",
            (public_key_hash,),
        )
        return cursor.fetchone() is not None
    finally:
        conn.close()


def check_csr_key_not_compromised(
    db_path,
    csr: x509.CertificateSigningRequest,
) -> list[str]:
    """
    Проверяет, что ключ из CSR не скомпрометирован (CTL-4).

    :param db_path: путь к БД
    :param csr: объект CSR
    :return: список ошибок (пустой = OK)
    """
    if db_path is None:
        return []

    pub = csr.public_key()
    key_hash = get_public_key_hash(pub)

    if is_key_compromised(db_path, key_hash):
        return [
            f"Ключ скомпрометирован (hash={key_hash[:16]}...). "
            f"Выпуск сертификата с этим ключом запрещён."
        ]
    return []


def get_compromised_keys_list(db_path) -> list[dict]:
    """Возвращает список скомпрометированных ключей из БД."""
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='compromised_keys'"
        )
        if cursor.fetchone() is None:
            return []

        cursor.execute("SELECT * FROM compromised_keys ORDER BY compromise_date DESC")
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Основная функция компрометации (CLI-33)
# ---------------------------------------------------------------------------

def simulate_compromise(
    db_path,
    cert_path: Path,
    reason: str = "keyCompromise",
    logger_inst=None,
    generate_crl: bool = False,
    ca_cert_path: Optional[Path] = None,
    ca_key_path: Optional[Path] = None,
    ca_passphrase: Optional[bytes] = None,
    out_dir: Optional[Path] = None,
    audit_logger=None,
) -> dict:
    """
    Симулирует компрометацию закрытого ключа (CTL-3).

    Выполняет:
    1. Загружает сертификат из файла
    2. Вычисляет хеш открытого ключа
    3. Немедленно отзывает сертификат с причиной keyCompromise
    4. Записывает в таблицу compromised_keys
    5. Создаёт аудит-запись высокой критичности
    6. Опционально генерирует экстренный CRL

    :param db_path: путь к БД
    :param cert_path: путь к сертификату (PEM)
    :param reason: причина компрометации
    :param logger_inst: логгер
    :param generate_crl: генерировать ли CRL сразу
    :param ca_cert_path: путь к CA-сертификату (для CRL)
    :param ca_key_path: путь к CA-ключу (для CRL)
    :param ca_passphrase: пароль для CA-ключа
    :param out_dir: каталог для CRL
    :param audit_logger: аудитный регистратор
    :return: dict с результатом
    """
    log = logger_inst or logger

    # Загружаем сертификат
    cert_pem = cert_path.read_bytes()
    cert = x509.load_pem_x509_certificate(cert_pem)

    # Серийный номер
    from micropki.serial import serial_to_hex
    serial_hex = serial_to_hex(cert.serial_number)

    # Субъект
    try:
        subject_str = cert.subject.rfc4514_string()
    except Exception:
        subject_str = str(cert.subject)

    # Хеш открытого ключа
    pub_key = cert.public_key()
    key_hash = get_public_key_hash(pub_key)

    log.warning(
        "КОМПРОМЕТАЦИЯ КЛЮЧА: serial=%s, subject=%s, key_hash=%s",
        serial_hex, subject_str, key_hash[:16] + "...",
    )

    # Отзываем сертификат
    revoke_result = revoke_certificate(
        db_path=db_path,
        serial_hex=serial_hex,
        reason=reason,
        logger_inst=log,
    )

    # Записываем в compromised_keys
    record_compromised_key(
        db_path=db_path,
        public_key_hash=key_hash,
        certificate_serial=serial_hex,
        reason=reason,
    )

    # Аудит (высокая критичность)
    if audit_logger:
        audit_logger.log_compromise(
            serial=serial_hex,
            subject=subject_str,
            key_hash=key_hash,
        )

    # Экстренный CRL (опционально)
    crl_path = None
    if generate_crl and ca_cert_path and ca_key_path and ca_passphrase:
        try:
            from micropki.crl import generate_crl as gen_crl_func
            from micropki.crypto_utils import (
                load_certificate,
                load_encrypted_private_key,
            )
            ca_cert = load_certificate(ca_cert_path)
            ca_private_key = load_encrypted_private_key(ca_key_path, ca_passphrase)
            crl_path = gen_crl_func(
                ca_name="intermediate",
                ca_cert=ca_cert,
                ca_private_key=ca_private_key,
                db_path=db_path,
                out_dir=out_dir or Path("./pki"),
                next_update_days=1,  # экстренный — короткий срок
                logger_inst=log,
            )
            log.warning(
                "Экстренный CRL сгенерирован после компрометации: %s", crl_path
            )
            if audit_logger:
                audit_logger.log_crl_generation(
                    ca_name="intermediate",
                    crl_number=-1,
                    revoked_count=1,
                    status="success",
                )
        except Exception as e:
            log.error("Ошибка генерации экстренного CRL: %s", e)

    return {
        "serial": serial_hex,
        "subject": subject_str,
        "key_hash": key_hash,
        "revoke_result": revoke_result,
        "crl_path": str(crl_path) if crl_path else None,
        "message": (
            f"Ключ сертификата {serial_hex} ({subject_str}) "
            f"помечен как скомпрометированный и немедленно отозван."
        ),
    }