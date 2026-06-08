"""
Модуль генерации списков отозванных сертификатов (CRL).

Содержит:
- построение CRL v2 по RFC 5280
- подпись CRL закрытым ключом CA
- сериализацию в PEM
- управление номерами CRL
"""

import datetime
import logging
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod, ec as ec_mod

from micropki.database import get_connection
from micropki.repository import get_revoked_certificates, list_certificates
from micropki.revocation import get_reason_flag

logger = logging.getLogger("micropki")


def _detect_key_type(private_key: PrivateKeyTypes) -> str:
    """Определяет тип ключа."""
    if isinstance(private_key, rsa_mod.RSAPrivateKey):
        return "rsa"
    if isinstance(private_key, ec_mod.EllipticCurvePrivateKey):
        return "ecc"
    raise ValueError(f"Неподдерживаемый тип ключа: {type(private_key)}")


def _get_signing_hash(key_type: str) -> hashes.HashAlgorithm:
    """Возвращает алгоритм хеширования для подписи."""
    if key_type == "rsa":
        return hashes.SHA256()
    if key_type == "ecc":
        return hashes.SHA384()
    raise ValueError(f"Неподдерживаемый тип ключа: {key_type}")


def _dn_to_string(name: x509.Name) -> str:
    """Преобразует x509.Name в строку для поиска в БД."""
    parts = []
    for attr in name:
        parts.append(f"{attr.oid._name}={attr.value}")
    return ", ".join(parts)


def get_crl_number(db_path: str | Path, ca_subject: str) -> int:
    """
    Получает текущий номер CRL для данного CA из БД.
    Если записи нет — возвращает 0.

    :param db_path: путь к БД
    :param ca_subject: DN субъекта CA
    :return: текущий номер CRL
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT crl_number FROM crl_metadata WHERE ca_subject = ?",
            (ca_subject,),
        )
        row = cursor.fetchone()
        return row["crl_number"] if row else 0
    finally:
        conn.close()


def update_crl_metadata(
    db_path: str | Path,
    ca_subject: str,
    crl_number: int,
    next_update: datetime.datetime,
    crl_path: str,
) -> None:
    """
    Обновляет или вставляет метаданные CRL в БД.

    :param db_path: путь к БД
    :param ca_subject: DN субъекта CA
    :param crl_number: новый номер CRL
    :param next_update: дата следующего обновления
    :param crl_path: путь к файлу CRL
    """
    conn = get_connection(db_path)
    try:
        now_str = datetime.datetime.now(
            datetime.timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        next_str = next_update.strftime("%Y-%m-%dT%H:%M:%SZ")

        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM crl_metadata WHERE ca_subject = ?",
            (ca_subject,),
        )
        row = cursor.fetchone()

        if row:
            cursor.execute(
                """
                UPDATE crl_metadata
                SET crl_number = ?, last_generated = ?, next_update = ?, crl_path = ?
                WHERE ca_subject = ?
                """,
                (crl_number, now_str, next_str, crl_path, ca_subject),
            )
        else:
            cursor.execute(
                """
                INSERT INTO crl_metadata (ca_subject, crl_number, last_generated, next_update, crl_path)
                VALUES (?, ?, ?, ?, ?)
                """,
                (ca_subject, crl_number, now_str, next_str, crl_path),
            )

        conn.commit()
    finally:
        conn.close()


def build_crl(
    ca_cert: x509.Certificate,
    ca_private_key: PrivateKeyTypes,
    revoked_certs: list[dict],
    next_update_days: int,
    crl_number: int,
) -> x509.CertificateRevocationList:
    """
    Строит и подписывает CRL v2.

    :param ca_cert: сертификат CA-издателя CRL
    :param ca_private_key: закрытый ключ CA
    :param revoked_certs: список отозванных сертификатов из БД
    :param next_update_days: дней до следующего обновления
    :param crl_number: порядковый номер CRL
    :return: подписанный CRL
    """
    key_type = _detect_key_type(ca_private_key)
    signing_hash = _get_signing_hash(key_type)

    now = datetime.datetime.now(datetime.timezone.utc)
    next_update = now + datetime.timedelta(days=next_update_days)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(next_update)
    )

    # Расширение: CRL Number
    builder = builder.add_extension(
        x509.CRLNumber(crl_number),
        critical=False,
    )

    # Расширение: Authority Key Identifier
    try:
        ca_ski_ext = ca_cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            ca_ski_ext.value
        )
        builder = builder.add_extension(aki, critical=False)
    except x509.ExtensionNotFound:
        logger.warning("Сертификат CA не содержит SKI, AKI в CRL не добавлен")

    # Добавляем каждый отозванный сертификат
    for cert_data in revoked_certs:
        serial = int(cert_data["serial_hex"], 16)

        # Парсим дату отзыва
        rev_date_str = cert_data.get("revocation_date", "")
        if rev_date_str:
            try:
                rev_date = datetime.datetime.strptime(
                    rev_date_str, "%Y-%m-%dT%H:%M:%SZ"
                ).replace(tzinfo=datetime.timezone.utc)
            except ValueError:
                rev_date = now
        else:
            rev_date = now

        revoked_builder = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(rev_date)
        )

        # Добавляем причину отзыва как расширение записи
        reason_str = cert_data.get("revocation_reason", "unspecified")
        if reason_str:
            reason_flag = get_reason_flag(reason_str)
            if reason_flag is not None:
                revoked_builder = revoked_builder.add_extension(
                    x509.CRLReason(reason_flag),
                    critical=False,
                )

        builder = builder.add_revoked_certificate(revoked_builder.build())

    # Подписываем CRL
    crl = builder.sign(
        private_key=ca_private_key,
        algorithm=signing_hash,
    )

    return crl


def serialize_crl_pem(crl: x509.CertificateRevocationList) -> bytes:
    """
    Сериализует CRL в PEM-формат.

    :param crl: объект CRL
    :return: байты PEM (-----BEGIN X509 CRL-----)
    """
    return crl.public_bytes(serialization.Encoding.PEM)


def generate_crl(
    ca_name: str,
    ca_cert: x509.Certificate,
    ca_private_key: PrivateKeyTypes,
    db_path: str | Path,
    out_dir: str | Path,
    next_update_days: int = 7,
    out_file: str | Path | None = None,
    logger_inst: logging.Logger | None = None,
) -> Path:
    """
    Полная процедура генерации CRL.

    1. Получает текущий CRL Number из БД
    2. Запрашивает отозванные сертификаты этого CA
    3. Строит и подписывает CRL
    4. Сохраняет файл
    5. Обновляет CRL Number в БД

    :param ca_name: имя CA ('root' или 'intermediate')
    :param ca_cert: сертификат CA
    :param ca_private_key: закрытый ключ CA
    :param db_path: путь к БД
    :param out_dir: выходной каталог
    :param next_update_days: дней до следующего обновления
    :param out_file: путь к файлу CRL (если None — автоматический)
    :param logger_inst: логгер
    :return: путь к сохранённому файлу CRL
    """
    log = logger_inst or logger

    ca_subject_str = _dn_to_string(ca_cert.subject)

    # Получаем CRL Number
    current_number = get_crl_number(db_path, ca_subject_str)
    new_number = current_number + 1

    log.info(
        "Начало генерации CRL: CA=%s, CRL Number=%d",
        ca_name, new_number,
    )

    # Запрашиваем отозванные сертификаты этого CA
    all_certs = list_certificates(db_path, status="revoked")
    # Фильтруем по издателю
    revoked_for_ca = [
        c for c in all_certs
        if c["issuer"] == ca_subject_str
    ]

    log.info(
        "Найдено %d отозванных сертификатов для CA '%s'",
        len(revoked_for_ca), ca_name,
    )

    # Строим CRL
    now = datetime.datetime.now(datetime.timezone.utc)
    next_update = now + datetime.timedelta(days=next_update_days)

    crl = build_crl(
        ca_cert=ca_cert,
        ca_private_key=ca_private_key,
        revoked_certs=revoked_for_ca,
        next_update_days=next_update_days,
        crl_number=new_number,
    )

    # Сохраняем файл
    if out_file:
        crl_path = Path(out_file)
    else:
        crl_dir = Path(out_dir) / "crl"
        crl_dir.mkdir(parents=True, exist_ok=True)
        crl_path = crl_dir / f"{ca_name}.crl.pem"

    crl_path.parent.mkdir(parents=True, exist_ok=True)
    crl_pem = serialize_crl_pem(crl)
    crl_path.write_bytes(crl_pem)

    log.info("CRL сохранён: %s", crl_path.resolve())

    # Обновляем метаданные в БД
    update_crl_metadata(
        db_path=db_path,
        ca_subject=ca_subject_str,
        crl_number=new_number,
        next_update=next_update,
        crl_path=str(crl_path),
    )

    log.info(
        "Генерация CRL завершена: CA=%s, CRL Number=%d, "
        "отозвано сертификатов=%d, thisUpdate=%s, nextUpdate=%s",
        ca_name, new_number, len(revoked_for_ca),
        now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        next_update.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )

    # Аудит (AUD-4)
    from micropki.audit import get_audit_logger
    audit = get_audit_logger()
    if audit:
        audit.log_crl_generation(
            ca_name=ca_name,
            crl_number=new_number,
            revoked_count=len(revoked_for_ca),
        )

    return crl_path