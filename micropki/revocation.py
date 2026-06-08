"""
Модуль отзыва сертификатов.

Содержит:
- маппинг строковых причин отзыва → коды RFC 5280
- функцию отзыва сертификата (обновление БД)
- валидацию причин отзыва
"""

import datetime
import logging

from pathlib import Path
from cryptography.x509 import ReasonFlags

from micropki.database import get_connection, check_schema
from micropki.serial import is_valid_hex

logger = logging.getLogger("micropki")


REVOCATION_REASONS: dict[str, tuple[int, ReasonFlags | None]] = {
    "unspecified":           (0,  ReasonFlags.unspecified),
    "keycompromise":         (1,  ReasonFlags.key_compromise),
    "cacompromise":          (2,  ReasonFlags.ca_compromise),
    "affiliationchanged":    (3,  ReasonFlags.affiliation_changed),
    "superseded":            (4,  ReasonFlags.superseded),
    "cessationofoperation":  (5,  ReasonFlags.cessation_of_operation),
    "certificatehold":       (6,  ReasonFlags.certificate_hold),
    "removefromcrl":         (8,  ReasonFlags.remove_from_crl),
    "privilegewithdrawn":    (9,  ReasonFlags.privilege_withdrawn),
    "aacompromise":          (10, ReasonFlags.aa_compromise),
}


def get_supported_reasons() -> list[str]:
    """
    Возвращает список поддерживаемых причин отзыва.

    :return: список строковых идентификаторов причин
    """
    return list(REVOCATION_REASONS.keys())


def validate_reason(reason: str) -> str:
    """
    Валидирует и нормализует причину отзыва.

    :param reason: строка причины (регистронезависимо)
    :return: нормализованная строка причины (нижний регистр)
    :raises ValueError: если причина не поддерживается
    """
    normalized = reason.lower().strip()
    if normalized not in REVOCATION_REASONS:
        raise ValueError(
            f"Неподдерживаемая причина отзыва: '{reason}'. "
            f"Допустимые: {get_supported_reasons()}"
        )
    return normalized


def get_reason_flag(reason: str) -> ReasonFlags | None:
    """
    Возвращает объект ReasonFlags для указанной причины.

    :param reason: нормализованная строка причины
    :return: объект ReasonFlags или None
    """
    normalized = reason.lower().strip()
    if normalized in REVOCATION_REASONS:
        return REVOCATION_REASONS[normalized][1]
    return None


def revoke_certificate(
    db_path: str | Path,
    serial_hex: str,
    reason: str = "unspecified",
    logger_inst: logging.Logger | None = None,
) -> dict:
    """
    Отзывает сертификат по серийному номеру.

    Обновляет в БД:
    - status → 'revoked'
    - revocation_reason → указанная причина
    - revocation_date → текущее UTC-время

    :param db_path: путь к файлу БД
    :param serial_hex: серийный номер в hex
    :param reason: причина отзыва
    :param logger_inst: логгер (если None, используется модульный)
    :return: словарь с результатом: {"status": "revoked"|"already_revoked"|"not_found", ...}
    :raises ValueError: при невалидной причине или серийном номере
    """
    log = logger_inst or logger

    # Валидация
    if not is_valid_hex(serial_hex):
        raise ValueError(f"Некорректный серийный номер: '{serial_hex}'")

    normalized_reason = validate_reason(reason)
    serial_upper = serial_hex.upper()

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()

        # Ищем сертификат
        cursor.execute(
            "SELECT serial_hex, subject, status, revocation_reason, revocation_date "
            "FROM certificates WHERE serial_hex = ? COLLATE NOCASE",
            (serial_upper,),
        )
        row = cursor.fetchone()

        if row is None:
            log.error("Сертификат не найден в БД: %s", serial_hex)
            return {
                "status": "not_found",
                "serial": serial_hex,
                "message": f"Сертификат с серийным номером {serial_hex} не найден в базе данных.",
            }

        current_status = row["status"]
        subject = row["subject"]

        # Уже отозван?
        if current_status == "revoked":
            log.warning(
                "Сертификат уже отозван: serial=%s, subject=%s, "
                "причина=%s, дата=%s",
                serial_hex, subject,
                row["revocation_reason"], row["revocation_date"],
            )
            return {
                "status": "already_revoked",
                "serial": serial_hex,
                "subject": subject,
                "revocation_reason": row["revocation_reason"],
                "revocation_date": row["revocation_date"],
                "message": f"Сертификат {serial_hex} уже отозван.",
            }

        # Отзываем
        now = datetime.datetime.now(datetime.timezone.utc)
        now_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        cursor.execute(
            """
            UPDATE certificates
            SET status = 'revoked',
                revocation_reason = ?,
                revocation_date = ?
            WHERE serial_hex = ? COLLATE NOCASE
            """,
            (normalized_reason, now_str, serial_upper),
        )
        conn.commit()

        # Аудит (AUD-4)
        from micropki.audit import get_audit_logger
        audit = get_audit_logger()
        if audit:
            audit.log_revoke(
                serial=serial_hex,
                subject=subject,
                reason=normalized_reason,
            )

        log.info(
            "Сертификат отозван: serial=%s, subject=%s, причина=%s, дата=%s",
            serial_hex, subject, normalized_reason, now_str,
        )

        return {
            "status": "revoked",
            "serial": serial_hex,
            "subject": subject,
            "revocation_reason": normalized_reason,
            "revocation_date": now_str,
            "message": f"Сертификат {serial_hex} успешно отозван.",
        }

    finally:
        conn.close()