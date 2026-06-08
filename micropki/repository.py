"""
Репозиторий сертификатов — CRUD-операции с базой данных.

Содержит:
- вставку нового сертификата
- поиск по серийному номеру
- список с фильтрами
- получение отозванных сертификатов (подготовка к CRL)
"""

import sqlite3
import datetime
import logging
from pathlib import Path

from micropki.database import get_connection

logger = logging.getLogger("micropki")


def insert_certificate(
    db_path: str | Path,
    serial_hex: str,
    subject: str,
    issuer: str,
    not_before: datetime.datetime,
    not_after: datetime.datetime,
    cert_pem: str,
) -> None:
    """
    Вставляет запись о сертификате в базу данных.

    :param db_path: путь к файлу БД
    :param serial_hex: серийный номер в hex
    :param subject: DN субъекта
    :param issuer: DN издателя
    :param not_before: начало действия
    :param not_after: конец действия
    :param cert_pem: полный PEM-текст сертификата
    :raises sqlite3.IntegrityError: при дубликате серийного номера
    """
    conn = get_connection(db_path)
    try:
        now = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        conn.execute(
            """
            INSERT INTO certificates
                (serial_hex, subject, issuer, not_before, not_after,
                 cert_pem, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'valid', ?)
            """,
            (
                serial_hex,
                subject,
                issuer,
                not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
                not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
                cert_pem,
                now,
            ),
        )
        conn.commit()
        logger.info(
            "Сертификат вставлен в БД: serial=%s, subject=%s",
            serial_hex, subject,
        )
    except sqlite3.IntegrityError as e:
        logger.error(
            "Ошибка вставки в БД (дубликат серийного номера?): %s", e
        )
        raise
    except sqlite3.Error as e:
        logger.error("Ошибка БД при вставке сертификата: %s", e)
        raise
    finally:
        conn.close()


def get_certificate_by_serial(
    db_path: str | Path,
    serial_hex: str,
) -> dict | None:
    """
    Находит сертификат по серийному номеру.

    :param db_path: путь к файлу БД
    :param serial_hex: серийный номер в hex (регистронезависимо)
    :return: словарь с данными сертификата или None
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM certificates WHERE serial_hex = ? COLLATE NOCASE",
            (serial_hex.upper(),),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return dict(row)
    finally:
        conn.close()


def list_certificates(
    db_path: str | Path,
    status: str | None = None,
    issuer: str | None = None,
) -> list[dict]:
    """
    Возвращает список сертификатов с необязательными фильтрами.

    :param db_path: путь к файлу БД
    :param status: фильтр по статусу ('valid', 'revoked', 'expired')
    :param issuer: фильтр по DN издателя
    :return: список словарей
    """
    conn = get_connection(db_path)
    try:
        query = "SELECT * FROM certificates WHERE 1=1"
        params: list = []

        if status is not None:
            query += " AND status = ?"
            params.append(status)

        if issuer is not None:
            query += " AND issuer LIKE ?"
            params.append(f"%{issuer}%")

        query += " ORDER BY created_at DESC"

        cursor = conn.cursor()
        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def update_certificate_status(
    db_path: str | Path,
    serial_hex: str,
    new_status: str,
    reason: str | None = None,
) -> bool:
    """
    Обновляет статус сертификата.

    :param db_path: путь к файлу БД
    :param serial_hex: серийный номер в hex
    :param new_status: новый статус ('valid', 'revoked', 'expired')
    :param reason: причина отзыва (если применимо)
    :return: True если запись обновлена
    """
    conn = get_connection(db_path)
    try:
        now = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        revocation_date = now if new_status == "revoked" else None

        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE certificates
            SET status = ?, revocation_reason = ?, revocation_date = ?
            WHERE serial_hex = ? COLLATE NOCASE
            """,
            (new_status, reason, revocation_date, serial_hex.upper()),
        )
        conn.commit()

        if cursor.rowcount > 0:
            logger.info(
                "Статус сертификата обновлён: serial=%s, status=%s",
                serial_hex, new_status,
            )
            return True

        logger.warning("Сертификат не найден для обновления: %s", serial_hex)
        return False
    finally:
        conn.close()


def get_revoked_certificates(db_path: str | Path) -> list[dict]:
    """
    Возвращает все отозванные сертификаты (подготовка к CRL).

    :param db_path: путь к файлу БД
    :return: список словарей с данными отозванных сертификатов
    """
    return list_certificates(db_path, status="revoked")