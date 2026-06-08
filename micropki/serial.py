"""
Генератор уникальных серийных номеров для сертификатов.

Использует составной 64-битный номер:
  - старшие 32 бита: метка времени Unix (секунды)
  - младшие 32 бита: случайное число от CSPRNG

Уникальность гарантируется UNIQUE constraint в БД
и механизмом повторной генерации при коллизии.
"""

import os
import time
import logging
import sqlite3
from pathlib import Path

from micropki.database import get_connection

logger = logging.getLogger("micropki")

MAX_RETRIES = 10


def generate_serial() -> int:
    """
    Генерирует 64-битный составной серийный номер.

    Старшие 32 бита = Unix timestamp (секунды).
    Младшие 32 бита = случайное число (CSPRNG).

    :return: положительное целое число
    """
    timestamp = int(time.time()) & 0xFFFFFFFF
    random_part = int.from_bytes(os.urandom(4), byteorder="big")
    serial = (timestamp << 32) | random_part

    serial = serial & 0x7FFFFFFFFFFFFFFF
    if serial == 0:
        serial = 1
    return serial


def serial_to_hex(serial: int) -> str:
    """
    Конвертирует серийный номер в шестнадцатеричную строку.

    :param serial: целое число
    :return: строка в верхнем регистре, например "660F7A4BA3B2C1D4"
    """
    return format(serial, "016X")


def hex_to_serial(hex_str: str) -> int:
    """
    Конвертирует шестнадцатеричную строку в целое число.

    :param hex_str: шестнадцатеричная строка
    :return: целое число
    :raises ValueError: при некорректном формате
    """
    try:
        return int(hex_str, 16)
    except ValueError:
        raise ValueError(f"Некорректный шестнадцатеричный серийный номер: '{hex_str}'")


def is_valid_hex(hex_str: str) -> bool:
    """
    Проверяет, является ли строка валидным шестнадцатеричным числом.

    :param hex_str: строка для проверки
    :return: True если валидна
    """
    try:
        int(hex_str, 16)
        return True
    except ValueError:
        return False


def generate_unique_serial(db_path: str | Path) -> int:
    """
    Генерирует серийный номер, гарантированно уникальный в БД.

    При коллизии (крайне маловероятной) повторяет генерацию
    до MAX_RETRIES раз.

    :param db_path: путь к файлу БД
    :return: уникальный серийный номер
    :raises RuntimeError: если не удалось сгенерировать уникальный номер
    """
    conn = get_connection(db_path)
    try:
        for attempt in range(MAX_RETRIES):
            serial = generate_serial()
            hex_str = serial_to_hex(serial)

            cursor = conn.cursor()
            cursor.execute(
                "SELECT 1 FROM certificates WHERE serial_hex = ?",
                (hex_str,),
            )
            if cursor.fetchone() is None:
                logger.info(
                    "Сгенерирован уникальный серийный номер: %s (попытка %d)",
                    hex_str, attempt + 1,
                )
                return serial

            logger.warning(
                "Коллизия серийного номера %s, повторная генерация (попытка %d/%d)",
                hex_str, attempt + 1, MAX_RETRIES,
            )

        raise RuntimeError(
            f"Не удалось сгенерировать уникальный серийный номер "
            f"за {MAX_RETRIES} попыток"
        )
    finally:
        conn.close()