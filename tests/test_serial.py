"""
Тесты генератора серийных номеров (TEST-17, TEST-18).

TEST-17: 100 сертификатов без коллизий.
TEST-18: Дубликат серийного номера отклоняется БД.
"""

import sqlite3
from pathlib import Path

import pytest

from micropki.database import init_database
from micropki.serial import (
    generate_serial,
    generate_unique_serial,
    serial_to_hex,
    hex_to_serial,
    is_valid_hex,
)
from micropki.repository import insert_certificate

import datetime


def test_serial_format():
    """Серийный номер — положительное 64-битное число."""
    serial = generate_serial()
    assert serial > 0
    assert serial < (1 << 63)  # 63 бита максимум (гарантия положительности)


def test_serial_to_hex_roundtrip():
    """Конвертация serial → hex → serial без потерь."""
    serial = generate_serial()
    hex_str = serial_to_hex(serial)
    assert hex_to_serial(hex_str) == serial


def test_is_valid_hex():
    """Валидация шестнадцатеричных строк."""
    assert is_valid_hex("3A7B") is True
    assert is_valid_hex("DEADBEEF") is True
    assert is_valid_hex("XYZ") is False
    assert is_valid_hex("") is False


def test_generate_100_unique_serials(tmp_path: Path):
    """TEST-17: 100 уникальных серийных номеров без коллизий."""
    db_path = tmp_path / "test.db"
    init_database(db_path)

    serials = set()
    now = datetime.datetime.now(datetime.timezone.utc)

    for i in range(100):
        serial = generate_unique_serial(db_path)
        hex_str = serial_to_hex(serial)
        assert hex_str not in serials, f"Коллизия на итерации {i}: {hex_str}"
        serials.add(hex_str)

        # Вставляем в БД чтобы проверять уникальность
        insert_certificate(
            db_path=db_path,
            serial_hex=hex_str,
            subject=f"CN=Test {i}",
            issuer="CN=Test CA",
            not_before=now,
            not_after=now + datetime.timedelta(days=365),
            cert_pem=f"-----BEGIN CERTIFICATE-----\nfake{i}\n-----END CERTIFICATE-----",
        )

    assert len(serials) == 100


def test_duplicate_serial_rejected(tmp_path: Path):
    """TEST-18: Дубликат серийного номера отклоняется БД."""
    db_path = tmp_path / "test.db"
    init_database(db_path)

    now = datetime.datetime.now(datetime.timezone.utc)
    serial_hex = "DEADBEEF12345678"

    # Первая вставка — ОК
    insert_certificate(
        db_path=db_path,
        serial_hex=serial_hex,
        subject="CN=Original",
        issuer="CN=Test CA",
        not_before=now,
        not_after=now + datetime.timedelta(days=365),
        cert_pem="-----BEGIN CERTIFICATE-----\noriginal\n-----END CERTIFICATE-----",
    )

    # Вторая вставка с тем же серийным номером — ошибка
    with pytest.raises(sqlite3.IntegrityError):
        insert_certificate(
            db_path=db_path,
            serial_hex=serial_hex,
            subject="CN=Duplicate",
            issuer="CN=Test CA",
            not_before=now,
            not_after=now + datetime.timedelta(days=365),
            cert_pem="-----BEGIN CERTIFICATE-----\nduplicate\n-----END CERTIFICATE-----",
        )