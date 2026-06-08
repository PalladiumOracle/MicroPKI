"""
Симуляция Certificate Transparency (CTL-2).

Простой текстовый журнал CT-записей.
Не является настоящим CT-журналом (без деревьев Меркла).
"""

import hashlib
import os
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization


def get_cert_fingerprint(cert: x509.Certificate) -> str:
    """
    Вычисляет SHA-256 отпечаток сертификата.

    :param cert: объект сертификата
    :return: hex-строка SHA-256
    """
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def verify_ct_inclusion(ct_log_path: Path, serial_hex: str) -> bool:
    """
    Проверяет наличие сертификата в CT-журнале (CTL-2).

    :param ct_log_path: путь к файлу ct.log
    :param serial_hex: серийный номер в hex
    :return: True если найден
    """
    if not ct_log_path.exists():
        return False

    serial_upper = serial_hex.upper()
    with open(ct_log_path, "r", encoding="utf-8") as f:
        for line in f:
            if serial_upper in line.upper():
                return True
    return False


def query_ct_log(
    ct_log_path: Path,
    serial_hex: Optional[str] = None,
    subject: Optional[str] = None,
) -> list[dict]:
    """
    Запрашивает CT-журнал с фильтрацией.

    :param ct_log_path: путь к файлу ct.log
    :param serial_hex: фильтр по серийному номеру
    :param subject: фильтр по субъекту
    :return: список записей в виде словарей
    """
    if not ct_log_path.exists():
        return []

    results = []
    with open(ct_log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < 4:
                continue

            entry = {
                "timestamp": parts[0],
                "serial": parts[1],
                "subject": parts[2],
                "fingerprint": parts[3],
                "issuer": parts[4] if len(parts) > 4 else "",
            }

            if serial_hex and serial_hex.upper() not in entry["serial"].upper():
                continue
            if subject and subject.lower() not in entry["subject"].lower():
                continue

            results.append(entry)

    return results