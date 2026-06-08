"""
Криптографические утилиты:
- генерация ключей RSA и ECC
- сериализация закрытых ключей (зашифрованный и незашифрованный PEM)
- безопасное сохранение ключей на диск
- чтение парольных фраз
- загрузка зашифрованных ключей
"""

import os
import platform
import logging
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives import serialization
from cryptography import x509

logger = logging.getLogger("micropki")


def generate_private_key(key_type: str, key_size: int) -> PrivateKeyTypes:
    """
    Генерирует закрытый ключ.

    :param key_type: 'rsa' или 'ecc'
    :param key_size: размер ключа (4096/2048 для RSA, 384/256 для ECC)
    :return: объект закрытого ключа
    """
    if key_type == "rsa":
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

    if key_type == "ecc":
        if key_size == 384:
            curve = ec.SECP384R1()
        elif key_size == 256:
            curve = ec.SECP256R1()
        else:
            raise ValueError(f"Неподдерживаемый размер ECC: {key_size}")
        return ec.generate_private_key(curve=curve)

    raise ValueError(f"Неподдерживаемый тип ключа: {key_type}")


def serialize_private_key_pem(
    private_key: PrivateKeyTypes,
    passphrase: bytes,
) -> bytes:
    """
    Сериализует закрытый ключ → зашифрованный PEM (PKCS#8).

    :param private_key: объект закрытого ключа
    :param passphrase: парольная фраза
    :return: байты зашифрованного PEM
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )


def serialize_private_key_pem_unencrypted(
    private_key: PrivateKeyTypes,
) -> bytes:
    """
    Сериализует закрытый ключ → незашифрованный PEM (PKCS#8).

    Используется для ключей конечных субъектов.

    :param private_key: объект закрытого ключа
    :return: байты незашифрованного PEM
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def save_key_file(pem_data: bytes, file_path: Path) -> None:
    """
    Сохраняет PEM-файл ключа на диск с правами 0o600.

    На Windows выдаёт предупреждение о невозможности
    установить POSIX-права.

    :param pem_data: содержимое PEM-файла
    :param file_path: путь для сохранения
    """
    is_windows = platform.system() == "Windows"

    file_path.parent.mkdir(parents=True, exist_ok=True)

    if not is_windows:
        try:
            os.chmod(file_path.parent, 0o700)
        except OSError as exc:
            logger.warning(
                "Не удалось установить права 0700 на %s: %s",
                file_path.parent, exc,
            )
    else:
        logger.warning(
            "Обнаружена Windows — разрешения POSIX не поддерживаются. "
            "Убедитесь, что '%s' защищён вручную.",
            file_path.parent,
        )

    file_path.write_bytes(pem_data)

    if not is_windows:
        try:
            os.chmod(file_path, 0o600)
        except OSError as exc:
            logger.warning(
                "Не удалось установить права 0600 на %s: %s",
                file_path, exc,
            )


save_private_key = save_key_file


def read_passphrase(passphrase_file: Path) -> bytes:
    """
    Читает парольную фразу из файла.

    Убирает завершающие символы новой строки.
    Парольная фраза НЕ логируется.

    :param passphrase_file: путь к файлу
    :return: парольная фраза в виде байтов
    """
    raw: bytes = passphrase_file.read_bytes()
    return raw.rstrip(b"\r\n").rstrip(b"\n")


def load_encrypted_private_key(
    pem_path: Path,
    passphrase: bytes,
) -> PrivateKeyTypes:
    """
    Загружает зашифрованный закрытый ключ из PEM-файла.

    :param pem_path: путь к PEM-файлу
    :param passphrase: парольная фраза
    :return: объект закрытого ключа
    """
    pem_data = pem_path.read_bytes()
    return serialization.load_pem_private_key(
        data=pem_data,
        password=passphrase,
    )


def load_certificate(cert_path: Path) -> x509.Certificate:
    """
    Загружает сертификат из PEM-файла.

    :param cert_path: путь к PEM-файлу сертификата
    :return: объект сертификата
    """
    pem_data = cert_path.read_bytes()
    return x509.load_pem_x509_certificate(pem_data)


def get_cn_from_subject(subject: x509.Name) -> str:
    """
    Извлекает Common Name (CN) из DN субъекта.

    Используется для формирования имени файла.

    :param subject: объект x509.Name
    :return: значение CN или 'unknown'
    """
    from cryptography.x509.oid import NameOID
    cn_attrs = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        return cn_attrs[0].value
    return "unknown"


def sanitize_filename(name: str) -> str:
    """
    Очищает строку для использования в качестве имени файла.

    Заменяет небезопасные символы на подчёркивания.

    :param name: исходная строка
    :return: безопасное имя файла
    """
    safe = ""
    for ch in name:
        if ch.isalnum() or ch in (".", "-", "_"):
            safe += ch
        else:
            safe += "_"
    return safe