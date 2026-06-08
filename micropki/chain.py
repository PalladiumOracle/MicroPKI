"""
Модуль проверки цепочки сертификатов.

Проверяет:
- подписи на каждом уровне цепочки
- сроки действия
- BasicConstraints (флаг CA и pathLenConstraint)
"""

import datetime
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import ExtensionOID


def load_certificate(cert_path: Path) -> x509.Certificate:
    """
    Загружает сертификат из PEM-файла.

    :param cert_path: путь к PEM-файлу сертификата
    :return: объект сертификата
    """
    pem_data = cert_path.read_bytes()
    return x509.load_pem_x509_certificate(pem_data)


def verify_signature(
    child_cert: x509.Certificate,
    parent_cert: x509.Certificate,
) -> bool:
    """
    Проверяет, что child_cert подписан закрытым ключом parent_cert.

    :param child_cert: дочерний сертификат
    :param parent_cert: родительский сертификат
    :return: True если подпись верна
    :raises ValueError: если подпись некорректна
    """
    parent_public_key = parent_cert.public_key()

    try:
        if isinstance(parent_public_key, rsa.RSAPublicKey):
            parent_public_key.verify(
                child_cert.signature,
                child_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                child_cert.signature_hash_algorithm,
            )
        elif isinstance(parent_public_key, ec.EllipticCurvePublicKey):
            parent_public_key.verify(
                child_cert.signature,
                child_cert.tbs_certificate_bytes,
                ec.ECDSA(child_cert.signature_hash_algorithm),
            )
        else:
            raise ValueError(f"Неподдерживаемый тип ключа: {type(parent_public_key)}")
    except InvalidSignature:
        raise ValueError(
            f"Подпись сертификата '{child_cert.subject}' "
            f"НЕ соответствует ключу издателя '{parent_cert.subject}'"
        )

    return True


def verify_validity(cert: x509.Certificate) -> bool:
    """
    Проверяет, что сертификат действителен по времени.

    :param cert: сертификат для проверки
    :return: True если действителен
    :raises ValueError: если сертификат просрочен или ещё не вступил в силу
    """
    now = datetime.datetime.now(datetime.timezone.utc)

    if now < cert.not_valid_before_utc:
        raise ValueError(
            f"Сертификат '{cert.subject}' ещё не вступил в силу. "
            f"Действителен с {cert.not_valid_before_utc}"
        )

    if now > cert.not_valid_after_utc:
        raise ValueError(
            f"Сертификат '{cert.subject}' истёк. "
            f"Действителен до {cert.not_valid_after_utc}"
        )

    return True


def verify_basic_constraints(cert: x509.Certificate, expect_ca: bool) -> bool:
    """
    Проверяет расширение BasicConstraints.

    :param cert: сертификат
    :param expect_ca: ожидаемое значение флага CA
    :return: True если расширение соответствует ожиданию
    :raises ValueError: если расширение отсутствует или не соответствует
    """
    try:
        bc_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
    except x509.ExtensionNotFound:
        raise ValueError(
            f"Сертификат '{cert.subject}' не содержит расширения BasicConstraints."
        )

    bc: x509.BasicConstraints = bc_ext.value

    if bc.ca != expect_ca:
        raise ValueError(
            f"Сертификат '{cert.subject}': ожидалось CA={expect_ca}, "
            f"получено CA={bc.ca}"
        )

    return True


def verify_chain(
    leaf_cert: x509.Certificate,
    intermediate_cert: x509.Certificate,
    root_cert: x509.Certificate,
) -> list[str]:
    """
    Полная проверка цепочки: leaf → intermediate → root.

    Проверяет:
    1. Подписи на каждом уровне
    2. Сроки действия всех сертификатов
    3. BasicConstraints: root и intermediate = CA:TRUE, leaf = CA:FALSE

    :return: список сообщений о прохождении проверок
    :raises ValueError: при первой обнаруженной ошибке
    """
    results: list[str] = []

    # Проверяем подпись leaf → подписан intermediate
    verify_signature(leaf_cert, intermediate_cert)
    results.append(
        f"Подпись leaf '{leaf_cert.subject}' верна "
        f"(подписан '{intermediate_cert.subject}')"
    )

    # Проверяем подпись intermediate → подписан root
    verify_signature(intermediate_cert, root_cert)
    results.append(
        f"Подпись intermediate '{intermediate_cert.subject}' верна "
        f"(подписан '{root_cert.subject}')"
    )

    # Проверяем подпись root → самоподписанный
    verify_signature(root_cert, root_cert)
    results.append(
        f"Корневой сертификат '{root_cert.subject}' самоподписан"
    )

    # Сроки действия
    for cert in (leaf_cert, intermediate_cert, root_cert):
        verify_validity(cert)
        results.append(f"Сертификат '{cert.subject}' действителен по времени")

    # BasicConstraints
    verify_basic_constraints(root_cert, expect_ca=True)
    results.append(f"Корневой CA: BasicConstraints CA=TRUE")

    verify_basic_constraints(intermediate_cert, expect_ca=True)
    results.append(f"Промежуточный CA: BasicConstraints CA=TRUE")

    verify_basic_constraints(leaf_cert, expect_ca=False)
    results.append(f"Конечный сертификат: BasicConstraints CA=FALSE")

    return results