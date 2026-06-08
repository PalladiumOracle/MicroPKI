"""
Модуль применения политик безопасности MicroPKI (спринт 7).

Реализует:
- контроль размера ключей (POL-3)
- контроль срока действия (POL-4)
- проверку и ограничения SAN (POL-5)
- контроль алгоритмов (POL-6)
- контроль pathLen (POL-7)
"""

import hashlib
from dataclasses import dataclass, field
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod, ec as ec_mod
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID


# ---------------------------------------------------------------------------
# Конфигурация политик
# ---------------------------------------------------------------------------

@dataclass
class PolicyConfig:
    """Настройки политик безопасности."""

    # Размеры ключей (минимальные)
    root_ca_rsa_min_bits: int = 4096
    root_ca_ecc_min_bits: int = 384        # P-384
    inter_ca_rsa_min_bits: int = 2048      # рекомендуется 4096
    inter_ca_ecc_min_bits: int = 384       # P-384
    leaf_rsa_min_bits: int = 2048
    leaf_ecc_min_bits: int = 256           # P-256

    # Сроки действия (максимальные, дней)
    root_ca_max_days: int = 3650           # 10 лет
    inter_ca_max_days: int = 1825          # 5 лет
    leaf_max_days: int = 365              # 1 год

    # SAN
    allow_wildcards: bool = False          # по умолчанию запрещены

    # pathLen
    inter_ca_max_pathlen: int = 0         # POL-7: только 0


# Глобальная конфигурация политик (можно переопределить)
_policy_config = PolicyConfig()


def get_policy_config() -> PolicyConfig:
    """Возвращает текущую конфигурацию политик."""
    return _policy_config


def set_policy_config(config: PolicyConfig) -> None:
    """Устанавливает конфигурацию политик."""
    global _policy_config
    _policy_config = config


# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------

def get_public_key_hash(public_key) -> str:
    """
    Вычисляет SHA-256 хеш открытого ключа (DER SPKI).

    Используется для обнаружения скомпрометированных ключей (CTL-4).

    :param public_key: объект открытого ключа
    :return: hex-строка SHA-256
    """
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def _get_rsa_bits(public_key) -> int:
    """Возвращает размер RSA-ключа в битах."""
    return public_key.key_size


def _get_ecc_bits(public_key) -> int:
    """Возвращает размер ECC-ключа (размер кривой) в битах."""
    curve = public_key.curve
    if isinstance(curve, ec_mod.SECP256R1):
        return 256
    if isinstance(curve, ec_mod.SECP384R1):
        return 384
    if isinstance(curve, ec_mod.SECP521R1):
        return 521
    # Для неизвестных кривых возвращаем 0
    return 0


# ---------------------------------------------------------------------------
# POL-3: Контроль размера ключей
# ---------------------------------------------------------------------------

def validate_key_size_for_cert_type(
    public_key,
    cert_type: str,
    config: Optional[PolicyConfig] = None,
) -> list[str]:
    """
    Проверяет размер ключа согласно политике (POL-3).

    :param public_key: открытый ключ
    :param cert_type: 'root_ca', 'inter_ca', 'leaf'
    :param config: конфигурация политик (None = глобальная)
    :return: список ошибок (пустой = OK)
    """
    cfg = config or get_policy_config()
    errors = []

    if isinstance(public_key, rsa_mod.RSAPublicKey):
        bits = _get_rsa_bits(public_key)
        if cert_type == "root_ca":
            min_bits = cfg.root_ca_rsa_min_bits
        elif cert_type == "inter_ca":
            min_bits = cfg.inter_ca_rsa_min_bits
        else:
            min_bits = cfg.leaf_rsa_min_bits

        if bits < min_bits:
            errors.append(
                f"RSA-ключ {bits} бит не соответствует минимуму "
                f"{min_bits} бит для {cert_type}."
            )

    elif isinstance(public_key, ec_mod.EllipticCurvePublicKey):
        bits = _get_ecc_bits(public_key)
        if cert_type == "root_ca":
            min_bits = cfg.root_ca_ecc_min_bits
        elif cert_type == "inter_ca":
            min_bits = cfg.inter_ca_ecc_min_bits
        else:
            min_bits = cfg.leaf_ecc_min_bits

        if bits < min_bits:
            errors.append(
                f"ECC-ключ {bits} бит (кривая) не соответствует минимуму "
                f"{min_bits} бит для {cert_type}."
            )
    else:
        errors.append(f"Неподдерживаемый тип ключа: {type(public_key)}")

    return errors


def validate_private_key_size(
    key_type: str,
    key_size: int,
    cert_type: str,
    config: Optional[PolicyConfig] = None,
) -> list[str]:
    """
    Проверяет размер ключа по параметрам генерации (до фактической генерации).

    :param key_type: 'rsa' или 'ecc'
    :param key_size: размер в битах
    :param cert_type: 'root_ca', 'inter_ca', 'leaf'
    :param config: конфигурация политик
    :return: список ошибок
    """
    cfg = config or get_policy_config()
    errors = []

    if key_type == "rsa":
        if cert_type == "root_ca":
            min_bits = cfg.root_ca_rsa_min_bits
        elif cert_type == "inter_ca":
            min_bits = cfg.inter_ca_rsa_min_bits
        else:
            min_bits = cfg.leaf_rsa_min_bits

        if key_size < min_bits:
            errors.append(
                f"RSA-ключ {key_size} бит не соответствует минимуму "
                f"{min_bits} бит для {cert_type}."
            )

    elif key_type == "ecc":
        if cert_type in ("root_ca", "inter_ca"):
            min_bits = cfg.root_ca_ecc_min_bits
        else:
            min_bits = cfg.leaf_ecc_min_bits

        if key_size < min_bits:
            errors.append(
                f"ECC-ключ {key_size} бит не соответствует минимуму "
                f"{min_bits} бит для {cert_type}."
            )

    return errors


# ---------------------------------------------------------------------------
# POL-4: Контроль срока действия
# ---------------------------------------------------------------------------

def validate_validity_days(
    validity_days: int,
    cert_type: str,
    config: Optional[PolicyConfig] = None,
) -> list[str]:
    """
    Проверяет срок действия согласно политике (POL-4).

    :param validity_days: запрошенный срок в днях
    :param cert_type: 'root_ca', 'inter_ca', 'leaf'
    :param config: конфигурация политик
    :return: список ошибок
    """
    cfg = config or get_policy_config()
    errors = []

    if cert_type == "root_ca":
        max_days = cfg.root_ca_max_days
    elif cert_type == "inter_ca":
        max_days = cfg.inter_ca_max_days
    else:
        max_days = cfg.leaf_max_days

    if validity_days > max_days:
        errors.append(
            f"Срок действия {validity_days} дней превышает максимум "
            f"{max_days} дней для {cert_type}."
        )

    return errors


# ---------------------------------------------------------------------------
# POL-5: Проверка SAN
# ---------------------------------------------------------------------------

def validate_san_policy(
    san_entries: list[tuple[str, str]],
    template_name: str,
    config: Optional[PolicyConfig] = None,
) -> list[str]:
    """
    Проверяет SAN согласно политике шаблона (POL-5).

    :param san_entries: список (тип, значение)
    :param template_name: 'server', 'client', 'code_signing'
    :param config: конфигурация политик
    :return: список ошибок
    """
    cfg = config or get_policy_config()
    errors = []

    # Разрешённые типы SAN по шаблону
    allowed_types = {
        "server": {"dns", "ip"},
        "client": {"email", "dns"},
        "code_signing": {"dns", "uri"},
    }

    template_allowed = allowed_types.get(template_name, set())

    for san_type, san_value in san_entries:
        # Проверка типа
        if san_type not in template_allowed:
            errors.append(
                f"Тип SAN '{san_type}' запрещён для шаблона '{template_name}'. "
                f"Допустимые: {sorted(template_allowed)}"
            )

        # Проверка wildcard (POL-5)
        if san_type == "dns" and san_value.startswith("*."):
            if not cfg.allow_wildcards:
                errors.append(
                    f"Wildcard SAN '{san_value}' запрещён политикой. "
                    f"Используйте конкретное доменное имя."
                )

    return errors


def validate_san_in_csr(
    csr: x509.CertificateSigningRequest,
    template_name: str,
    config: Optional[PolicyConfig] = None,
) -> list[str]:
    """
    Проверяет SAN в CSR согласно политике (POL-5).

    :param csr: объект CSR
    :param template_name: имя шаблона
    :param config: конфигурация политик
    :return: список ошибок
    """
    try:
        san_ext = csr.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        san_entries = []
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                san_entries.append(("dns", name.value))
            elif isinstance(name, x509.IPAddress):
                san_entries.append(("ip", str(name.value)))
            elif isinstance(name, x509.RFC822Name):
                san_entries.append(("email", name.value))
            elif isinstance(name, x509.UniformResourceIdentifier):
                san_entries.append(("uri", name.value))
        return validate_san_policy(san_entries, template_name, config)
    except x509.ExtensionNotFound:
        return []


# ---------------------------------------------------------------------------
# POL-6: Контроль алгоритмов подписи
# ---------------------------------------------------------------------------

def validate_csr_signature_algorithm(
    csr: x509.CertificateSigningRequest,
) -> list[str]:
    """
    Проверяет алгоритм подписи CSR (POL-6).

    :param csr: объект CSR
    :return: список ошибок
    """
    errors = []
    sig_hash = csr.signature_hash_algorithm

    if sig_hash is None:
        errors.append("CSR не содержит алгоритма хеширования подписи.")
        return errors

    algo_name = sig_hash.name.lower()

    # SHA-1 запрещён
    if "sha1" in algo_name or algo_name == "sha-1":
        errors.append(
            f"Алгоритм подписи SHA-1 запрещён политикой. "
            f"Используйте SHA-256 или выше."
        )

    # Проверяем соответствие алгоритма и ключа
    pub = csr.public_key()
    if isinstance(pub, ec_mod.EllipticCurvePublicKey):
        curve_bits = _get_ecc_bits(pub)
        if curve_bits == 384 and "sha256" in algo_name:
            # P-384 должен использовать SHA-384
            errors.append(
                f"Для P-384 ключа рекомендуется SHA-384, получен {sig_hash.name}."
            )

    return errors


# ---------------------------------------------------------------------------
# POL-7: Контроль pathLen
# ---------------------------------------------------------------------------

def validate_pathlen(
    pathlen: int,
    config: Optional[PolicyConfig] = None,
) -> list[str]:
    """
    Проверяет pathLenConstraint для промежуточного CA (POL-7).

    :param pathlen: запрошенное значение pathLen
    :param config: конфигурация политик
    :return: список ошибок
    """
    cfg = config or get_policy_config()
    errors = []

    if pathlen > cfg.inter_ca_max_pathlen:
        errors.append(
            f"pathLen={pathlen} запрещён политикой. "
            f"Максимальное допустимое значение: {cfg.inter_ca_max_pathlen}. "
            f"Промежуточный CA не может выпускать подчинённые CA."
        )

    return errors


# ---------------------------------------------------------------------------
# Комплексная проверка при выпуске листового сертификата
# ---------------------------------------------------------------------------

def validate_leaf_issuance(
    key_type: str,
    key_size: int,
    validity_days: int,
    san_entries: list[tuple[str, str]],
    template_name: str,
    config: Optional[PolicyConfig] = None,
) -> list[str]:
    """
    Выполняет все проверки политик при выпуске листового сертификата.

    :param key_type: 'rsa' или 'ecc'
    :param key_size: размер ключа в битах
    :param validity_days: срок действия
    :param san_entries: список SAN
    :param template_name: шаблон
    :param config: конфигурация политик
    :return: список всех ошибок
    """
    errors = []
    errors.extend(validate_private_key_size(key_type, key_size, "leaf", config))
    errors.extend(validate_validity_days(validity_days, "leaf", config))
    errors.extend(validate_san_policy(san_entries, template_name, config))
    return errors


def validate_csr_issuance(
    csr: x509.CertificateSigningRequest,
    validity_days: int,
    template_name: str,
    config: Optional[PolicyConfig] = None,
) -> list[str]:
    """
    Выполняет все проверки политик при выпуске из CSR.

    :param csr: объект CSR
    :param validity_days: срок действия
    :param template_name: шаблон
    :param config: конфигурация политик
    :return: список всех ошибок
    """
    errors = []

    # Проверяем ключ из CSR
    pub = csr.public_key()
    errors.extend(validate_key_size_for_cert_type(pub, "leaf", config))

    # Срок действия
    errors.extend(validate_validity_days(validity_days, "leaf", config))

    # SAN
    errors.extend(validate_san_in_csr(csr, template_name, config))

    # Алгоритм подписи
    errors.extend(validate_csr_signature_algorithm(csr))

    return errors