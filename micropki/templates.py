"""
Шаблоны сертификатов для конечных субъектов.

Определяет три шаблона: server, client, code_signing.
Каждый шаблон задаёт набор расширений X.509v3,
допустимые типы SAN и требования к их наличию.
"""

from dataclasses import dataclass, field
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec


@dataclass(frozen=True)
class CertificateTemplate:
    """Описание шаблона сертификата."""

    name: str
    extended_key_usages: list[x509.ObjectIdentifier]
    san_required: bool
    allowed_san_types: list[str]
    key_encipherment_for_rsa: bool = False


SERVER_TEMPLATE = CertificateTemplate(
    name="server",
    extended_key_usages=[ExtendedKeyUsageOID.SERVER_AUTH],
    san_required=True,
    allowed_san_types=["dns", "ip"],
    key_encipherment_for_rsa=True,
)

CLIENT_TEMPLATE = CertificateTemplate(
    name="client",
    extended_key_usages=[ExtendedKeyUsageOID.CLIENT_AUTH],
    san_required=False,
    allowed_san_types=["email", "dns"],
    key_encipherment_for_rsa=False,
)

CODE_SIGNING_TEMPLATE = CertificateTemplate(
    name="code_signing",
    extended_key_usages=[ExtendedKeyUsageOID.CODE_SIGNING],
    san_required=False,
    allowed_san_types=["dns", "uri"],
    key_encipherment_for_rsa=False,
)

TEMPLATES: dict[str, CertificateTemplate] = {
    "server": SERVER_TEMPLATE,
    "client": CLIENT_TEMPLATE,
    "code_signing": CODE_SIGNING_TEMPLATE,
}


def get_template(name: str) -> CertificateTemplate:
    """
    Возвращает шаблон по имени.

    :param name: имя шаблона (server, client, code_signing)
    :raises ValueError: если шаблон не найден
    """
    if name not in TEMPLATES:
        raise ValueError(
            f"Неизвестный шаблон: '{name}'. "
            f"Доступные: {sorted(TEMPLATES.keys())}"
        )
    return TEMPLATES[name]


def build_key_usage(template: CertificateTemplate, key_type: str) -> x509.KeyUsage:
    """
    Строит расширение KeyUsage на основе шаблона и типа ключа.

    Для серверного шаблона с RSA добавляется keyEncipherment.

    :param template: шаблон сертификата
    :param key_type: 'rsa' или 'ecc'
    :return: объект x509.KeyUsage
    """
    use_key_encipherment = (
        template.key_encipherment_for_rsa and key_type == "rsa"
    )

    return x509.KeyUsage(
        digital_signature=True,
        key_encipherment=use_key_encipherment,
        content_commitment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def validate_san_types(
    template: CertificateTemplate,
    san_entries: list[tuple[str, str]],
) -> list[str]:
    """
    Проверяет, допустимы ли указанные типы SAN для данного шаблона.

    :param template: шаблон сертификата
    :param san_entries: список кортежей (тип, значение), например [("dns", "example.com")]
    :return: список ошибок (пустой = всё ок)
    """
    errors: list[str] = []

    for san_type, san_value in san_entries:
        if san_type not in template.allowed_san_types:
            errors.append(
                f"Тип SAN '{san_type}' не допускается для шаблона "
                f"'{template.name}'. Допустимые: {template.allowed_san_types}"
            )

    if template.san_required and not san_entries:
        errors.append(
            f"Шаблон '{template.name}' требует хотя бы одну запись SAN."
        )

    return errors