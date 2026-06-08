"""
Модуль для работы с запросами на сертификат (CSR / PKCS#10).

Содержит:
- генерацию CSR для промежуточного УЦ
- парсинг и валидацию CSR
- проверку подписи CSR
"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.exceptions import InvalidSignature


def build_intermediate_csr(
    private_key: PrivateKeyTypes,
    subject: x509.Name,
    path_length: int,
    key_type: str,
) -> x509.CertificateSigningRequest:
    """
    Создаёт CSR (PKCS#10) для промежуточного удостоверяющего центра.

    :param private_key: закрытый ключ промежуточного CA
    :param subject: DN субъекта промежуточного CA
    :param path_length: ограничение длины пути (pathLenConstraint)
    :param key_type: 'rsa' или 'ecc' — для выбора алгоритма хеширования
    :return: объект CSR
    """
    if key_type == "rsa":
        signing_hash = hashes.SHA256()
    elif key_type == "ecc":
        signing_hash = hashes.SHA384()
    else:
        raise ValueError(f"Неподдерживаемый тип ключа: {key_type}")

    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
    )

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=path_length),
        critical=True,
    )

    csr = builder.sign(
        private_key=private_key,
        algorithm=signing_hash,
    )

    return csr


def serialize_csr_pem(csr: x509.CertificateSigningRequest) -> bytes:
    """
    Сериализует CSR в формат PEM.

    :param csr: объект CSR
    :return: байты PEM-файла
    """
    return csr.public_bytes(serialization.Encoding.PEM)


def verify_csr_signature(csr: x509.CertificateSigningRequest) -> bool:
    """
    Проверяет самоподпись CSR (proof-of-possession).

    Работает со всеми версиями cryptography >= 38.

    :param csr: объект CSR
    :return: True если подпись верна
    :raises ValueError: если подпись неверна или тип ключа не поддерживается
    """
    pub = csr.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(
                csr.signature,
                csr.tbs_certrequest_bytes,
                padding.PKCS1v15(),
                csr.signature_hash_algorithm,
            )
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(
                csr.signature,
                csr.tbs_certrequest_bytes,
                ECDSA(csr.signature_hash_algorithm),
            )
        else:
            raise ValueError(
                f"Неподдерживаемый тип ключа в CSR: {type(pub)}"
            )
    except InvalidSignature as e:
        raise ValueError(f"Подпись CSR недействительна: {e}") from e

    return True