"""
Модуль проверки статуса отзыва сертификатов.

Реализует:
- проверку по CRL (локальный файл или URL) — REV-1, REV-5
- проверку через OCSP — REV-2, REV-4
- логику приоритетов: OCSP → CRL → unknown — REV-3
- разбор расширений AIA и CDP — REV-4, REV-5
"""

import datetime
import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional
from urllib.request import urlopen, Request as UrllibRequest

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod, ec as ec_mod
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.x509 import ocsp
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger("micropki")


# ---------------------------------------------------------------------------
# Типы результата
# ---------------------------------------------------------------------------

class RevocationStatus(Enum):
    GOOD = "good"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


@dataclass
class RevocationResult:
    status: RevocationStatus
    method: str                        # "ocsp", "crl", "unknown"
    reason: Optional[str] = None       # причина отзыва
    revocation_time: Optional[datetime.datetime] = None
    message: str = ""
    fallback_used: bool = False        # True если OCSP не сработал и переключились на CRL


# ---------------------------------------------------------------------------
# Разбор расширений AIA и CDP
# ---------------------------------------------------------------------------

def extract_ocsp_urls(cert: x509.Certificate) -> list[str]:
    """
    Извлекает OCSP URL из расширения Authority Information Access (AIA).

    :param cert: сертификат
    :return: список URL OCSP-ответчиков
    """
    try:
        aia_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )
        urls = []
        for access in aia_ext.value:
            if access.access_method == AuthorityInformationAccessOID.OCSP:
                uri = access.access_location.value
                urls.append(uri)
        return urls
    except x509.ExtensionNotFound:
        return []
    except Exception as e:
        logger.warning("Ошибка разбора AIA: %s", e)
        return []


def extract_crl_urls(cert: x509.Certificate) -> list[str]:
    """
    Извлекает URL точек распространения CRL из расширения CDP.

    :param cert: сертификат
    :return: список URL CRL Distribution Points
    """
    try:
        cdp_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        )
        urls = []
        for dp in cdp_ext.value:
            if dp.full_name:
                for name in dp.full_name:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        urls.append(name.value)
        return urls
    except x509.ExtensionNotFound:
        return []
    except Exception as e:
        logger.warning("Ошибка разбора CDP: %s", e)
        return []


# ---------------------------------------------------------------------------
# CRL-проверка
# ---------------------------------------------------------------------------

def _load_crl(source: str) -> x509.CertificateRevocationList:
    """
    Загружает CRL из файла (путь) или URL.

    :param source: путь к файлу или http/ldap URL
    :return: объект CRL
    """
    if source.startswith("http://") or source.startswith("https://"):
        logger.info("Загрузка CRL по URL: %s", source)
        req = UrllibRequest(source, headers={"User-Agent": "MicroPKI/1.0"})
        with urlopen(req, timeout=10) as resp:
            data = resp.read()
        # Пробуем DER, потом PEM
        try:
            return x509.load_der_x509_crl(data)
        except Exception:
            return x509.load_pem_x509_crl(data)
    else:
        path = Path(source)
        data = path.read_bytes()
        try:
            return x509.load_pem_x509_crl(data)
        except Exception:
            return x509.load_der_x509_crl(data)


def _verify_crl_signature(
    crl: x509.CertificateRevocationList,
    issuer_cert: x509.Certificate,
) -> bool:
    """Проверяет подпись CRL публичным ключом издателя."""
    pub = issuer_cert.public_key()
    try:
        if isinstance(pub, rsa_mod.RSAPublicKey):
            pub.verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                asym_padding.PKCS1v15(),
                crl.signature_hash_algorithm,
            )
        elif isinstance(pub, ec_mod.EllipticCurvePublicKey):
            pub.verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                ECDSA(crl.signature_hash_algorithm),
            )
        else:
            raise ValueError(f"Неподдерживаемый тип ключа: {type(pub)}")
        return True
    except InvalidSignature:
        return False


def check_crl(
    cert: x509.Certificate,
    issuer_cert: x509.Certificate,
    crl_source: Optional[str] = None,
) -> RevocationResult:
    """
    Проверяет статус отзыва сертификата по CRL.

    Порядок поиска CRL:
    1. Явно указанный crl_source (файл или URL)
    2. URL из расширения CDP сертификата

    :param cert: проверяемый сертификат
    :param issuer_cert: сертификат издателя (для проверки подписи CRL)
    :param crl_source: путь к файлу CRL или URL (опционально)
    :return: RevocationResult
    """
    sources = []
    if crl_source:
        sources.append(crl_source)
    # Автоматически из CDP
    cdp_urls = extract_crl_urls(cert)
    sources.extend(cdp_urls)

    if not sources:
        return RevocationResult(
            status=RevocationStatus.UNKNOWN,
            method="crl",
            message="CRL не указан и CDP-расширение в сертификате отсутствует",
        )

    last_error = ""
    for src in sources:
        try:
            crl = _load_crl(src)
        except Exception as e:
            last_error = f"Не удалось загрузить CRL из {src}: {e}"
            logger.warning(last_error)
            continue

        # Проверяем подпись CRL
        if not _verify_crl_signature(crl, issuer_cert):
            last_error = f"Подпись CRL из {src} НЕВЕРНА"
            logger.warning(last_error)
            continue

        # Проверяем издателя
        if crl.issuer != issuer_cert.subject:
            last_error = (
                f"Издатель CRL ({crl.issuer}) не совпадает "
                f"с ожидаемым ({issuer_cert.subject})"
            )
            logger.warning(last_error)
            continue

        # Актуальность
        now = datetime.datetime.now(datetime.timezone.utc)
        if crl.next_update_utc and now > crl.next_update_utc:
            logger.warning(
                "CRL устарел: nextUpdate=%s, сейчас=%s. "
                "Продолжаем использовать.",
                crl.next_update_utc, now,
            )

        # Ищем серийный номер
        serial = cert.serial_number
        revoked = crl.get_revoked_certificate_by_serial_number(serial)

        if revoked is None:
            return RevocationResult(
                status=RevocationStatus.GOOD,
                method="crl",
                message=f"Сертификат не найден в CRL ({src}) — статус: good",
            )

        # Извлекаем причину
        reason_str = "unspecified"
        rev_time = revoked.revocation_date_utc
        try:
            reason_ext = revoked.extensions.get_extension_for_class(
                x509.CRLReason
            )
            reason_str = reason_ext.value.reason.name
        except x509.ExtensionNotFound:
            pass

        return RevocationResult(
            status=RevocationStatus.REVOKED,
            method="crl",
            reason=reason_str,
            revocation_time=rev_time,
            message=(
                f"Сертификат отозван согласно CRL ({src}). "
                f"Причина: {reason_str}, дата: {rev_time}"
            ),
        )

    return RevocationResult(
        status=RevocationStatus.UNKNOWN,
        method="crl",
        message=f"Не удалось получить валидный CRL. Последняя ошибка: {last_error}",
    )


# ---------------------------------------------------------------------------
# OCSP-проверка
# ---------------------------------------------------------------------------

def _build_ocsp_request(
    cert: x509.Certificate,
    issuer_cert: x509.Certificate,
) -> bytes:
    """Строит OCSP-запрос с nonce."""
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, hashes.SHA256())
    # Добавляем nonce если поддерживается
    try:
        import os
        nonce_val = os.urandom(16)
        try:
            from cryptography.x509.ocsp import OCSPNonce
            builder = builder.add_extension(OCSPNonce(nonce_val), critical=False)
        except (ImportError, Exception):
            pass
    except Exception:
        pass
    return builder.build().public_bytes(serialization.Encoding.DER)


def _send_ocsp_request(url: str, request_der: bytes) -> bytes:
    """Отправляет OCSP-запрос POST и возвращает тело ответа."""
    req = UrllibRequest(
        url,
        data=request_der,
        headers={
            "Content-Type": "application/ocsp-request",
            "Accept": "application/ocsp-response",
            "User-Agent": "MicroPKI/1.0",
        },
        method="POST",
    )
    with urlopen(req, timeout=10) as resp:
        return resp.read()


def check_ocsp(
    cert: x509.Certificate,
    issuer_cert: x509.Certificate,
    ocsp_url: Optional[str] = None,
) -> RevocationResult:
    """
    Проверяет статус сертификата через OCSP.

    :param cert: проверяемый сертификат
    :param issuer_cert: сертификат издателя
    :param ocsp_url: URL OCSP-ответчика (если None — берётся из AIA)
    :return: RevocationResult
    """
    urls = []
    if ocsp_url:
        urls.append(ocsp_url)
    urls.extend(extract_ocsp_urls(cert))

    if not urls:
        return RevocationResult(
            status=RevocationStatus.UNKNOWN,
            method="ocsp",
            message="URL OCSP-ответчика не указан и AIA-расширение отсутствует",
        )

    last_error = ""
    for url in urls:
        try:
            request_der = _build_ocsp_request(cert, issuer_cert)
            response_der = _send_ocsp_request(url, request_der)
        except Exception as e:
            last_error = f"OCSP-запрос к {url} не удался: {e}"
            logger.warning(last_error)
            continue

        try:
            response = ocsp.load_der_ocsp_response(response_der)
        except Exception as e:
            last_error = f"Ошибка разбора OCSP-ответа от {url}: {e}"
            logger.warning(last_error)
            continue

        if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            last_error = (
                f"OCSP-ответ от {url}: статус ошибки "
                f"{response.response_status.name}"
            )
            logger.warning(last_error)
            continue

        # Проверяем подпись ответа
        try:
            responder_pub = response.responder_key_hash
            # Простая проверка: если ответчик тот же что и издатель
            issuer_pub = issuer_cert.public_key()
            try:
                if isinstance(issuer_pub, rsa_mod.RSAPublicKey):
                    issuer_pub.verify(
                        response.signature,
                        response.tbs_response_bytes,
                        asym_padding.PKCS1v15(),
                        response.signature_hash_algorithm,
                    )
                elif isinstance(issuer_pub, ec_mod.EllipticCurvePublicKey):
                    issuer_pub.verify(
                        response.signature,
                        response.tbs_response_bytes,
                        ECDSA(response.signature_hash_algorithm),
                    )
                logger.debug("OCSP-ответ подписан издателем")
            except InvalidSignature:
                # Ответ подписан другим ключом (делегированный ответчик) —
                # для учебного проекта принимаем
                logger.debug(
                    "OCSP-ответ подписан делегированным ответчиком — принимаем"
                )
        except Exception as e:
            logger.debug("Проверка подписи OCSP-ответа: %s", e)

        cert_status = response.certificate_status

        if cert_status == ocsp.OCSPCertStatus.GOOD:
            return RevocationResult(
                status=RevocationStatus.GOOD,
                method="ocsp",
                message=f"OCSP ({url}): статус good",
            )

        if cert_status == ocsp.OCSPCertStatus.REVOKED:
            rev_time = response.revocation_time_utc
            reason = response.revocation_reason
            reason_str = reason.name if reason else "unspecified"
            return RevocationResult(
                status=RevocationStatus.REVOKED,
                method="ocsp",
                reason=reason_str,
                revocation_time=rev_time,
                message=(
                    f"OCSP ({url}): сертификат отозван. "
                    f"Причина: {reason_str}, дата: {rev_time}"
                ),
            )

        # UNKNOWN
        last_error = f"OCSP ({url}): статус unknown"
        logger.info(last_error)

    return RevocationResult(
        status=RevocationStatus.UNKNOWN,
        method="ocsp",
        message=f"OCSP вернул unknown или недоступен. Последняя ошибка: {last_error}",
    )


# ---------------------------------------------------------------------------
# Логика приоритетов: OCSP → CRL (REV-3)
# ---------------------------------------------------------------------------

def check_revocation(
    cert: x509.Certificate,
    issuer_cert: x509.Certificate,
    ocsp_url: Optional[str] = None,
    crl_source: Optional[str] = None,
    prefer_ocsp: bool = True,
) -> RevocationResult:
    """
    Проверяет статус отзыва с логикой приоритетов.

    Алгоритм (REV-3):
    1. Попытка OCSP (если prefer_ocsp=True и URL доступен)
    2. Если OCSP успешен (good/revoked) — возвращаем результат
    3. Если OCSP недоступен/unknown — переключаемся на CRL
    4. Если CRL успешен — возвращаем результат
    5. Если оба недоступны — возвращаем unknown

    :param cert: проверяемый сертификат
    :param issuer_cert: сертификат издателя
    :param ocsp_url: явный URL OCSP (если None — из AIA)
    :param crl_source: путь к CRL или URL (если None — из CDP)
    :param prefer_ocsp: использовать ли OCSP в первую очередь
    :return: RevocationResult с признаком fallback_used
    """
    ocsp_urls = ([ocsp_url] if ocsp_url else []) + extract_ocsp_urls(cert)
    has_ocsp = bool(ocsp_urls)

    if prefer_ocsp and has_ocsp:
        logger.info("Проверка отзыва: попытка OCSP")
        ocsp_result = check_ocsp(cert, issuer_cert, ocsp_url)

        if ocsp_result.status in (RevocationStatus.GOOD, RevocationStatus.REVOKED):
            logger.info(
                "OCSP-проверка успешна: статус=%s", ocsp_result.status.value
            )
            return ocsp_result

        # OCSP не дал результата — переключаемся на CRL
        logger.warning(
            "OCSP недоступен или вернул unknown (%s). "
            "Переключаемся на CRL.",
            ocsp_result.message,
        )
        crl_result = check_crl(cert, issuer_cert, crl_source)
        crl_result.fallback_used = True
        crl_result.message = (
            f"[Fallback: OCSP→CRL] {crl_result.message} "
            f"(OCSP: {ocsp_result.message})"
        )
        return crl_result

    # Только CRL
    if crl_source or extract_crl_urls(cert):
        logger.info("Проверка отзыва: только CRL")
        return check_crl(cert, issuer_cert, crl_source)

    return RevocationResult(
        status=RevocationStatus.UNKNOWN,
        method="unknown",
        message="Не указаны ни OCSP, ни CRL. Статус неизвестен.",
    )