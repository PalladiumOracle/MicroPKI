"""
Клиентская логика MicroPKI (спринт 6).

Содержит:
- gen_csr           — генерация закрытого ключа и CSR (CLI-25)
- request_cert      — отправка CSR в CA через API (CLI-26)
- validate_cert     — проверка цепочки сертификатов (CLI-27)
- check_status      — проверка статуса отзыва (CLI-28)
"""

import datetime
import logging
import os
import platform
import sys
from pathlib import Path
from typing import Optional
from urllib.request import urlopen, Request as UrllibRequest
from urllib.error import URLError, HTTPError
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID

from micropki.crypto_utils import (
    generate_private_key,
    serialize_private_key_pem_unencrypted,
    save_key_file,
)
from micropki.certificates import parse_subject_dn, parse_san_entries, build_san_extension
from micropki.validation import validate_chain, ValidationResult
from micropki.revocation_check import (
    check_revocation,
    check_ocsp,
    check_crl,
    RevocationStatus,
    RevocationResult,
    extract_ocsp_urls,
    extract_crl_urls,
)

logger = logging.getLogger("micropki")

CLIENT_LOG_NAME = "micropki.client"
client_logger = logging.getLogger(CLIENT_LOG_NAME)


def _setup_client_logger(log_file: Optional[Path] = None) -> None:
    """Настраивает логгер клиента (LOG-14)."""
    cl = logging.getLogger(CLIENT_LOG_NAME)
    if cl.handlers:
        return
    cl.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)s [client] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(str(log_file), mode="a", encoding="utf-8")
    else:
        home_log = Path.home() / ".micropki" / "client.log"
        try:
            home_log.parent.mkdir(parents=True, exist_ok=True)
            handler = logging.FileHandler(str(home_log), mode="a", encoding="utf-8")
        except OSError:
            handler = logging.StreamHandler(sys.stderr)

    handler.setFormatter(fmt)
    cl.addHandler(handler)


# ---------------------------------------------------------------------------
# gen-csr (CLI-25)
# ---------------------------------------------------------------------------

def gen_csr(
    subject: str,
    san_strings: list[str],
    key_type: str = "rsa",
    key_size: int = 2048,
    out_key: Path = Path("./key.pem"),
    out_csr: Path = Path("./request.csr.pem"),
    log_file: Optional[Path] = None,
) -> tuple[Path, Path]:
    """
    Генерирует закрытый ключ и CSR.

    :param subject: DN субъекта
    :param san_strings: список SAN в формате 'тип:значение'
    :param key_type: 'rsa' или 'ecc'
    :param key_size: размер ключа
    :param out_key: файл для ключа
    :param out_csr: файл для CSR
    :param log_file: файл лога
    :return: (путь к ключу, путь к CSR)
    """
    _setup_client_logger(log_file)
    client_logger.info(
        "gen-csr: subject=%s key_type=%s key_size=%d", subject, key_type, key_size
    )

    # Генерация ключа
    private_key = generate_private_key(key_type, key_size)
    key_pem = serialize_private_key_pem_unencrypted(private_key)

    # Сохранение ключа с правами 0o600
    out_key.parent.mkdir(parents=True, exist_ok=True)
    out_key.write_bytes(key_pem)
    if platform.system() != "Windows":
        try:
            os.chmod(out_key, 0o600)
        except OSError as e:
            client_logger.warning("Не удалось установить права 0600 на %s: %s", out_key, e)

    print(
        f"\nПРЕДУПРЕЖДЕНИЕ: Закрытый ключ сохранён БЕЗ шифрования!\n"
        f"  Файл: {out_key}\n"
        f"  Защитите файл от несанкционированного доступа.\n",
        file=sys.stderr,
    )

    # Построение CSR
    subject_name = parse_subject_dn(subject)
    san_entries = parse_san_entries(san_strings) if san_strings else []

    if key_type == "rsa":
        signing_hash = hashes.SHA256()
    else:
        signing_hash = hashes.SHA384()

    builder = x509.CertificateSigningRequestBuilder().subject_name(subject_name)

    san_ext = build_san_extension(san_entries)
    if san_ext is not None:
        builder = builder.add_extension(san_ext, critical=False)

    csr = builder.sign(private_key=private_key, algorithm=signing_hash)
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    out_csr.parent.mkdir(parents=True, exist_ok=True)
    out_csr.write_bytes(csr_pem)

    client_logger.info(
        "gen-csr: ключ сохранён в %s, CSR сохранён в %s", out_key, out_csr
    )
    print(f"Закрытый ключ: {out_key}")
    print(f"CSR:           {out_csr}")

    return out_key, out_csr


# ---------------------------------------------------------------------------
# request-cert (CLI-26)
# ---------------------------------------------------------------------------

def request_cert(
    csr_path: Path,
    template: str,
    ca_url: str,
    out_cert: Path = Path("./cert.pem"),
    api_key: Optional[str] = None,
    log_file: Optional[Path] = None,
) -> Path:
    """
    Отправляет CSR в CA через HTTP API и получает подписанный сертификат.

    :param csr_path: путь к файлу CSR (PEM)
    :param template: шаблон (server, client, code_signing)
    :param ca_url: базовый URL репозитория
    :param out_cert: файл для сохранения сертификата
    :param api_key: API-ключ для аутентификации
    :param log_file: файл лога
    :return: путь к сохранённому сертификату
    """
    _setup_client_logger(log_file)
    client_logger.info(
        "request-cert: csr=%s template=%s ca_url=%s", csr_path, template, ca_url
    )

    csr_pem = csr_path.read_bytes()

    url = f"{ca_url.rstrip('/')}/request-cert?template={template}"

    headers = {
        "Content-Type": "application/x-pem-file",
        "Accept": "application/x-pem-file",
    }
    if api_key:
        headers["X-API-Key"] = api_key

    req = UrllibRequest(url, data=csr_pem, headers=headers, method="POST")

    try:
        with urlopen(req, timeout=30) as resp:
            status_code = resp.status
            cert_pem = resp.read()
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        client_logger.error(
            "request-cert: HTTP ошибка %d: %s", e.code, body
        )
        print(f"Ошибка HTTP {e.code}: {body}", file=sys.stderr)
        raise
    except URLError as e:
        client_logger.error("request-cert: сетевая ошибка: %s", e.reason)
        print(f"Сетевая ошибка: {e.reason}", file=sys.stderr)
        raise

    out_cert.parent.mkdir(parents=True, exist_ok=True)
    out_cert.write_bytes(cert_pem)

    client_logger.info(
        "request-cert: сертификат получен и сохранён в %s (HTTP %d)",
        out_cert, status_code,
    )
    print(f"Сертификат сохранён: {out_cert}")

    return out_cert


# ---------------------------------------------------------------------------
# validate (CLI-27)
# ---------------------------------------------------------------------------

def validate(
    cert_path: Path,
    untrusted_paths: list[Path],
    trusted_path: Path,
    crl_source: Optional[str] = None,
    ocsp_url: Optional[str] = None,
    mode: str = "full",
    validation_time: Optional[datetime.datetime] = None,
    log_file: Optional[Path] = None,
) -> ValidationResult:
    """
    Выполняет проверку цепочки сертификатов.

    :param cert_path: путь к конечному сертификату
    :param untrusted_paths: пути к промежуточным сертификатам
    :param trusted_path: путь к файлу доверенных корневых сертификатов
    :param crl_source: путь к CRL или URL (для full-режима)
    :param ocsp_url: URL OCSP-ответчика (для full-режима)
    :param mode: 'chain' или 'full'
    :param validation_time: время для проверки
    :param log_file: файл лога
    :return: ValidationResult
    """
    _setup_client_logger(log_file)
    client_logger.info(
        "validate: cert=%s mode=%s", cert_path, mode
    )

    # Загружаем сертификаты
    leaf = x509.load_pem_x509_certificate(cert_path.read_bytes())

    untrusted: list[x509.Certificate] = []
    for p in untrusted_paths:
        data = p.read_bytes()
        # Файл может содержать несколько сертификатов
        certs = _load_pem_bundle(data)
        untrusted.extend(certs)

    trusted_data = trusted_path.read_bytes()
    trusted = _load_pem_bundle(trusted_data)

    if not trusted:
        print("Ошибка: файл доверенных сертификатов пуст или не содержит сертификатов.",
              file=sys.stderr)
        return ValidationResult(
            success=False,
            error="Файл доверенных сертификатов пуст",
        )

    check_rev = (mode == "full") and (
        crl_source is not None or ocsp_url is not None
        or extract_ocsp_urls(leaf) or extract_crl_urls(leaf)
    )

    result = validate_chain(
        leaf=leaf,
        untrusted=untrusted,
        trusted=trusted,
        validation_time=validation_time,
        check_revocation=False,  # проверяем отдельно ниже
    )

    # Дополнительная проверка отзыва в full-режиме
    if result.success and check_rev:
        # Находим издателя листового сертификата
        issuer_cert = _find_issuer(leaf, untrusted + trusted)
        if issuer_cert:
            prefer_ocsp = ocsp_url is not None or bool(extract_ocsp_urls(leaf))
            rev_result = check_revocation(
                cert=leaf,
                issuer_cert=issuer_cert,
                ocsp_url=ocsp_url,
                crl_source=crl_source,
                prefer_ocsp=prefer_ocsp,
            )

            if rev_result.fallback_used:
                client_logger.warning(
                    "validate: OCSP недоступен, использован CRL (fallback). %s",
                    rev_result.message,
                )

            if rev_result.status == RevocationStatus.REVOKED:
                result.success = False
                result.error = (
                    f"Сертификат ОТОЗВАН. {rev_result.message}"
                )
                client_logger.info(
                    "validate: сертификат отозван. method=%s reason=%s",
                    rev_result.method, rev_result.reason,
                )
            elif rev_result.status == RevocationStatus.UNKNOWN:
                client_logger.warning(
                    "validate: статус отзыва неизвестен. %s", rev_result.message
                )
                # Не считаем ошибкой — статус unknown
            else:
                client_logger.info(
                    "validate: статус отзыва good (method=%s)", rev_result.method
                )

    client_logger.info(
        "validate: результат=%s", "SUCCESS" if result.success else "FAILED"
    )
    return result


def _find_issuer(
    cert: x509.Certificate,
    candidates: list[x509.Certificate],
) -> Optional[x509.Certificate]:
    """Ищет издателя сертификата среди кандидатов."""
    for c in candidates:
        if c.subject == cert.issuer:
            return c
    return None


def _load_pem_bundle(data: bytes) -> list[x509.Certificate]:
    """Загружает все сертификаты из PEM-файла (может быть цепочка)."""
    certs = []
    delimiter = b"-----BEGIN CERTIFICATE-----"
    end_delimiter = b"-----END CERTIFICATE-----"
    parts = data.split(delimiter)
    for part in parts[1:]:
        end_idx = part.find(end_delimiter)
        if end_idx == -1:
            continue
        pem_block = delimiter + part[: end_idx + len(end_delimiter)]
        try:
            cert = x509.load_pem_x509_certificate(pem_block)
            certs.append(cert)
        except Exception as e:
            logger.warning("Ошибка загрузки сертификата из bundle: %s", e)
    return certs


# ---------------------------------------------------------------------------
# check-status (CLI-28)
# ---------------------------------------------------------------------------

def check_status(
    cert_path: Path,
    ca_cert_path: Path,
    crl_source: Optional[str] = None,
    ocsp_url: Optional[str] = None,
    log_file: Optional[Path] = None,
) -> RevocationResult:
    """
    Проверяет статус отзыва сертификата (OCSP → CRL fallback).

    :param cert_path: путь к сертификату
    :param ca_cert_path: путь к сертификату издателя
    :param crl_source: путь к CRL или URL (опционально)
    :param ocsp_url: URL OCSP-ответчика (опционально)
    :param log_file: файл лога
    :return: RevocationResult
    """
    _setup_client_logger(log_file)
    client_logger.info(
        "check-status: cert=%s ca=%s ocsp_url=%s crl=%s",
        cert_path, ca_cert_path, ocsp_url, crl_source,
    )

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    issuer_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())

    prefer_ocsp = ocsp_url is not None or bool(extract_ocsp_urls(cert))

    result = check_revocation(
        cert=cert,
        issuer_cert=issuer_cert,
        ocsp_url=ocsp_url,
        crl_source=crl_source,
        prefer_ocsp=prefer_ocsp,
    )

    if result.fallback_used:
        client_logger.warning(
            "check-status: OCSP недоступен, использован CRL (fallback). %s",
            result.message,
        )

    client_logger.info(
        "check-status: статус=%s method=%s reason=%s",
        result.status.value, result.method, result.reason,
    )

    return result