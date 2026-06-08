"""
Модуль OCSP (Online Certificate Status Protocol).

Содержит:
- вычисление хешей издателя для сопоставления CertID
- определение статуса сертификата по БД
- построение подписанного OCSP-ответа (BasicOCSPResponse)
- обработку nonce
"""

import hashlib
import datetime
import logging
from typing import Optional, Any

from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod, ec as ec_mod

from micropki.repository import get_certificate_by_serial
from micropki.serial import serial_to_hex

logger = logging.getLogger("micropki")


def _get_signing_hash(private_key: PrivateKeyTypes) -> hashes.HashAlgorithm:
    """Возвращает алгоритм хеширования по типу ключа OCSP-ответчика."""
    if isinstance(private_key, rsa_mod.RSAPrivateKey):
        return hashes.SHA256()
    if isinstance(private_key, ec_mod.EllipticCurvePrivateKey):
        return hashes.SHA256()
    raise ValueError(f"Неподдерживаемый тип ключа: {type(private_key)}")


def _hash_data(algo: hashes.HashAlgorithm, data: bytes) -> bytes:
    """Хеширует данные указанным алгоритмом через hashlib."""
    name = algo.name.lower().replace("-", "")
    h = hashlib.new(name)
    h.update(data)
    return h.digest()


def compute_issuer_name_hash(
    ca_cert: x509.Certificate,
    algorithm: hashes.HashAlgorithm,
) -> bytes:
    """
    Вычисляет хеш DN субъекта издателя (DER-кодирование).

    """
    issuer_der = ca_cert.subject.public_bytes()
    return _hash_data(algorithm, issuer_der)


def compute_issuer_key_hash(
    ca_cert: x509.Certificate,
    algorithm: hashes.HashAlgorithm,
) -> bytes:
    """
    Вычисляет хеш открытого ключа издателя (raw BIT STRING value).

    """
    pub_key_der = ca_cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    raw_key = _extract_spki_bitstring(pub_key_der)
    return _hash_data(algorithm, raw_key)


def _extract_spki_bitstring(spki_der: bytes) -> bytes:
    """
    Извлекает raw bytes из BIT STRING в SubjectPublicKeyInfo DER.

    SubjectPublicKeyInfo ::= SEQUENCE {
        algorithm  AlgorithmIdentifier,
        publicKey  BIT STRING
    }
    Возвращает содержимое BIT STRING без unused-bits байта.
    """
    idx = 0

    # SEQUENCE
    assert spki_der[idx] == 0x30, "Ожидался тег SEQUENCE (0x30)"
    idx += 1
    idx += _asn1_length_size(spki_der, idx)

    # AlgorithmIdentifier (SEQUENCE)
    assert spki_der[idx] == 0x30, "Ожидался тег AlgorithmIdentifier SEQUENCE"
    idx += 1
    algo_len_size = _asn1_length_size(spki_der, idx)
    algo_len = _asn1_read_length(spki_der, idx)
    idx += algo_len_size + algo_len

    # BIT STRING
    assert spki_der[idx] == 0x03, "Ожидался тег BIT STRING (0x03)"
    idx += 1
    bs_len_size = _asn1_length_size(spki_der, idx)
    bs_len = _asn1_read_length(spki_der, idx)
    idx += bs_len_size

    idx += 1
    raw_key = spki_der[idx: idx + bs_len - 1]
    return raw_key


def _asn1_read_length(data: bytes, offset: int) -> int:
    """Читает длину ASN.1 TLV."""
    b = data[offset]
    if b < 0x80:
        return b
    num_bytes = b & 0x7F
    length = 0
    for i in range(num_bytes):
        length = (length << 8) | data[offset + 1 + i]
    return length


def _asn1_length_size(data: bytes, offset: int) -> int:
    """Возвращает количество байт, занимаемых полем длины."""
    b = data[offset]
    if b < 0x80:
        return 1
    return 1 + (b & 0x7F)


def get_cert_id_from_request(request: ocsp.OCSPRequest) -> Any:
    """
    Извлекает CertID из OCSP-запроса.

    :param request: разобранный OCSP-запрос
    :return: объект с атрибутами issuer_name_hash, issuer_key_hash,
             hash_algorithm, serial_number
    :raises ValueError: если не удалось найти нужные атрибуты
    """

    if hasattr(request, "serial_number") and hasattr(request, "issuer_name_hash"):
        return request

    # Старый API: отдельный объект cert_id
    if hasattr(request, "cert_id"):
        return request.cert_id

    # Итерируемый API
    try:
        single_requests = list(request)
        if single_requests:
            first = single_requests[0]
            if hasattr(first, "serial_number"):
                return first
            if hasattr(first, "cert_id"):
                return first.cert_id
    except TypeError:
        pass

    # Атрибут .requests
    if hasattr(request, "requests"):
        try:
            reqs = list(request.requests)
            if reqs:
                first = reqs[0]
                if hasattr(first, "serial_number"):
                    return first
                if hasattr(first, "cert_id"):
                    return first.cert_id
        except Exception:
            pass

    raise ValueError(
        f"Не удалось извлечь CertID из запроса. "
        f"Доступные атрибуты: "
        f"{[a for a in dir(request) if not a.startswith('_')]}"
    )


def _get_nonce_classes() -> list:
    """Возвращает возможные классы OCSPNonce для разных версий cryptography."""
    candidates = []

    try:
        from cryptography.x509.ocsp import OCSPNonce as N1
        candidates.append(N1)
    except ImportError:
        pass

    try:
        from cryptography.x509 import OCSPNonce as N2
        if N2 not in candidates:
            candidates.append(N2)
    except ImportError:
        pass

    return candidates


def _unwrap_nonce_value(raw: bytes) -> bytes:
    """
    Разворачивает DER OCTET STRING если нужно.

    Nonce может храниться как голые байты или как DER OCTET STRING.
    """
    if len(raw) >= 2 and raw[0] == 0x04:
        length = raw[1]
        if length < 0x80:
            return raw[2: 2 + length]
        num_len_bytes = length & 0x7F
        actual_len = int.from_bytes(raw[2: 2 + num_len_bytes], "big")
        return raw[2 + num_len_bytes: 2 + num_len_bytes + actual_len]
    return raw


def _extract_nonce(request: ocsp.OCSPRequest) -> Optional[bytes]:
    """
    Извлекает nonce из OCSP-запроса.


    :param request: OCSP-запрос
    :return: байты nonce или None если отсутствует
    """
    extensions = request.extensions

    for nonce_class in _get_nonce_classes():
        try:
            ext = extensions.get_extension_for_class(nonce_class)
            return ext.value.nonce
        except (x509.ExtensionNotFound, AttributeError, Exception):
            continue

    nonce_oid = x509.ObjectIdentifier("1.3.6.1.5.5.7.48.1.2")
    try:
        ext = extensions.get_extension_for_oid(nonce_oid)
        raw = (
            ext.value.value
            if hasattr(ext.value, "value")
            else bytes(ext.value)
        )
        return _unwrap_nonce_value(raw)
    except (x509.ExtensionNotFound, Exception):
        pass

    return None


def _add_nonce_to_builder(
    builder: ocsp.OCSPResponseBuilder,
    nonce_value: bytes,
) -> ocsp.OCSPResponseBuilder:
    """
    Добавляет nonce в OCSPResponseBuilder.


    :param builder: строитель OCSP-ответа
    :param nonce_value: байты nonce
    :return: обновлённый builder
    """
    for nonce_class in _get_nonce_classes():
        try:
            builder = builder.add_extension(
                nonce_class(nonce_value),
                critical=False,
            )
            logger.debug("Nonce добавлен через %s", nonce_class.__name__)
            return builder
        except Exception:
            continue

    nonce_oid = x509.ObjectIdentifier("1.3.6.1.5.5.7.48.1.2")
    try:
        if len(nonce_value) < 0x80:
            der_nonce = bytes([0x04, len(nonce_value)]) + nonce_value
        else:
            ln = len(nonce_value)
            lb = ln.to_bytes((ln.bit_length() + 7) // 8, "big")
            der_nonce = bytes([0x04, 0x80 | len(lb)]) + lb + nonce_value

        builder = builder.add_extension(
            x509.UnrecognizedExtension(nonce_oid, der_nonce),
            critical=False,
        )
        logger.debug("Nonce добавлен через UnrecognizedExtension")
        return builder
    except Exception as e:
        logger.warning("Не удалось добавить nonce в ответ: %s", e)

    return builder


class IssuerHashes:
    """Предвычисленные хеши для одного CA (SHA-1 и SHA-256)."""

    def __init__(self, ca_cert: x509.Certificate):
        self.ca_cert = ca_cert
        self._sha1_name = compute_issuer_name_hash(ca_cert, hashes.SHA1())
        self._sha1_key = compute_issuer_key_hash(ca_cert, hashes.SHA1())
        self._sha256_name = compute_issuer_name_hash(ca_cert, hashes.SHA256())
        self._sha256_key = compute_issuer_key_hash(ca_cert, hashes.SHA256())

        logger.debug(
            "IssuerHashes: sha1_name=%s sha1_key=%s",
            self._sha1_name.hex(), self._sha1_key.hex(),
        )

    def matches(self, cert_id: Any) -> bool:
        """
        Проверяет, соответствует ли CertID из запроса данному CA.

        cert_id — объект с атрибутами:
          .issuer_name_hash  (bytes)
          .issuer_key_hash   (bytes)
          .hash_algorithm    (hashes.HashAlgorithm)
          .serial_number     (int)
        """
        req_name_hash = cert_id.issuer_name_hash
        req_key_hash = cert_id.issuer_key_hash
        algo_name = cert_id.hash_algorithm.name.lower().replace("-", "")

        if algo_name == "sha1":
            match = (
                req_name_hash == self._sha1_name
                and req_key_hash == self._sha1_key
            )
        elif algo_name == "sha256":
            match = (
                req_name_hash == self._sha256_name
                and req_key_hash == self._sha256_key
            )
        else:
            try:
                algo = cert_id.hash_algorithm
                name_hash = compute_issuer_name_hash(self.ca_cert, algo)
                key_hash = compute_issuer_key_hash(self.ca_cert, algo)
                match = (
                    req_name_hash == name_hash
                    and req_key_hash == key_hash
                )
            except Exception as e:
                logger.warning(
                    "Ошибка вычисления хешей для алгоритма %s: %s",
                    algo_name, e,
                )
                return False

        logger.debug(
            "IssuerHashes.matches: algo=%s req_name=%s req_key=%s match=%s",
            algo_name,
            req_name_hash.hex(),
            req_key_hash.hex(),
            match,
        )
        return match


def _parse_reason(reason_str: str) -> Optional[x509.ReasonFlags]:
    """Конвертирует строку причины отзыва в ReasonFlags."""
    mapping = {
        "unspecified":          x509.ReasonFlags.unspecified,
        "keycompromise":        x509.ReasonFlags.key_compromise,
        "cacompromise":         x509.ReasonFlags.ca_compromise,
        "affiliationchanged":   x509.ReasonFlags.affiliation_changed,
        "superseded":           x509.ReasonFlags.superseded,
        "cessationofoperation": x509.ReasonFlags.cessation_of_operation,
        "certificatehold":      x509.ReasonFlags.certificate_hold,
        "removefromcrl":        x509.ReasonFlags.remove_from_crl,
        "privilegewithdrawn":   x509.ReasonFlags.privilege_withdrawn,
        "aacompromise":         x509.ReasonFlags.aa_compromise,
    }
    key = reason_str.lower().replace("_", "").replace(" ", "")
    return mapping.get(key, x509.ReasonFlags.unspecified)


def determine_cert_status(
    db_path: str,
    serial_int: int,
    issuer_hashes: IssuerHashes,
    cert_id: Any,
) -> tuple:
    """
    Определяет статус сертификата по БД.

    :param db_path: путь к БД
    :param serial_int: серийный номер как целое число
    :param issuer_hashes: предвычисленные хеши издателя
    :param cert_id: CertID из запроса (duck typing)
    :return: кортеж (OCSPCertStatus, revocation_time | None, ReasonFlags | None)
    """
    # Проверяем что издатель соответствует нашему CA
    if not issuer_hashes.matches(cert_id):
        logger.info(
            "Издатель не распознан для серийного номера %016X", serial_int,
        )
        return ocsp.OCSPCertStatus.UNKNOWN, None, None

    serial_hex = serial_to_hex(serial_int)
    cert_data = get_certificate_by_serial(db_path, serial_hex)

    if cert_data is None:
        logger.info("Сертификат не найден в БД: serial=%s", serial_hex)
        return ocsp.OCSPCertStatus.UNKNOWN, None, None

    status = cert_data.get("status", "unknown")

    if status == "valid":
        return ocsp.OCSPCertStatus.GOOD, None, None

    if status == "revoked":
        rev_date_str = cert_data.get("revocation_date") or ""
        try:
            rev_date = datetime.datetime.strptime(
                rev_date_str, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=datetime.timezone.utc)
        except (ValueError, TypeError):
            rev_date = datetime.datetime.now(datetime.timezone.utc)

        reason_str = cert_data.get("revocation_reason") or "unspecified"
        reason_flag = _parse_reason(reason_str)
        return ocsp.OCSPCertStatus.REVOKED, rev_date, reason_flag

    # Просроченные — считаем good
    return ocsp.OCSPCertStatus.GOOD, None, None


def build_ocsp_response(
    request: ocsp.OCSPRequest,
    responder_cert: x509.Certificate,
    responder_key: PrivateKeyTypes,
    ca_cert: x509.Certificate,
    db_path: str,
    cache_ttl: int = 60,
) -> bytes:
    """
    Строит подписанный OCSP-ответ в DER-формате.

    Использует add_response_by_hash() для точного воспроизведения
    certID из запроса — включая серийный номер и хеши издателя.
    Это гарантирует корректный certID в ответе для любого статуса
    (good, revoked, unknown).

    :param request: разобранный OCSP-запрос
    :param responder_cert: сертификат OCSP-ответчика
    :param responder_key: закрытый ключ OCSP-ответчика
    :param ca_cert: сертификат выпускающего CA
    :param db_path: путь к БД
    :param cache_ttl: TTL в секундах (nextUpdate = thisUpdate + TTL)
    :return: DER-байты OCSPResponse
    """
    issuer_hashes = IssuerHashes(ca_cert)
    signing_hash = _get_signing_hash(responder_key)
    now = datetime.datetime.now(datetime.timezone.utc)
    next_update = now + datetime.timedelta(seconds=cache_ttl)

    # Извлекаем nonce
    nonce_value: Optional[bytes] = None
    try:
        nonce_value = _extract_nonce(request)
        if nonce_value is not None:
            logger.debug("OCSP nonce получен: %s", nonce_value.hex())
    except Exception as e:
        logger.debug("Nonce не извлечён: %s", e)

    # Извлекаем CertID из запроса
    cert_id = get_cert_id_from_request(request)
    serial_int = cert_id.serial_number
    serial_hex = serial_to_hex(serial_int)

    # Сохраняем хеши и алгоритм из запроса — используем их в ответе
    issuer_name_hash = cert_id.issuer_name_hash
    issuer_key_hash = cert_id.issuer_key_hash
    hash_algorithm = cert_id.hash_algorithm

    cert_status, revocation_time, revocation_reason = determine_cert_status(
        db_path=db_path,
        serial_int=serial_int,
        issuer_hashes=issuer_hashes,
        cert_id=cert_id,
    )

    logger.info("OCSP: serial=%s status=%s", serial_hex, cert_status.name)

    # add_response_by_hash — точно воспроизводит certID из запроса
    # без подстановки реального сертификата
    builder = (
        ocsp.OCSPResponseBuilder()
        .add_response_by_hash(
            issuer_name_hash=issuer_name_hash,
            issuer_key_hash=issuer_key_hash,
            serial_number=serial_int,
            algorithm=hash_algorithm,
            cert_status=cert_status,
            this_update=now,
            next_update=next_update,
            revocation_time=revocation_time,
            revocation_reason=revocation_reason,
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, responder_cert)
    )

    # Добавляем nonce если был в запросе
    if nonce_value is not None:
        builder = _add_nonce_to_builder(builder, nonce_value)

    response = builder.sign(responder_key, signing_hash)
    return response.public_bytes(serialization.Encoding.DER)


def build_error_response(status: ocsp.OCSPResponseStatus) -> bytes:
    """
    Строит OCSP-ответ об ошибке (без подписи).

    :param status: статус ошибки (malformedRequest, internalError и т.д.)
    :return: DER-байты OCSPResponse
    """
    response = ocsp.OCSPResponseBuilder.build_unsuccessful(status)
    return response.public_bytes(serialization.Encoding.DER)