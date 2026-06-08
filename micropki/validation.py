"""
Модуль проверки пути сертификации.

Содержит:
- построение цепочки сертификатов от конечного до доверенного корня
- базовые проверки: подпись, срок действия, BasicConstraints,
  pathLenConstraint, KeyUsage
- поддержку параметра validation_time
- структурированный результат ValidationResult
"""

import datetime
import logging
from dataclasses import dataclass, field
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod, ec as ec_mod, padding
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger("micropki")


# ---------------------------------------------------------------------------
# Структуры результата
# ---------------------------------------------------------------------------

@dataclass
class CertCheckResult:
    """Результат проверки одного сертификата."""
    subject: str
    passed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return len(self.failed) == 0


@dataclass
class ValidationResult:
    """Итоговый результат проверки цепочки."""
    success: bool
    chain: list[str] = field(default_factory=list)          # субъекты в порядке цепочки
    cert_results: list[CertCheckResult] = field(default_factory=list)
    error: Optional[str] = None

    def summary(self) -> str:
        lines = []
        status = "УСПЕХ" if self.success else "ОШИБКА"
        lines.append(f"Результат проверки цепочки: {status}")
        if self.chain:
            lines.append("Цепочка сертификатов:")
            for i, subj in enumerate(self.chain):
                lines.append(f"  [{i}] {subj}")
        for cr in self.cert_results:
            lines.append(f"\nСертификат: {cr.subject}")
            for p in cr.passed:
                lines.append(f"   {p}")
            for f in cr.failed:
                lines.append(f"   {f}")
        if self.error:
            lines.append(f"\nОшибка: {self.error}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------

def _subject_str(cert: x509.Certificate) -> str:
    """Возвращает строку субъекта сертификата."""
    try:
        return cert.subject.rfc4514_string()
    except Exception:
        return str(cert.subject)


def _issuer_str(cert: x509.Certificate) -> str:
    """Возвращает строку издателя сертификата."""
    try:
        return cert.issuer.rfc4514_string()
    except Exception:
        return str(cert.issuer)


def _cert_is_self_signed(cert: x509.Certificate) -> bool:
    """Проверяет, является ли сертификат самоподписанным."""
    return cert.subject == cert.issuer


def _verify_signature_raw(
    child: x509.Certificate,
    parent: x509.Certificate,
) -> bool:
    """
    Проверяет подпись child, используя открытый ключ parent.

    :return: True если подпись верна
    :raises InvalidSignature: если подпись неверна
    """
    pub = parent.public_key()
    if isinstance(pub, rsa_mod.RSAPublicKey):
        pub.verify(
            child.signature,
            child.tbs_certificate_bytes,
            padding.PKCS1v15(),
            child.signature_hash_algorithm,
        )
    elif isinstance(pub, ec_mod.EllipticCurvePublicKey):
        pub.verify(
            child.signature,
            child.tbs_certificate_bytes,
            ECDSA(child.signature_hash_algorithm),
        )
    else:
        raise ValueError(f"Неподдерживаемый тип ключа: {type(pub)}")
    return True


def _get_path_len_constraint(cert: x509.Certificate) -> Optional[int]:
    """Возвращает pathLenConstraint или None."""
    try:
        bc = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
        return bc.path_length
    except x509.ExtensionNotFound:
        return None


def _is_ca_cert(cert: x509.Certificate) -> bool:
    """Возвращает True если сертификат является CA (BasicConstraints.ca=True)."""
    try:
        bc = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
        return bc.ca
    except x509.ExtensionNotFound:
        return False


# ---------------------------------------------------------------------------
# Построение цепочки
# ---------------------------------------------------------------------------

def build_chain(
    leaf: x509.Certificate,
    untrusted: list[x509.Certificate],
    trusted: list[x509.Certificate],
) -> Optional[list[x509.Certificate]]:
    """
    Строит цепочку от leaf до доверенного корневого сертификата.

    Алгоритм: жадный поиск — для каждого сертификата ищем издателя
    сначала среди untrusted, потом среди trusted.

    :param leaf: конечный сертификат
    :param untrusted: промежуточные сертификаты (не доверенные якоря)
    :param trusted: доверенные корневые сертификаты
    :return: список [leaf, ..., root] или None если цепочку построить не удалось
    """
    chain = [leaf]
    pool = list(untrusted) + list(trusted)
    trusted_subjects = {c.subject for c in trusted}

    current = leaf
    visited = {id(leaf)}

    for _ in range(20):  # защита от бесконечного цикла
        # Если текущий сертификат уже является доверенным якорем — готово
        if current.subject in trusted_subjects and current != leaf:
            return chain

        # Ищем издателя: сначала среди untrusted, потом среди trusted
        issuer = None
        # Сначала untrusted (не корневые)
        for candidate in untrusted:
            if id(candidate) in visited:
                continue
            if candidate.subject == current.issuer:
                issuer = candidate
                break

        # Потом trusted
        if issuer is None:
            for candidate in trusted:
                if candidate.subject == current.issuer:
                    issuer = candidate
                    break

        if issuer is None:
            logger.debug(
                "Не найден издатель для: %s (ищем issuer=%s)",
                _subject_str(current), _issuer_str(current),
            )
            return None

        chain.append(issuer)
        visited.add(id(issuer))

        # Если нашли доверенный корень
        if issuer.subject in trusted_subjects:
            return chain

        current = issuer

    logger.warning("Превышена максимальная длина цепочки")
    return None


# ---------------------------------------------------------------------------
# Проверки отдельного сертификата
# ---------------------------------------------------------------------------

def check_signature(
    child: x509.Certificate,
    parent: x509.Certificate,
    result: CertCheckResult,
) -> bool:
    """Проверяет подпись child публичным ключом parent."""
    try:
        _verify_signature_raw(child, parent)
        result.passed.append(
            f"Подпись верна (подписан: {_subject_str(parent)})"
        )
        return True
    except (InvalidSignature, ValueError) as e:
        result.failed.append(f"Подпись НЕВЕРНА: {e}")
        return False


def check_validity(
    cert: x509.Certificate,
    result: CertCheckResult,
    validation_time: Optional[datetime.datetime] = None,
) -> bool:
    """Проверяет срок действия сертификата."""
    now = validation_time or datetime.datetime.now(datetime.timezone.utc)

    ok = True
    if now < cert.not_valid_before_utc:
        result.failed.append(
            f"Сертификат ещё не действителен. notBefore={cert.not_valid_before_utc}"
        )
        ok = False
    elif now > cert.not_valid_after_utc:
        result.failed.append(
            f"Сертификат просрочен. notAfter={cert.not_valid_after_utc}"
        )
        ok = False
    else:
        result.passed.append(
            f"Срок действия в норме ({cert.not_valid_before_utc.date()} "
            f"— {cert.not_valid_after_utc.date()})"
        )
    return ok


def check_basic_constraints(
    cert: x509.Certificate,
    expect_ca: bool,
    result: CertCheckResult,
) -> bool:
    """Проверяет BasicConstraints."""
    try:
        bc_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        bc: x509.BasicConstraints = bc_ext.value
        if bc.ca == expect_ca:
            result.passed.append(
                f"BasicConstraints: CA={bc.ca} (ожидалось CA={expect_ca})"
            )
            return True
        else:
            result.failed.append(
                f"BasicConstraints: CA={bc.ca}, ожидалось CA={expect_ca}"
            )
            return False
    except x509.ExtensionNotFound:
        # Если расширение отсутствует и ожидается CA=False — допустимо
        if not expect_ca:
            result.passed.append(
                "BasicConstraints отсутствует (конечный сертификат, допустимо)"
            )
            return True
        result.failed.append("BasicConstraints отсутствует (требуется CA=True)")
        return False


def check_path_len(
    ca_cert: x509.Certificate,
    subordinate_ca_count: int,
    result: CertCheckResult,
) -> bool:
    """
    Проверяет pathLenConstraint CA-сертификата.

    :param subordinate_ca_count: количество подчинённых CA ниже данного
    """
    path_len = _get_path_len_constraint(ca_cert)
    if path_len is None:
        result.passed.append("pathLenConstraint: не задан (без ограничений)")
        return True
    if subordinate_ca_count <= path_len:
        result.passed.append(
            f"pathLenConstraint: {subordinate_ca_count} ≤ {path_len} (норма)"
        )
        return True
    result.failed.append(
        f"pathLenConstraint нарушен: {subordinate_ca_count} > {path_len}"
    )
    return False


def check_key_usage_ca(
    cert: x509.Certificate,
    result: CertCheckResult,
) -> bool:
    """Проверяет KeyUsage для CA-сертификата (keyCertSign обязателен если KU критичен)."""
    try:
        ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        ku: x509.KeyUsage = ku_ext.value
        if ku_ext.critical:
            if ku.key_cert_sign:
                result.passed.append("KeyUsage: keyCertSign присутствует (критичное)")
                return True
            else:
                result.failed.append(
                    "KeyUsage: keyCertSign ОТСУТСТВУЕТ (критичное расширение CA)"
                )
                return False
        else:
            result.passed.append("KeyUsage: некритичное, пропускаем проверку keyCertSign")
            return True
    except x509.ExtensionNotFound:
        result.passed.append("KeyUsage: расширение отсутствует (некритично для CA)")
        return True


def check_key_usage_leaf(
    cert: x509.Certificate,
    result: CertCheckResult,
) -> bool:
    """Проверяет KeyUsage для конечного сертификата (digitalSignature)."""
    try:
        ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        ku: x509.KeyUsage = ku_ext.value
        if ku_ext.critical:
            if ku.digital_signature:
                result.passed.append(
                    "KeyUsage: digitalSignature присутствует (критичное)"
                )
                return True
            else:
                result.failed.append(
                    "KeyUsage: digitalSignature ОТСУТСТВУЕТ (критичное расширение)"
                )
                return False
        else:
            result.passed.append("KeyUsage: некритичное, пропускаем строгую проверку")
            return True
    except x509.ExtensionNotFound:
        result.passed.append("KeyUsage: расширение отсутствует")
        return True


# ---------------------------------------------------------------------------
# Главная функция валидации
# ---------------------------------------------------------------------------

def validate_chain(
    leaf: x509.Certificate,
    untrusted: list[x509.Certificate],
    trusted: list[x509.Certificate],
    validation_time: Optional[datetime.datetime] = None,
    check_revocation: bool = False,
    revocation_checker=None,
) -> ValidationResult:
    """
    Выполняет полную проверку цепочки сертификатов.

    :param leaf: конечный сертификат
    :param untrusted: промежуточные сертификаты
    :param trusted: доверенные корневые сертификаты
    :param validation_time: время для проверки срока действия (None = сейчас)
    :param check_revocation: выполнять ли проверку отзыва
    :param revocation_checker: callable(cert, issuer_cert) -> RevocationResult
    :return: ValidationResult
    """
    vt = validation_time or datetime.datetime.now(datetime.timezone.utc)

    # 1. Построение цепочки
    chain = build_chain(leaf, untrusted, trusted)
    if chain is None:
        return ValidationResult(
            success=False,
            error=(
                "Не удалось построить цепочку сертификатов. "
                "Проверьте наличие промежуточных сертификатов (--untrusted)."
            ),
        )

    chain_subjects = [_subject_str(c) for c in chain]
    trusted_subjects = {c.subject for c in trusted}
    cert_results: list[CertCheckResult] = []
    overall_ok = True

    # 2. Проверяем каждый сертификат в цепочке (кроме самого доверенного корня)
    for i, cert in enumerate(chain):
        subj = _subject_str(cert)
        cr = CertCheckResult(subject=subj)
        is_leaf = (i == 0)
        is_trusted_anchor = (cert.subject in trusted_subjects)

        # Доверенный якорь — минимальные проверки
        if is_trusted_anchor:
            check_validity(cert, cr, vt)
            cert_results.append(cr)
            continue

        parent = chain[i + 1]
        expect_ca = not is_leaf

        # Подпись
        sig_ok = check_signature(cert, parent, cr)

        # Срок действия
        val_ok = check_validity(cert, cr, vt)

        # BasicConstraints
        bc_ok = check_basic_constraints(cert, expect_ca, cr)

        # Для CA-сертификатов: pathLen и KeyUsage
        if expect_ca:
            # Количество подчинённых CA между этим CA и leaf
            subordinate_cas = sum(
                1 for j in range(0, i)
                if _is_ca_cert(chain[j]) and not (j == 0 and is_leaf)
            )
            check_path_len(cert, subordinate_cas, cr)
            check_key_usage_ca(cert, cr)
        else:
            check_key_usage_leaf(cert, cr)

        if not cr.ok:
            overall_ok = False

        cert_results.append(cr)

        # При первой ошибке останавливаемся
        if not cr.ok:
            first_error = cr.failed[0]
            return ValidationResult(
                success=False,
                chain=chain_subjects,
                cert_results=cert_results,
                error=f"Ошибка в сертификате [{subj}]: {first_error}",
            )

    return ValidationResult(
        success=overall_ok,
        chain=chain_subjects,
        cert_results=cert_results,
    )