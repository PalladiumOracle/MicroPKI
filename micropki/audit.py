"""
Система аудита MicroPKI (спринт 7).

Реализует:
- структурированное NDJSON-логирование (AUD-1)
- хеш-цепочку для целостности журнала (AUD-2)
- верификацию журнала (AUD-3)
- обязательные события аудита (AUD-4)
- CT-журнал (CTL-2)
- инициализацию журнала (LOG-19)
"""

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Константы
# ---------------------------------------------------------------------------

AUDIT_LOG_NAME = "audit.log"
CHAIN_FILE_NAME = "chain.dat"
CT_LOG_NAME = "ct.log"

ZERO_HASH = "0" * 64


# ---------------------------------------------------------------------------
# Вычисление хешей
# ---------------------------------------------------------------------------

def _canonical_json(obj: dict) -> str:
    """
    Возвращает каноническое JSON-представление (отсортированные ключи,
    без лишних пробелов) — для воспроизводимого хеширования.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(data: str) -> str:
    """SHA-256 строки → hex."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def compute_entry_hash(entry_without_hash: dict) -> str:
    """
    Вычисляет hash текущей записи.

    Хешируется каноническое JSON содержимое записи БЕЗ поля integrity.hash
    (но с integrity.prev_hash включённым).

    :param entry_without_hash: запись без поля integrity.hash
    :return: hex-строка SHA-256
    """
    return _sha256(_canonical_json(entry_without_hash))


# ---------------------------------------------------------------------------
# Основной класс AuditLogger
# ---------------------------------------------------------------------------

class AuditLogger:
    """
    Аудитный регистратор с хеш-цепочкой (LOG-17).

    Пишет NDJSON в файл audit.log.
    Хранит последний хеш в chain.dat.
    Пишет CT-записи в ct.log.

    Потокобезопасен.
    """

    def __init__(
        self,
        audit_dir: Path,
        app_name: str = "micropki",
    ) -> None:
        """
        :param audit_dir: каталог для журналов (создаётся автоматически)
        :param app_name: имя приложения для записей
        """
        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(parents=True, exist_ok=True)

        self.log_path = self.audit_dir / AUDIT_LOG_NAME
        self.chain_path = self.audit_dir / CHAIN_FILE_NAME
        self.ct_path = self.audit_dir / CT_LOG_NAME
        self.app_name = app_name
        self._lock = threading.Lock()

        # CT-журнал — публичный (0o644)
        if not self.ct_path.exists():
            self.ct_path.touch()
            try:
                os.chmod(self.ct_path, 0o644)
            except OSError:
                pass

        # Инициализируем chain.dat если нет
        if not self.chain_path.exists():
            self._write_chain(ZERO_HASH)

        # Если лог не существует — первая запись (LOG-19)
        if not self.log_path.exists():
            self._write_entry(
                level="AUDIT",
                operation="audit_init",
                status="success",
                message="Журнал аудита инициализирован",
                metadata={"app": app_name},
            )

    # ------------------------------------------------------------------
    # Внутренние методы
    # ------------------------------------------------------------------

    def _read_last_hash(self) -> str:
        """Читает последний хеш из chain.dat."""
        try:
            content = self.chain_path.read_text("utf-8").strip()
            return content if content else ZERO_HASH
        except FileNotFoundError:
            return ZERO_HASH

    def _write_chain(self, new_hash: str) -> None:
        """Записывает последний хеш в chain.dat."""
        self.chain_path.write_text(new_hash + "\n", encoding="utf-8")

    def _write_entry(
        self,
        level: str,
        operation: str,
        status: str,
        message: str,
        metadata: dict[str, Any],
    ) -> str:
        """
        Формирует запись аудита, вычисляет хеш, записывает в лог.

        :return: hash текущей записи
        """
        with self._lock:
            prev_hash = self._read_last_hash()
            now = datetime.now(timezone.utc)
            ts = now.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"

            # Запись без integrity.hash (для вычисления хеша)
            entry_base = {
                "timestamp": ts,
                "level": level,
                "operation": operation,
                "status": status,
                "message": message,
                "metadata": metadata,
                "integrity": {
                    "prev_hash": prev_hash,
                },
            }

            current_hash = compute_entry_hash(entry_base)

            # Полная запись
            entry_full = dict(entry_base)
            entry_full["integrity"] = {
                "prev_hash": prev_hash,
                "hash": current_hash,
            }

            line = json.dumps(entry_full, sort_keys=True,
                              separators=(",", ":"), ensure_ascii=False)

            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

            self._write_chain(current_hash)
            return current_hash

    # ------------------------------------------------------------------
    # Публичные методы логирования
    # ------------------------------------------------------------------

    def log(
        self,
        operation: str,
        status: str,
        message: str,
        metadata: Optional[dict] = None,
        level: str = "AUDIT",
    ) -> None:
        """
        Записывает событие в журнал аудита.

        :param operation: тип операции (issue_certificate, revoke, ...)
        :param status: "success" или "failure"
        :param message: читаемое описание
        :param metadata: дополнительные поля (серийный номер, субъект, ...)
        :param level: уровень (AUDIT, INFO, WARNING, ERROR)
        """
        self._write_entry(
            level=level,
            operation=operation,
            status=status,
            message=message,
            metadata=metadata or {},
        )

    def log_issue(
        self,
        serial: str,
        subject: str,
        template: str,
        requester: str = "cli",
        status: str = "success",
        message: str = "",
    ) -> None:
        """Аудит выпуска сертификата (AUD-4)."""
        self.log(
            operation="issue_certificate",
            status=status,
            message=message or f"Выпуск сертификата: {subject}",
            metadata={
                "serial": serial,
                "subject": subject,
                "template": template,
                "requester": requester,
            },
        )

    def log_revoke(
        self,
        serial: str,
        subject: str,
        reason: str,
        requester: str = "cli",
        status: str = "success",
    ) -> None:
        """Аудит отзыва сертификата (AUD-4)."""
        self.log(
            operation="revoke_certificate",
            status=status,
            message=f"Отзыв сертификата: {subject}, причина: {reason}",
            metadata={
                "serial": serial,
                "subject": subject,
                "reason": reason,
                "requester": requester,
            },
        )

    def log_ca_init(
        self,
        ca_type: str,
        subject: str,
        status: str = "success",
    ) -> None:
        """Аудит инициализации CA (AUD-4)."""
        self.log(
            operation="ca_init",
            status=status,
            message=f"Инициализация {ca_type} CA: {subject}",
            metadata={"ca_type": ca_type, "subject": subject},
        )

    def log_crl_generation(
        self,
        ca_name: str,
        crl_number: int,
        revoked_count: int,
        status: str = "success",
    ) -> None:
        """Аудит генерации CRL (AUD-4)."""
        self.log(
            operation="generate_crl",
            status=status,
            message=f"Генерация CRL для CA={ca_name}, номер={crl_number}",
            metadata={
                "ca_name": ca_name,
                "crl_number": crl_number,
                "revoked_count": revoked_count,
            },
        )

    def log_policy_violation(
        self,
        operation: str,
        violation: str,
        subject: str = "",
        requester: str = "cli",
    ) -> None:
        """Аудит нарушения политики (AUD-4)."""
        self.log(
            operation="policy_violation",
            status="failure",
            message=f"Нарушение политики при {operation}: {violation}",
            metadata={
                "blocked_operation": operation,
                "violation": violation,
                "subject": subject,
                "requester": requester,
            },
            level="AUDIT",
        )

    def log_compromise(
        self,
        serial: str,
        subject: str,
        key_hash: str,
        requester: str = "cli",
    ) -> None:
        """Аудит компрометации ключа (AUD-4, CTL-3)."""
        self.log(
            operation="key_compromise",
            status="success",
            message=f"КОМПРОМЕТАЦИЯ КЛЮЧА: {subject} (serial={serial})",
            metadata={
                "serial": serial,
                "subject": subject,
                "public_key_hash": key_hash,
                "requester": requester,
            },
            level="AUDIT",
        )

    def log_ocsp_server(self, action: str, host: str, port: int) -> None:
        """Аудит запуска/остановки OCSP-ответчика (AUD-4)."""
        self.log(
            operation=f"ocsp_server_{action}",
            status="success",
            message=f"OCSP-ответчик {action}: {host}:{port}",
            metadata={"host": host, "port": port},
        )

    # ------------------------------------------------------------------
    # CT-журнал (CTL-2)
    # ------------------------------------------------------------------

    def log_ct(
        self,
        serial_hex: str,
        subject: str,
        cert_fingerprint: str,
        issuer: str = "",
    ) -> None:
        """
        Добавляет запись в CT-журнал (CTL-2).

        Формат строки:
        <timestamp> <serial_hex> <subject> <fingerprint> [<issuer>]
        """
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        parts = [now, serial_hex, subject, cert_fingerprint]
        if issuer:
            parts.append(issuer)
        line = "\t".join(parts)

        with self._lock:
            with open(self.ct_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")


# ---------------------------------------------------------------------------
# Глобальный экземпляр (синглтон)
# ---------------------------------------------------------------------------

_global_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> Optional[AuditLogger]:
    """Возвращает глобальный аудитный регистратор (если инициализирован)."""
    return _global_audit_logger


def init_audit_logger(audit_dir: Path) -> AuditLogger:
    """
    Инициализирует глобальный аудитный регистратор.

    :param audit_dir: каталог для журналов аудита
    :return: экземпляр AuditLogger
    """
    global _global_audit_logger
    _global_audit_logger = AuditLogger(audit_dir=audit_dir)
    return _global_audit_logger


# ---------------------------------------------------------------------------
# Верификация журнала (AUD-3)
# ---------------------------------------------------------------------------

def load_audit_log(log_path: Path) -> list[dict]:
    """
    Загружает все записи из NDJSON-файла журнала.

    :param log_path: путь к файлу журнала
    :return: список записей (dict)
    :raises FileNotFoundError: если файл не существует
    """
    entries = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                entries.append(entry)
            except json.JSONDecodeError as e:
                raise ValueError(
                    f"Некорректная JSON-запись в строке {line_num}: {e}"
                )
    return entries


def verify_audit_log(
    log_path: Path,
    chain_path: Optional[Path] = None,
) -> tuple[bool, list[str]]:
    """
    Верифицирует целостность журнала аудита путём пересчёта хеш-цепочки.

    :param log_path: путь к файлу журнала
    :param chain_path: путь к файлу chain.dat (опционально)
    :return: (ok: bool, errors: list[str])
    """
    errors: list[str] = []

    if not log_path.exists():
        return False, [f"Файл журнала не найден: {log_path}"]

    try:
        entries = load_audit_log(log_path)
    except ValueError as e:
        return False, [str(e)]

    if not entries:
        return True, []

    prev_hash = ZERO_HASH

    for i, entry in enumerate(entries):
        integrity = entry.get("integrity", {})
        stored_prev_hash = integrity.get("prev_hash", "")
        stored_hash = integrity.get("hash", "")

        # Проверяем prev_hash
        if stored_prev_hash != prev_hash:
            errors.append(
                f"Запись #{i + 1} ({entry.get('timestamp', '?')}): "
                f"prev_hash не совпадает. "
                f"Ожидалось: {prev_hash[:16]}..., "
                f"в записи: {stored_prev_hash[:16]}..."
            )
            if len(errors) >= 5:
                errors.append("... (показаны первые 5 ошибок)")
                break
            prev_hash = stored_hash if stored_hash else ZERO_HASH
            continue

        # Пересчитываем hash записи (без поля integrity.hash)
        entry_for_hash = dict(entry)
        entry_for_hash["integrity"] = {"prev_hash": stored_prev_hash}
        expected_hash = compute_entry_hash(entry_for_hash)

        if stored_hash != expected_hash:
            errors.append(
                f"Запись #{i + 1} ({entry.get('timestamp', '?')}): "
                f"hash не совпадает (запись модифицирована). "
                f"Ожидалось: {expected_hash[:16]}..., "
                f"в записи: {stored_hash[:16]}..."
            )
            if len(errors) >= 5:
                errors.append("... (показаны первые 5 ошибок)")
                break

        prev_hash = stored_hash

    # Сравниваем с chain.dat если указан
    if chain_path and chain_path.exists() and not errors:
        stored_chain_hash = chain_path.read_text("utf-8").strip()
        if stored_chain_hash != prev_hash:
            errors.append(
                f"Хеш последней записи не совпадает с chain.dat. "
                f"Возможно, записи были добавлены вне системы аудита."
            )

    ok = len(errors) == 0
    return ok, errors


# ---------------------------------------------------------------------------
# Вычисление отпечатка сертификата для CT (CTL-2)
# ---------------------------------------------------------------------------

def cert_fingerprint_sha256(cert_pem: bytes) -> str:
    """
    Вычисляет SHA-256 отпечаток сертификата из PEM.

    :param cert_pem: байты PEM-сертификата
    :return: hex-строка SHA-256
    """
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(cert_pem)
    from cryptography.hazmat.primitives import serialization
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


# ---------------------------------------------------------------------------
# Запрос журнала (CLI-31)
# ---------------------------------------------------------------------------

def query_audit_log(
    log_path: Path,
    from_ts: Optional[str] = None,
    to_ts: Optional[str] = None,
    level: Optional[str] = None,
    operation: Optional[str] = None,
    serial: Optional[str] = None,
) -> list[dict]:
    """
    Выполняет запрос к журналу аудита с фильтрацией.

    :param log_path: путь к файлу журнала
    :param from_ts: начальная метка времени (ISO 8601)
    :param to_ts: конечная метка времени (ISO 8601)
    :param level: фильтр по уровню
    :param operation: фильтр по операции
    :param serial: фильтр по серийному номеру
    :return: список записей
    """
    if not log_path.exists():
        return []

    entries = load_audit_log(log_path)
    result = []

    for entry in entries:
        ts = entry.get("timestamp", "")

        if from_ts and ts < from_ts:
            continue
        if to_ts and ts > to_ts:
            continue
        if level and entry.get("level", "").upper() != level.upper():
            continue
        if operation and operation.lower() not in entry.get("operation", "").lower():
            continue
        if serial:
            meta = entry.get("metadata", {})
            if serial.upper() not in meta.get("serial", "").upper():
                continue

        result.append(entry)

    return result