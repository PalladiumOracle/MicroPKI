"""
OCSP-ответчик на базе FastAPI.

Принимает POST /ocsp с Content-Type: application/ocsp-request (DER),
возвращает application/ocsp-response (DER).

Логирует каждый запрос с уровнем INFO (структурированный JSON):
  timestamp | client_ip | serial | status | elapsed_ms
"""

import time
import logging
import json
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Optional

import uvicorn
from fastapi import FastAPI, Request, Response

from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import serialization

from micropki.ocsp import (
    build_ocsp_response,
    build_error_response,
    get_cert_id_from_request,
)
from micropki.serial import serial_to_hex

logger = logging.getLogger("micropki.ocsp")
access_logger = logging.getLogger("micropki.ocsp.access")


def _load_responder_cert(path: str) -> x509.Certificate:
    pem = Path(path).read_bytes()
    return x509.load_pem_x509_certificate(pem)


def _load_responder_key(path: str):
    pem = Path(path).read_bytes()
    return serialization.load_pem_private_key(pem, password=None)


def _load_ca_cert(path: str) -> x509.Certificate:
    pem = Path(path).read_bytes()
    return x509.load_pem_x509_certificate(pem)


def _log_ocsp_access(
    client_ip: str,
    serial: str,
    status: str,
    elapsed_ms: float,
    error: Optional[str] = None,
) -> None:
    """Логирует OCSP-запрос в структурированном JSON."""
    record = {
        "client_ip": client_ip,
        "serial": serial,
        "ocsp_status": status,
        "elapsed_ms": round(elapsed_ms, 2),
    }
    if error:
        record["error"] = error
        access_logger.error(json.dumps(record, ensure_ascii=False))
    else:
        access_logger.info(json.dumps(record, ensure_ascii=False))


def create_ocsp_app(
    db_path: str,
    responder_cert_path: str,
    responder_key_path: str,
    ca_cert_path: str,
    cache_ttl: int = 60,
) -> FastAPI:
    """
    Создаёт FastAPI-приложение OCSP-ответчика.

    :param db_path: путь к БД SQLite
    :param responder_cert_path: PEM-сертификат OCSP-ответчика
    :param responder_key_path: незашифрованный PEM-ключ OCSP-ответчика
    :param ca_cert_path: PEM-сертификат выпускающего CA
    :param cache_ttl: TTL кэша в секундах
    :return: экземпляр FastAPI
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logger.info(
            "OCSP-ответчик запущен (db=%s, responder=%s, ca=%s, ttl=%ds)",
            db_path, responder_cert_path, ca_cert_path, cache_ttl,
        )
        yield
        logger.info("OCSP-ответчик остановлен")

    app = FastAPI(
        title="MicroPKI OCSP Responder",
        description="OCSP-ответчик MicroPKI",
        lifespan=lifespan,
    )

    app.state.db_path = db_path
    app.state.cache_ttl = cache_ttl

    try:
        app.state.responder_cert = _load_responder_cert(responder_cert_path)
        app.state.responder_key = _load_responder_key(responder_key_path)
        app.state.ca_cert = _load_ca_cert(ca_cert_path)
        logger.info("Криптоматериалы OCSP-ответчика загружены успешно")
    except Exception as e:
        logger.error("Ошибка загрузки криптоматериалов: %s", e)
        raise

    @app.post("/ocsp")
    async def handle_ocsp(request: Request) -> Response:
        """Основной эндпоинт OCSP."""
        start_time = time.monotonic()
        client_ip = request.client.host if request.client else "unknown"

        # Читаем тело запроса
        body = await request.body()

        # Проверяем наличие тела
        if not body:
            elapsed = (time.monotonic() - start_time) * 1000
            _log_ocsp_access(
                client_ip, "N/A", "malformedRequest", elapsed,
                "Пустое тело запроса",
            )
            error_der = build_error_response(
                ocsp.OCSPResponseStatus.MALFORMED_REQUEST
            )
            return Response(
                content=error_der,
                media_type="application/ocsp-response",
                status_code=400,
            )

        # Разбор OCSP-запроса (OCSP-1)
        try:
            ocsp_request = ocsp.load_der_ocsp_request(body)
        except Exception as e:
            elapsed = (time.monotonic() - start_time) * 1000
            logger.error(
                "Ошибка разбора OCSP-запроса от %s: %s", client_ip, e,
            )
            _log_ocsp_access(
                client_ip, "N/A", "malformedRequest", elapsed, str(e),
            )
            error_der = build_error_response(
                ocsp.OCSPResponseStatus.MALFORMED_REQUEST
            )
            return Response(
                content=error_der,
                media_type="application/ocsp-response",
                status_code=400,
            )

        # Извлекаем serial для логирования — совместимо с cryptography >= 42
        serial_hex = "N/A"
        try:
            cert_id = get_cert_id_from_request(ocsp_request)
            serial_int = cert_id.serial_number
            serial_hex = serial_to_hex(serial_int)
        except Exception as e:
            elapsed = (time.monotonic() - start_time) * 1000
            logger.error(
                "Не удалось извлечь CertID из запроса от %s: %s", client_ip, e,
            )
            _log_ocsp_access(
                client_ip, "N/A", "malformedRequest", elapsed, str(e),
            )
            error_der = build_error_response(
                ocsp.OCSPResponseStatus.MALFORMED_REQUEST
            )
            return Response(
                content=error_der,
                media_type="application/ocsp-response",
                status_code=400,
            )

        # Формирование OCSP-ответа
        try:
            response_der = build_ocsp_response(
                request=ocsp_request,
                responder_cert=app.state.responder_cert,
                responder_key=app.state.responder_key,
                ca_cert=app.state.ca_cert,
                db_path=app.state.db_path,
                cache_ttl=app.state.cache_ttl,
            )

            # Определяем статус для логирования
            try:
                parsed = ocsp.load_der_ocsp_response(response_der)
                if parsed.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
                    status_str = parsed.certificate_status.name
                else:
                    status_str = parsed.response_status.name
            except Exception:
                status_str = "SUCCESSFUL"

            elapsed = (time.monotonic() - start_time) * 1000
            _log_ocsp_access(client_ip, serial_hex, status_str, elapsed)

            return Response(
                content=response_der,
                media_type="application/ocsp-response",
                status_code=200,
            )

        except Exception as e:
            elapsed = (time.monotonic() - start_time) * 1000
            logger.error(
                "Внутренняя ошибка при обработке OCSP serial=%s: %s",
                serial_hex, e,
            )
            _log_ocsp_access(
                client_ip, serial_hex, "internalError", elapsed, str(e),
            )
            error_der = build_error_response(
                ocsp.OCSPResponseStatus.INTERNAL_ERROR
            )
            return Response(
                content=error_der,
                media_type="application/ocsp-response",
                status_code=200,
            )

    @app.get("/health")
    async def health() -> dict:
        """Проверка работоспособности OCSP-ответчика."""
        return {"status": "ok", "service": "MicroPKI OCSP Responder"}

    return app


def run_ocsp_server(
    host: str,
    port: int,
    db_path: str,
    responder_cert_path: str,
    responder_key_path: str,
    ca_cert_path: str,
    cache_ttl: int = 60,
    log_file: Optional[str] = None,
) -> None:
    """
    Запускает OCSP-ответчик.

    :param host: адрес привязки
    :param port: TCP-порт
    :param db_path: путь к БД
    :param responder_cert_path: сертификат OCSP-ответчика (PEM)
    :param responder_key_path: ключ OCSP-ответчика (PEM, без шифрования)
    :param ca_cert_path: сертификат выпускающего CA (PEM)
    :param cache_ttl: TTL кэша в секундах
    :param log_file: файл журнала (None = stderr)
    """
    from micropki.database import check_schema

    if not check_schema(db_path):
        raise RuntimeError(f"База данных не инициализирована: {db_path}")

    app = create_ocsp_app(
        db_path=db_path,
        responder_cert_path=responder_cert_path,
        responder_key_path=responder_key_path,
        ca_cert_path=ca_cert_path,
        cache_ttl=cache_ttl,
    )

    logger.info("Запуск OCSP-ответчика на http://%s:%d/ocsp", host, port)
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="warning",
        access_log=False,
    )