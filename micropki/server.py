"""
HTTP-сервер репозитория сертификатов (FastAPI).

Эндпоинты:
  GET  /certificate/{serial_hex} — получить сертификат по серийному номеру
  GET  /ca/{level}               — получить сертификат УЦ (root / intermediate)
  GET  /crl                      — получить CRL
  POST /request-cert             — выпустить сертификат по CSR (REPO-15)
"""

import os
import hashlib
import logging
from pathlib import Path
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Query, Header
from fastapi.responses import PlainTextResponse, Response
from fastapi.middleware.cors import CORSMiddleware

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from micropki.database import check_schema
from micropki.repository import get_certificate_by_serial
from micropki.serial import is_valid_hex
from micropki.csr import verify_csr_signature

logger = logging.getLogger("micropki")
http_logger = logging.getLogger("micropki.http")

# REPO-16: API-ключ из переменной окружения или значение по умолчанию
# ВНИМАНИЕ: значение по умолчанию небезопасно — только для демонстрации!
_DEFAULT_API_KEY = "changeme"
_API_KEY_WARNING_SHOWN = False


def _get_api_key() -> str:
    return os.environ.get("MICROPKI_API_KEY", _DEFAULT_API_KEY)


def _check_api_key(provided: str | None) -> bool:
    """
    Проверяет API-ключ.
    Если переменная MICROPKI_API_KEY не задана — аутентификация отключена
    с предупреждением в лог.
    """
    global _API_KEY_WARNING_SHOWN
    configured = os.environ.get("MICROPKI_API_KEY")
    if configured is None:
        if not _API_KEY_WARNING_SHOWN:
            logger.warning(
                "БЕЗОПАСНОСТЬ: Переменная MICROPKI_API_KEY не задана. "
                "Эндпоинт /request-cert работает БЕЗ аутентификации. "
                "В production задайте MICROPKI_API_KEY."
            )
            _API_KEY_WARNING_SHOWN = True
        return True  # аутентификация отключена
    return provided == configured


def create_app(db_path: str, cert_dir: str) -> FastAPI:
    """
    Создаёт экземпляр FastAPI-приложения.

    :param db_path: путь к базе данных SQLite
    :param cert_dir: каталог с PEM-сертификатами
    :return: экземпляр FastAPI
    """

    from micropki.ratelimit import get_rate_limiter
    from fastapi.responses import JSONResponse
    import math

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logger.info("Сервер репозитория запущен (db=%s, certs=%s)", db_path, cert_dir)
        yield
        logger.info("Сервер репозитория остановлен")

    app = FastAPI(
        title="MicroPKI Repository",
        description="Репозиторий сертификатов MicroPKI",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    app.state.db_path = db_path
    app.state.cert_dir = cert_dir

    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        response = await call_next(request)
        client_ip = request.client.host if request.client else "unknown"
        http_logger.info(
            "[HTTP] %s %s %s → %d",
            request.method, request.url.path, client_ip, response.status_code,
        )
        return response

    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        """Rate limiting по IP (CTL-1)."""
        limiter = get_rate_limiter()
        if limiter:
            client_ip = request.client.host if request.client else "unknown"
            allowed, retry_after = limiter.check(client_ip)
            if not allowed:
                retry_secs = math.ceil(retry_after)
                http_logger.warning(
                    "[RATE-LIMIT] %s превысил лимит запросов, retry_after=%ds",
                    client_ip, retry_secs,
                )
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too Many Requests. Превышен лимит запросов."},
                    headers={"Retry-After": str(retry_secs)},
                )
        response = await call_next(request)
        return response

    @app.get("/certificate/{serial_hex}")
    async def get_certificate(serial_hex: str):
        """Получить сертификат по серийному номеру."""
        if not is_valid_hex(serial_hex):
            raise HTTPException(
                status_code=400,
                detail=f"Некорректный формат серийного номера: '{serial_hex}'.",
            )
        cert_data = get_certificate_by_serial(db_path, serial_hex)
        if cert_data is None:
            raise HTTPException(
                status_code=404,
                detail=f"Сертификат не найден: {serial_hex}")
        return PlainTextResponse(
            content=cert_data["cert_pem"],
            media_type="application/x-pem-file")

    @app.get("/ca/{level}")
    async def get_ca_certificate(level: str):
        """Получить сертификат УЦ (root / intermediate)."""
        file_map = {"root": "ca.cert.pem", "intermediate": "intermediate.cert.pem"}
        if level not in file_map:
            raise HTTPException(
                status_code=400,
                detail=f"Неподдерживаемый уровень: '{level}'.")
        cert_path = Path(cert_dir) / file_map[level]
        if not cert_path.exists():
            raise HTTPException(
                status_code=404,
                detail=f"Сертификат УЦ не найден: {cert_path}")
        return PlainTextResponse(
            content=cert_path.read_text("utf-8"),
            media_type="application/x-pem-file")

    @app.get("/crl")
    async def get_crl(ca: str = Query(default="intermediate", pattern="^(root|intermediate)$")):
        """Получить CRL."""
        certs_path = Path(cert_dir)
        crl_dir = certs_path.parent / "crl"
        crl_file = crl_dir / f"{ca}.crl.pem"

        if not crl_file.exists():
            raise HTTPException(
                status_code=404,
                detail=f"CRL для '{ca}' не найден.",
            )

        crl_content = crl_file.read_bytes()
        stat = crl_file.stat()
        etag = hashlib.md5(crl_content).hexdigest()

        return Response(
            content=crl_content,
            media_type="application/pkix-crl",
            headers={
                "Last-Modified": str(stat.st_mtime),
                "ETag": f'"{etag}"',
                "Cache-Control": "max-age=3600",
            },
        )

    @app.post("/request-cert", status_code=201)
    async def request_cert_endpoint(
        request: Request,
        template: str = Query(..., description="Шаблон: server, client, code_signing"),
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    ):
        """
        Выпустить сертификат по CSR (REPO-15).

        Принимает CSR в формате PEM (Content-Type: application/x-pem-file).
        Возвращает подписанный сертификат в PEM.

        БЕЗОПАСНОСТЬ (REPO-16): Аутентификация через заголовок X-API-Key.
        Если переменная окружения MICROPKI_API_KEY не задана —
        аутентификация ОТКЛЮЧЕНА (только для демонстрации, небезопасно!).
        """
        # Аутентификация (REPO-16)
        if not _check_api_key(x_api_key):
            raise HTTPException(
                status_code=401,
                detail="Неверный или отсутствующий API-ключ (X-API-Key).",
            )

        # Валидация шаблона
        allowed_templates = {"server", "client", "code_signing"}
        if template not in allowed_templates:
            raise HTTPException(
                status_code=400,
                detail=f"Недопустимый шаблон: '{template}'. Допустимые: {sorted(allowed_templates)}",
            )

        # Читаем тело запроса (CSR PEM)
        body = await request.body()
        if not body:
            raise HTTPException(status_code=400, detail="Тело запроса пустое.")

        # Парсим CSR
        try:
            csr = x509.load_pem_x509_csr(body)
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Некорректный CSR: {e}",
            )

        # Проверяем подпись CSR
        try:
            verify_csr_signature(csr)
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Подпись CSR недействительна: {e}",
            )

        # Получаем CA-материалы из cert_dir
        ca_cert_path = Path(cert_dir) / "intermediate.cert.pem"
        ca_key_path_candidates = [
            Path(cert_dir).parent / "private" / "intermediate.key.pem",
        ]

        if not ca_cert_path.exists():
            raise HTTPException(
                status_code=500,
                detail="Сертификат промежуточного CA не найден на сервере.",
            )

        ca_key_path = None
        for p in ca_key_path_candidates:
            if p.exists():
                ca_key_path = p
                break

        if ca_key_path is None:
            raise HTTPException(
                status_code=500,
                detail=(
                    "Ключ промежуточного CA не найден. "
                    "Убедитесь что файл доступен серверу."
                ),
            )

        # Читаем ключ CA (ключ должен быть без шифрования для сервера)
        try:
            from cryptography.hazmat.primitives import serialization as _serial
            ca_key_pem = ca_key_path.read_bytes()
            ca_private_key = _serial.load_pem_private_key(ca_key_pem, password=None)
        except Exception:
            # Пробуем с паролем из переменной окружения
            ca_pass = os.environ.get("MICROPKI_CA_PASS", "").encode()
            if not ca_pass:
                raise HTTPException(
                    status_code=500,
                    detail=(
                        "Не удалось загрузить ключ CA. "
                        "Задайте MICROPKI_CA_PASS или используйте незашифрованный ключ."
                    ),
                )
            try:
                from cryptography.hazmat.primitives import serialization as _serial2
                ca_key_pem = ca_key_path.read_bytes()
                ca_private_key = _serial2.load_pem_private_key(ca_key_pem, password=ca_pass)
            except Exception as e:
                raise HTTPException(
                    status_code=500,
                    detail=f"Не удалось расшифровать ключ CA: {e}",
                )

        ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())

        # Выпускаем сертификат
        try:
            from micropki.templates import get_template
            from micropki.certificates import build_leaf_certificate_from_csr
            from micropki.certificates import serialize_certificate_pem
            from micropki.serial import generate_unique_serial
            from micropki.database import check_schema as _check_schema
            from micropki.repository import insert_certificate
            from micropki.serial import serial_to_hex

            tmpl = get_template(template)

            if check_schema(db_path):
                serial_number = generate_unique_serial(db_path)
            else:
                serial_number = None

            cert = build_leaf_certificate_from_csr(
                csr=csr,
                ca_private_key=ca_private_key,
                ca_cert=ca_cert,
                template=tmpl,
                validity_days=365,
                serial_number=serial_number,
            )

            cert_pem = serialize_certificate_pem(cert)

            # Сохраняем в БД
            if check_schema(db_path):
                def _dn(name):
                    parts = []
                    for attr in name:
                        parts.append(f"{attr.oid._name}={attr.value}")
                    return ", ".join(parts)

                s_hex = serial_to_hex(cert.serial_number)
                insert_certificate(
                    db_path=db_path,
                    serial_hex=s_hex,
                    subject=_dn(cert.subject),
                    issuer=_dn(cert.issuer),
                    not_before=cert.not_valid_before_utc,
                    not_after=cert.not_valid_after_utc,
                    cert_pem=cert_pem.decode("utf-8"),
                )

                # LOG-16: аудит API-запросов
                client_ip = request.client.host if request.client else "unknown"
                logger.info(
                    "AUDIT /request-cert: serial=%s subject=%s template=%s "
                    "client_ip=%s via_api=True",
                    s_hex, _dn(cert.subject), template, client_ip,
                )

        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            logger.error("Ошибка выпуска сертификата через API: %s", e)
            raise HTTPException(
                status_code=500,
                detail=f"Внутренняя ошибка при выпуске сертификата: {e}",
            )

        return Response(
            content=cert_pem,
            status_code=201,
            media_type="application/x-pem-file",
        )

    return app


def run_server(
    host: str,
    port: int,
    db_path: str,
    cert_dir: str,
    rate_limit: float = 0,
    rate_burst: int = 10,
) -> None:
    """Запускает HTTP-сервер репозитория."""
    if not check_schema(db_path):
        logger.error("БД не инициализирована: %s", db_path)
        raise RuntimeError("База данных не инициализирована")

    # Rate limiting
    from micropki.ratelimit import init_rate_limiter
    if rate_limit > 0:
        init_rate_limiter(rate=rate_limit, burst=rate_burst)
        logger.info(
            "Rate limiting включён: %g req/s, burst=%d", rate_limit, rate_burst
        )

    app = create_app(db_path, cert_dir)
    logger.info("Запуск сервера на http://%s:%d", host, port)
    uvicorn.run(app, host=host, port=port, log_level="warning", access_log=False)