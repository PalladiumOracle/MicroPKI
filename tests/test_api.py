"""
Тесты API репозитория (TEST-16).

Проверяют:
- GET /ca/root возвращает PEM корневого CA
- GET /ca/intermediate возвращает PEM промежуточного CA
- Содержимое совпадает с файлами на диске
"""

import logging
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from micropki.database import init_database
from micropki.server import create_app
from micropki.ca import init_root_ca, issue_intermediate


@pytest.fixture
def pki_env(tmp_path: Path):
    """Создаёт полное PKI-окружение для тестов."""
    out_dir = tmp_path / "pki"
    db_path = out_dir / "micropki.db"
    cert_dir = out_dir / "certs"

    # Парольные фразы
    root_pass = tmp_path / "root.pass"
    root_pass.write_bytes(b"root-test-pass")
    inter_pass = tmp_path / "inter.pass"
    inter_pass.write_bytes(b"inter-test-pass")

    logger = logging.getLogger("test_api")
    if not logger.handlers:
        logger.addHandler(logging.NullHandler())

    # Инициализация БД
    init_database(db_path)

    # Корневой CA
    init_root_ca(
        subject="/CN=Test Root CA",
        key_type="rsa", key_size=4096,
        passphrase_file=root_pass, out_dir=out_dir,
        validity_days=3650, force=False, logger=logger,
        db_path=db_path,
    )

    # Промежуточный CA
    issue_intermediate(
        root_cert_path=cert_dir / "ca.cert.pem",
        root_key_path=out_dir / "private" / "ca.key.pem",
        root_pass_file=root_pass,
        subject="CN=Test Intermediate CA",
        key_type="rsa", key_size=4096,
        passphrase_file=inter_pass, out_dir=out_dir,
        validity_days=1825, path_length=0,
        force=False, logger=logger, db_path=db_path,
    )

    return {
        "out_dir": out_dir,
        "db_path": str(db_path),
        "cert_dir": str(cert_dir),
    }


def test_get_root_ca(pki_env):
    """GET /ca/root возвращает PEM корневого CA."""
    app = create_app(pki_env["db_path"], pki_env["cert_dir"])
    client = TestClient(app)

    response = client.get("/ca/root")
    assert response.status_code == 200

    # Содержимое совпадает с файлом
    expected = (Path(pki_env["cert_dir"]) / "ca.cert.pem").read_text()
    assert response.text == expected
    assert "BEGIN CERTIFICATE" in response.text


def test_get_intermediate_ca(pki_env):
    """GET /ca/intermediate возвращает PEM промежуточного CA."""
    app = create_app(pki_env["db_path"], pki_env["cert_dir"])
    client = TestClient(app)

    response = client.get("/ca/intermediate")
    assert response.status_code == 200

    expected = (Path(pki_env["cert_dir"]) / "intermediate.cert.pem").read_text()
    assert response.text == expected


def test_get_ca_unknown_level(pki_env):
    """GET /ca/unknown возвращает 400."""
    app = create_app(pki_env["db_path"], pki_env["cert_dir"])
    client = TestClient(app)

    response = client.get("/ca/unknown")
    assert response.status_code == 400


