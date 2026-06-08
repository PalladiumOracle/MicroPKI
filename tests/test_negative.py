"""
Негативные тесты (TEST-10).
"""

import logging
from pathlib import Path

import pytest

from micropki.templates import validate_san_types, get_template


def _make_logger():
    logger = logging.getLogger("test_negative")
    if not logger.handlers:
        logger.addHandler(logging.NullHandler())
    return logger


def test_server_cert_without_san_rejected():
    """Серверный сертификат без SAN отклоняется при валидации."""
    template = get_template("server")
    errors = validate_san_types(template, [])
    assert len(errors) >= 1
    assert "требует" in errors[0]


def test_server_cert_email_san_rejected():
    """Email SAN для серверного сертификата отклоняется."""
    template = get_template("server")
    errors = validate_san_types(template, [("email", "test@example.com")])
    assert len(errors) >= 1


def test_code_signing_ip_san_rejected():
    """IP SAN для сертификата подписи кода отклоняется."""
    template = get_template("code_signing")
    errors = validate_san_types(template, [("ip", "1.2.3.4")])
    assert len(errors) >= 1


def test_wrong_passphrase_rejected(tmp_path: Path):
    """Неверная парольная фраза → ошибка при загрузке ключа."""
    from micropki.ca import init_root_ca, issue_intermediate

    out_dir = tmp_path / "pki"
    pass_file = tmp_path / "root.pass"
    pass_file.write_bytes(b"correct-pass")

    # Создаём корневой CA
    init_root_ca(
        subject="/CN=Root",
        key_type="rsa",
        key_size=4096,
        passphrase_file=pass_file,
        out_dir=out_dir,
        validity_days=365,
        force=False,
        logger=_make_logger(),
    )

    # Пробуем создать промежуточный с неверным паролем
    wrong_pass = tmp_path / "wrong.pass"
    wrong_pass.write_bytes(b"wrong-password")

    inter_pass = tmp_path / "inter.pass"
    inter_pass.write_bytes(b"inter-pass")

    with pytest.raises(Exception):
        issue_intermediate(
            root_cert_path=out_dir / "certs" / "ca.cert.pem",
            root_key_path=out_dir / "private" / "ca.key.pem",
            root_pass_file=wrong_pass,
            subject="CN=Inter",
            key_type="rsa",
            key_size=4096,
            passphrase_file=inter_pass,
            out_dir=out_dir,
            validity_days=365,
            path_length=0,
            force=False,
            logger=_make_logger(),
        )