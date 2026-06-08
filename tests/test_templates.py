"""
Тесты модуля шаблонов сертификатов.
"""

import pytest


from micropki.templates import (
    get_template,
    build_key_usage,
    validate_san_types,
    SERVER_TEMPLATE,
    CLIENT_TEMPLATE,
    CODE_SIGNING_TEMPLATE,
)


def test_get_template_server():
    """Получение серверного шаблона по имени."""
    t = get_template("server")
    assert t.name == "server"
    assert t.san_required is True


def test_get_template_client():
    """Получение клиентского шаблона по имени."""
    t = get_template("client")
    assert t.name == "client"
    assert t.san_required is False


def test_get_template_code_signing():
    """Получение шаблона подписи кода по имени."""
    t = get_template("code_signing")
    assert t.name == "code_signing"


def test_get_template_unknown():
    """Неизвестный шаблон → ValueError."""
    with pytest.raises(ValueError, match="Неизвестный шаблон"):
        get_template("unknown")


def test_key_usage_server_rsa():
    """Для серверного RSA — digitalSignature + keyEncipherment."""
    ku = build_key_usage(SERVER_TEMPLATE, "rsa")
    assert ku.digital_signature is True
    assert ku.key_encipherment is True
    assert ku.key_cert_sign is False


def test_key_usage_server_ecc():
    """Для серверного ECC — только digitalSignature."""
    ku = build_key_usage(SERVER_TEMPLATE, "ecc")
    assert ku.digital_signature is True
    assert ku.key_encipherment is False


def test_key_usage_client():
    """Для клиентского — digitalSignature."""
    ku = build_key_usage(CLIENT_TEMPLATE, "rsa")
    assert ku.digital_signature is True
    assert ku.key_encipherment is False


def test_validate_san_server_dns_ok():
    """DNS SAN допустим для серверного шаблона."""
    errors = validate_san_types(SERVER_TEMPLATE, [("dns", "example.com")])
    assert errors == []


def test_validate_san_server_ip_ok():
    """IP SAN допустим для серверного шаблона."""
    errors = validate_san_types(SERVER_TEMPLATE, [("ip", "1.2.3.4")])
    assert errors == []


def test_validate_san_server_email_rejected():
    """Email SAN НЕ допустим для серверного шаблона."""
    errors = validate_san_types(SERVER_TEMPLATE, [("email", "a@b.com")])
    assert len(errors) == 1
    assert "email" in errors[0]


def test_validate_san_server_missing():
    """Серверный шаблон требует хотя бы один SAN."""
    errors = validate_san_types(SERVER_TEMPLATE, [])
    assert len(errors) == 1
    assert "требует" in errors[0]


def test_validate_san_client_email_ok():
    """Email SAN допустим для клиентского шаблона."""
    errors = validate_san_types(CLIENT_TEMPLATE, [("email", "a@b.com")])
    assert errors == []


def test_validate_san_code_signing_ip_rejected():
    """IP SAN НЕ допустим для шаблона подписи кода."""
    errors = validate_san_types(CODE_SIGNING_TEMPLATE, [("ip", "1.2.3.4")])
    assert len(errors) == 1