"""
Тесты парсинга и построения SAN (Subject Alternative Name).
"""

import pytest
from cryptography import x509

from micropki.certificates import parse_san_entries, build_san_extension


def test_parse_san_dns():
    """Парсинг DNS SAN."""
    entries = parse_san_entries(["dns:example.com"])
    assert entries == [("dns", "example.com")]


def test_parse_san_ip():
    """Парсинг IP SAN."""
    entries = parse_san_entries(["ip:192.168.1.1"])
    assert entries == [("ip", "192.168.1.1")]


def test_parse_san_email():
    """Парсинг email SAN."""
    entries = parse_san_entries(["email:alice@example.com"])
    assert entries == [("email", "alice@example.com")]


def test_parse_san_uri():
    """Парсинг URI SAN."""
    entries = parse_san_entries(["uri:https://example.com"])
    assert entries == [("uri", "https://example.com")]


def test_parse_san_multiple():
    """Парсинг нескольких SAN."""
    entries = parse_san_entries([
        "dns:example.com",
        "dns:www.example.com",
        "ip:10.0.0.1",
    ])
    assert len(entries) == 3


def test_parse_san_invalid_format():
    """Некорректный формат SAN → ValueError."""
    with pytest.raises(ValueError, match="Некорректный формат SAN"):
        parse_san_entries(["invalid"])


def test_parse_san_unsupported_type():
    """Неподдерживаемый тип SAN → ValueError."""
    with pytest.raises(ValueError, match="Неподдерживаемый тип SAN"):
        parse_san_entries(["phone:+12345"])


def test_build_san_extension_dns():
    """Построение SAN с DNS-именем."""
    ext = build_san_extension([("dns", "example.com")])
    assert ext is not None
    names = list(ext)
    assert len(names) == 1
    assert isinstance(names[0], x509.DNSName)
    assert names[0].value == "example.com"


def test_build_san_extension_ip():
    """Построение SAN с IP-адресом."""
    import ipaddress
    ext = build_san_extension([("ip", "10.0.0.1")])
    names = list(ext)
    assert isinstance(names[0], x509.IPAddress)
    assert names[0].value == ipaddress.ip_address("10.0.0.1")


def test_build_san_extension_empty():
    """Пустой список SAN → None."""
    ext = build_san_extension([])
    assert ext is None


def test_build_san_invalid_ip():
    """Некорректный IP → ValueError."""
    with pytest.raises(ValueError, match="Некорректный IP"):
        build_san_extension([("ip", "not-an-ip")])