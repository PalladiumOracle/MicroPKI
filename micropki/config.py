"""
Модуль конфигурации MicroPKI.

Загружает настройки из YAML-файла micropki.conf
и предоставляет значения по умолчанию.
"""

import yaml
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class Config:
    """Конфигурация MicroPKI."""

    db_path: str = "./pki/micropki.db"
    cert_dir: str = "./pki/certs"
    private_dir: str = "./pki/private"
    out_dir: str = "./pki"
    host: str = "127.0.0.1"
    port: int = 8080
    log_file: str | None = None


def load_config(config_path: Path | None = None) -> Config:
    """
    Загружает конфигурацию из YAML-файла.

    Если файл не указан или не существует, используются значения по умолчанию.

    :param config_path: путь к файлу конфигурации
    :return: объект Config
    """
    config = Config()

    if config_path is None:
        # Ищем в текущей директории
        default_paths = [
            Path("micropki.conf"),
            Path("micropki.yaml"),
        ]
        for p in default_paths:
            if p.exists():
                config_path = p
                break

    if config_path is not None and config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        config.db_path = data.get("db_path", config.db_path)
        config.cert_dir = data.get("cert_dir", config.cert_dir)
        config.private_dir = data.get("private_dir", config.private_dir)
        config.out_dir = data.get("out_dir", config.out_dir)
        config.host = data.get("host", config.host)
        config.port = data.get("port", config.port)
        config.log_file = data.get("log_file", config.log_file)

    return config


def create_default_config(path: Path) -> None:
    """
    Создаёт файл конфигурации по умолчанию.

    :param path: путь для сохранения
    """
    default_content = """\
# MicroPKI — файл конфигурации

# Путь к базе данных SQLite
db_path: "./pki/micropki.db"

# Каталог с сертификатами (PEM)
cert_dir: "./pki/certs"

# Каталог с закрытыми ключами
private_dir: "./pki/private"

# Основной выходной каталог
out_dir: "./pki"

# Настройки HTTP-сервера репозитория
host: "127.0.0.1"
port: 8080

# Файл журнала (null = stderr)
# log_file: "./logs/micropki.log"
"""
    path.write_text(default_content, encoding="utf-8")