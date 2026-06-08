"""
Модуль работы с базой данных SQLite.

Содержит:
- инициализацию БД и создание схемы
- миграции схемы (v1, v2, v3)
- получение подключения
"""

import sqlite3
import logging
from pathlib import Path

logger = logging.getLogger("micropki")

SCHEMA_VERSION = 3

SCHEMA_V1_SQL = """\
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_hex TEXT UNIQUE NOT NULL,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    cert_pem TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'valid',
    revocation_reason TEXT,
    revocation_date TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_serial_hex ON certificates(serial_hex);
CREATE INDEX IF NOT EXISTS idx_status ON certificates(status);
CREATE INDEX IF NOT EXISTS idx_subject ON certificates(subject);
"""

MIGRATION_V1_TO_V2_SQL = """\
CREATE TABLE IF NOT EXISTS crl_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_subject TEXT NOT NULL,
    crl_number INTEGER NOT NULL,
    last_generated TEXT NOT NULL,
    next_update TEXT NOT NULL,
    crl_path TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ca_subject ON crl_metadata(ca_subject);
"""

# DB-10: таблица compromised_keys
MIGRATION_V2_TO_V3_SQL = """\
CREATE TABLE IF NOT EXISTS compromised_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_key_hash TEXT UNIQUE NOT NULL,
    certificate_serial TEXT NOT NULL,
    compromise_date TEXT NOT NULL,
    compromise_reason TEXT NOT NULL,
    FOREIGN KEY (certificate_serial) REFERENCES certificates(serial_hex)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_compromised_key_hash
ON compromised_keys(public_key_hash);
"""

SCHEMA_VERSION_TABLE_SQL = """\
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);
"""


def get_connection(db_path) -> sqlite3.Connection:
    """Открывает подключение к SQLite."""
    db_path = str(db_path)
    conn = sqlite3.Connection(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def _get_schema_version(conn: sqlite3.Connection) -> int:
    cursor = conn.cursor()
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
    )
    if cursor.fetchone() is None:
        return 0
    cursor.execute("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1")
    row = cursor.fetchone()
    return row["version"] if row else 0


def _set_schema_version(conn: sqlite3.Connection, version: int) -> None:
    conn.executescript(SCHEMA_VERSION_TABLE_SQL)
    conn.execute("DELETE FROM schema_version")
    conn.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))


def init_database(db_path) -> None:
    """
    Инициализирует БД: создаёт таблицы и выполняет миграции.

    Версии:
    - v1: таблица certificates
    - v2: таблица crl_metadata
    - v3: таблица compromised_keys (DB-10)
    """
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = get_connection(db_path)
    try:
        current_version = _get_schema_version(conn)

        if current_version >= SCHEMA_VERSION:
            logger.info(
                "База данных актуальна: %s (версия схемы: %d)",
                db_path, current_version,
            )
            return

        if current_version < 1:
            logger.info("Создание схемы версии 1...")
            conn.executescript(SCHEMA_V1_SQL)
            _set_schema_version(conn, 1)
            current_version = 1

        if current_version < 2:
            logger.info("Миграция схемы: версия 1 → 2...")
            conn.executescript(MIGRATION_V1_TO_V2_SQL)
            _set_schema_version(conn, 2)
            current_version = 2

        if current_version < 3:
            logger.info("Миграция схемы: версия 2 → 3 (compromised_keys)...")
            conn.executescript(MIGRATION_V2_TO_V3_SQL)
            _set_schema_version(conn, 3)
            current_version = 3

        conn.commit()
        logger.info(
            "База данных инициализирована: %s (версия схемы: %d)",
            db_path, current_version,
        )

    except sqlite3.Error as e:
        logger.error("Ошибка инициализации БД: %s", e)
        raise
    finally:
        conn.close()


def check_schema(db_path) -> bool:
    """Проверяет, что схема БД инициализирована."""
    db_path = Path(db_path)
    if not db_path.exists():
        return False

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='certificates'"
        )
        return cursor.fetchone() is not None
    finally:
        conn.close()