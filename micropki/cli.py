"""
Парсер аргументов командной строки для MicroPKI.

Подкоманды (спринт 7):
  audit query       — поиск записей аудита
  audit verify      — проверка целостности журнала
  audit ct-verify   — проверка включения в CT-журнал
  ca compromise     — симуляция компрометации ключа
  repo serve        — расширен --rate-limit, --rate-burst
  ocsp serve        — расширен --rate-limit, --rate-burst
  (все прежние команды сохранены)
"""

import argparse
from pathlib import Path


def create_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="micropki",
        description="MicroPKI — учебный УЦ",
    )

    root.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Путь к файлу конфигурации (по умолчанию: micropki.conf)",
    )

    top_sub = root.add_subparsers(
        dest="command",
        title="commands",
        metavar="[ca, db, repo, ocsp, client, audit]",
    )

    # ==================== ca ====================
    ca_parser = top_sub.add_parser("ca", help="Операции с удостоверяющим центром")
    ca_sub = ca_parser.add_subparsers(
        dest="ca_action", title="ca actions", metavar="<action>"
    )

    # --- ca init ---
    ca_init = ca_sub.add_parser("init", help="Создать самоподписанный корневой УЦ")
    ca_init.add_argument("--subject", "-sub", required=True, type=str)
    ca_init.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    ca_init.add_argument("--key-size", choices=[4096, 384], default=None, type=int)
    ca_init.add_argument("--passphrase-file", required=True, type=Path)
    ca_init.add_argument("--out-dir", default=Path("./pki"), type=Path)
    ca_init.add_argument("--validity-days", default=3650, type=int)
    ca_init.add_argument("--log-file", default=None, type=Path)
    ca_init.add_argument("--force", action="store_true", default=False)
    ca_init.add_argument("--db-path", default=None, type=Path)

    # --- ca issue-intermediate ---
    ca_inter = ca_sub.add_parser("issue-intermediate", help="Создать промежуточный УЦ")
    ca_inter.add_argument("--root-cert", required=True, type=Path)
    ca_inter.add_argument("--root-key", required=True, type=Path)
    ca_inter.add_argument("--root-pass-file", required=True, type=Path)
    ca_inter.add_argument("--subject", required=True, type=str)
    ca_inter.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    ca_inter.add_argument("--key-size", choices=[4096, 384], default=None, type=int)
    ca_inter.add_argument("--passphrase-file", required=True, type=Path)
    ca_inter.add_argument("--out-dir", default=Path("./pki"), type=Path)
    ca_inter.add_argument("--validity-days", default=1825, type=int)
    ca_inter.add_argument("--pathlen", default=0, type=int)
    ca_inter.add_argument("--log-file", default=None, type=Path)
    ca_inter.add_argument("--force", action="store_true", default=False)
    ca_inter.add_argument("--db-path", default=Path("./pki/micropki.db"), type=Path)

    # --- ca issue-cert ---
    ca_issue = ca_sub.add_parser("issue-cert", help="Выпустить конечный сертификат")
    ca_issue.add_argument("--ca-cert", required=True, type=Path)
    ca_issue.add_argument("--ca-key", required=True, type=Path)
    ca_issue.add_argument("--ca-pass-file", required=True, type=Path)
    ca_issue.add_argument("--template", required=True,
                          choices=["server", "client", "code_signing"])
    ca_issue.add_argument("--subject", required=False, default=None, type=str)
    ca_issue.add_argument("--san", action="append", default=[])
    ca_issue.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    ca_issue.add_argument("--key-size", default=None, type=int)
    ca_issue.add_argument("--out-dir", default=Path("./pki/certs"), type=Path)
    ca_issue.add_argument("--validity-days", default=365, type=int)
    ca_issue.add_argument("--log-file", default=None, type=Path)
    ca_issue.add_argument("--db-path", default=Path("./pki/micropki.db"), type=Path)
    ca_issue.add_argument("--csr", default=None, type=Path)

    # --- ca issue-ocsp-cert ---
    ca_ocsp = ca_sub.add_parser("issue-ocsp-cert", help="Выпустить сертификат OCSP")
    ca_ocsp.add_argument("--ca-cert", required=True, type=Path)
    ca_ocsp.add_argument("--ca-key", required=True, type=Path)
    ca_ocsp.add_argument("--ca-pass-file", required=True, type=Path)
    ca_ocsp.add_argument("--subject", required=True, type=str)
    ca_ocsp.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    ca_ocsp.add_argument("--key-size", default=None, type=int)
    ca_ocsp.add_argument("--san", action="append", default=[])
    ca_ocsp.add_argument("--out-dir", default=Path("./pki/certs"), type=Path)
    ca_ocsp.add_argument("--validity-days", default=365, type=int)
    ca_ocsp.add_argument("--db-path", default=Path("./pki/micropki.db"), type=Path)
    ca_ocsp.add_argument("--log-file", default=None, type=Path)

    # --- ca list-certs ---
    ca_list = ca_sub.add_parser("list-certs", help="Список выпущенных сертификатов")
    ca_list.add_argument("--status", choices=["valid", "revoked", "expired"],
                         default=None)
    ca_list.add_argument("--format", dest="output_format",
                         choices=["table", "json", "csv"], default="table")
    ca_list.add_argument("--db-path", default=Path("./pki/micropki.db"), type=Path)
    ca_list.add_argument("--log-file", default=None, type=Path)

    # --- ca show-cert ---
    ca_show = ca_sub.add_parser("show-cert", help="Показать сертификат")
    ca_show.add_argument("serial", type=str)
    ca_show.add_argument("--db-path", default=Path("./pki/micropki.db"), type=Path)
    ca_show.add_argument("--log-file", default=None, type=Path)

    # --- ca revoke ---
    ca_revoke = ca_sub.add_parser("revoke", help="Отозвать сертификат")
    ca_revoke.add_argument("serial", type=str)
    ca_revoke.add_argument("--reason", default="unspecified")
    ca_revoke.add_argument("--force", action="store_true", default=False)
    ca_revoke.add_argument("--db-path", default=Path("./pki/micropki.db"), type=Path)
    ca_revoke.add_argument("--log-file", default=None, type=Path)

    # --- ca gen-crl ---
    ca_gencrl = ca_sub.add_parser("gen-crl", help="Сгенерировать CRL")
    ca_gencrl.add_argument("--ca", required=True)
    ca_gencrl.add_argument("--ca-cert", required=True, type=Path)
    ca_gencrl.add_argument("--ca-key", required=True, type=Path)
    ca_gencrl.add_argument("--ca-pass-file", required=True, type=Path)
    ca_gencrl.add_argument("--next-update", default=7, type=int)
    ca_gencrl.add_argument("--out-file", default=None, type=Path)
    ca_gencrl.add_argument("--out-dir", default=Path("./pki"), type=Path)
    ca_gencrl.add_argument("--db-path", default=Path("./pki/micropki.db"), type=Path)
    ca_gencrl.add_argument("--log-file", default=None, type=Path)

    # --- ca compromise (CLI-33) ---
    ca_compromise = ca_sub.add_parser(
        "compromise",
        help="Симуляция компрометации закрытого ключа (CLI-33)",
    )
    ca_compromise.add_argument(
        "--cert", required=True, type=Path,
        help="Путь к сертификату, чей ключ скомпрометирован",
    )
    ca_compromise.add_argument(
        "--reason", default="keyCompromise",
        help="Причина отзыва (по умолч.: keyCompromise)",
    )
    ca_compromise.add_argument(
        "--force", action="store_true", default=False,
        help="Без запроса подтверждения",
    )
    ca_compromise.add_argument(
        "--db-path", default=Path("./pki/micropki.db"), type=Path
    )
    ca_compromise.add_argument(
        "--out-dir", default=Path("./pki"), type=Path,
        help="Каталог для экстренного CRL",
    )
    ca_compromise.add_argument(
        "--ca-cert", default=None, type=Path,
        help="CA-сертификат для генерации экстренного CRL (опционально)",
    )
    ca_compromise.add_argument(
        "--ca-key", default=None, type=Path,
        help="CA-ключ для генерации экстренного CRL (опционально)",
    )
    ca_compromise.add_argument(
        "--ca-pass-file", default=None, type=Path,
        help="Парольная фраза CA-ключа (опционально)",
    )
    ca_compromise.add_argument("--log-file", default=None, type=Path)

    # ==================== db ====================
    db_parser = top_sub.add_parser("db", help="Управление базой данных")
    db_sub = db_parser.add_subparsers(
        dest="db_action", title="db actions", metavar="<action>"
    )
    db_init = db_sub.add_parser("init", help="Инициализировать базу данных")
    db_init.add_argument("--db-path", default=Path("./pki/micropki.db"), type=Path)
    db_init.add_argument("--log-file", default=None, type=Path)

    # ==================== repo ====================
    repo_parser = top_sub.add_parser("repo", help="Управление репозиторием")
    repo_sub = repo_parser.add_subparsers(
        dest="repo_action", title="repo actions", metavar="<action>"
    )
    repo_serve = repo_sub.add_parser("serve", help="Запустить HTTP-сервер репозитория")
    repo_serve.add_argument("--host", default="127.0.0.1")
    repo_serve.add_argument("--port", default=8080, type=int)
    repo_serve.add_argument("--db-path", default=Path("./pki/micropki.db"), type=Path)
    repo_serve.add_argument("--cert-dir", default=Path("./pki/certs"), type=Path)
    repo_serve.add_argument("--log-file", default=None, type=Path)
    # CLI-34: rate limit
    repo_serve.add_argument(
        "--rate-limit", default=0, type=float,
        help="Запросов в секунду с одного IP (0 = отключено)",
    )
    repo_serve.add_argument(
        "--rate-burst", default=10, type=int,
        help="Допустимая вспышка запросов (по умолч.: 10)",
    )

    # ==================== ocsp ====================
    ocsp_parser = top_sub.add_parser("ocsp", help="Управление OCSP-ответчиком")
    ocsp_sub = ocsp_parser.add_subparsers(
        dest="ocsp_action", title="ocsp actions", metavar="<action>"
    )
    ocsp_serve = ocsp_sub.add_parser("serve", help="Запустить OCSP-ответчик")
    ocsp_serve.add_argument("--host", default="127.0.0.1")
    ocsp_serve.add_argument("--port", default=8081, type=int)
    ocsp_serve.add_argument("--db-path", default=Path("./pki/micropki.db"), type=Path)
    ocsp_serve.add_argument("--responder-cert", required=True, type=Path)
    ocsp_serve.add_argument("--responder-key", required=True, type=Path)
    ocsp_serve.add_argument("--ca-cert", required=True, type=Path)
    ocsp_serve.add_argument("--cache-ttl", default=60, type=int)
    ocsp_serve.add_argument("--log-file", default=None, type=Path)
    # CLI-34: rate limit
    ocsp_serve.add_argument(
        "--rate-limit", default=0, type=float,
        help="Запросов в секунду с одного IP (0 = отключено)",
    )
    ocsp_serve.add_argument(
        "--rate-burst", default=10, type=int,
        help="Допустимая вспышка запросов (по умолч.: 10)",
    )

    # ==================== client ====================
    client_parser = top_sub.add_parser(
        "client", help="Клиентские операции (CSR, проверка, отзыв)"
    )
    client_sub = client_parser.add_subparsers(
        dest="client_action", title="client actions", metavar="<action>"
    )

    c_gencsr = client_sub.add_parser("gen-csr", help="Сгенерировать ключ и CSR")
    c_gencsr.add_argument("--subject", required=True, type=str)
    c_gencsr.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    c_gencsr.add_argument("--key-size", default=None, type=int)
    c_gencsr.add_argument("--san", action="append", default=[])
    c_gencsr.add_argument("--out-key", default=Path("./key.pem"), type=Path)
    c_gencsr.add_argument("--out-csr", default=Path("./request.csr.pem"), type=Path)
    c_gencsr.add_argument("--log-file", default=None, type=Path)

    c_reqcert = client_sub.add_parser(
        "request-cert", help="Запросить сертификат у CA через API"
    )
    c_reqcert.add_argument("--csr", required=True, type=Path)
    c_reqcert.add_argument("--template", required=True,
                           choices=["server", "client", "code_signing"])
    c_reqcert.add_argument("--ca-url", required=True, type=str)
    c_reqcert.add_argument("--out-cert", default=Path("./cert.pem"), type=Path)
    c_reqcert.add_argument("--api-key", default=None, type=str)
    c_reqcert.add_argument("--log-file", default=None, type=Path)

    c_validate = client_sub.add_parser(
        "validate", help="Проверить цепочку сертификатов"
    )
    c_validate.add_argument("--cert", required=True, type=Path)
    c_validate.add_argument("--untrusted", action="append", default=[], type=Path)
    c_validate.add_argument(
        "--trusted", default=Path("./pki/certs/ca.cert.pem"), type=Path
    )
    c_validate.add_argument("--crl", default=None, type=str)
    c_validate.add_argument("--ocsp", default=None, type=str, dest="ocsp_url")
    c_validate.add_argument("--mode", choices=["chain", "full"], default="full")
    c_validate.add_argument("--validation-time", default=None, type=str)
    c_validate.add_argument("--log-file", default=None, type=Path)

    c_checkstatus = client_sub.add_parser(
        "check-status", help="Проверить статус отзыва"
    )
    c_checkstatus.add_argument("--cert", required=True, type=Path)
    c_checkstatus.add_argument("--ca-cert", required=True, type=Path)
    c_checkstatus.add_argument("--crl", default=None, type=str)
    c_checkstatus.add_argument("--ocsp-url", default=None, type=str)
    c_checkstatus.add_argument("--log-file", default=None, type=Path)

    # ==================== audit ====================
    audit_parser = top_sub.add_parser(
        "audit", help="Управление журналом аудита (CLI-31, CLI-32)"
    )
    audit_sub = audit_parser.add_subparsers(
        dest="audit_action", title="audit actions", metavar="<action>"
    )

    # --- audit query (CLI-31) ---
    audit_query = audit_sub.add_parser(
        "query",
        help="Поиск и отображение записей аудита",
    )
    audit_query.add_argument(
        "--log-file",
        default=Path("./pki/audit/audit.log"),
        type=Path,
        help="Путь к журналу аудита",
    )
    audit_query.add_argument(
        "--from", dest="from_ts", default=None, type=str,
        help="Начальная метка времени (ISO 8601)",
    )
    audit_query.add_argument(
        "--to", dest="to_ts", default=None, type=str,
        help="Конечная метка времени (ISO 8601)",
    )
    audit_query.add_argument(
        "--level", default=None, type=str,
        help="Уровень записи (INFO, WARNING, ERROR, AUDIT)",
    )
    audit_query.add_argument(
        "--operation", default=None, type=str,
        help="Фильтр по типу операции (issue, revoke, ...)",
    )
    audit_query.add_argument(
        "--serial", default=None, type=str,
        help="Фильтр по серийному номеру",
    )
    audit_query.add_argument(
        "--format", dest="output_format",
        choices=["table", "json", "csv"], default="table",
    )
    audit_query.add_argument(
        "--verify", action="store_true", default=False,
        help="Проверить целостность хеш-цепочки найденных записей",
    )

    # --- audit verify (CLI-32) ---
    audit_verify = audit_sub.add_parser(
        "verify",
        help="Проверить целостность всего журнала аудита",
    )
    audit_verify.add_argument(
        "--log-file",
        default=Path("./pki/audit/audit.log"),
        type=Path,
        help="Путь к журналу аудита",
    )
    audit_verify.add_argument(
        "--chain-file",
        default=Path("./pki/audit/chain.dat"),
        type=Path,
        help="Путь к файлу хеш-цепочки",
    )

    # --- audit ct-verify (CTL-2) ---
    audit_ct_verify = audit_sub.add_parser(
        "ct-verify",
        help="Проверить наличие сертификата в CT-журнале",
    )
    audit_ct_verify.add_argument(
        "--serial", required=True, type=str,
        help="Серийный номер сертификата (hex)",
    )
    audit_ct_verify.add_argument(
        "--ct-log",
        default=Path("./pki/audit/ct.log"),
        type=Path,
        help="Путь к CT-журналу",
    )

    return root