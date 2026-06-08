# MicroPKI

Минималистичный инструмент для создания инфраструктуры открытых ключей (PKI) в учебных целях.

## Зависимости

- Python 3.10+
- OpenSSL
- cryptography >= 46.0.0
- pytest >= 7.0

## Установка

```bash
git clone https://github.com/michaaans/MicroPKI.git
cd MicroPKI

python3 -m venv venv
source venv/bin/activate

pip install -e .
```

Для запуска тестов:

```bash
pip install -e ".[test]"
pytest
```

## Использование

### Подготовка парольных фраз

```bash
echo -n "MySecure_Passphrase_RootCA" > secrets/ca.pass
echo -n "MySecure_Passphrase_IntermediateCA" > secrets/intermediate.pass
```

### Инициализация базы данных

```bash
micropki db init --db-path ./pki/micropki.db
```

При изменении схемы база данных обновится автоматически:

```bash
micropki db init
# Миграция схемы: версия 1 → 2...
# Миграция на версию 2 завершена (добавлена таблица crl_metadata)
```

### Корневой Удостоверяющий Центр

RSA-4096:

```bash
micropki ca init \
    --subject "/CN=Demo Root CA/O=MicroPKI/C=RU" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file secrets/ca.pass \
    --out-dir pki \
    --validity-days 3650
```

ECC P-384:

```bash
micropki ca init \
    --subject "CN=ECC Root CA,O=MicroPKI" \
    --key-type ecc \
    --key-size 384 \
    --passphrase-file secrets/ca.pass \
    --out-dir pki
```

### Промежуточный Удостоверяющий Центр

```bash
micropki ca issue-intermediate \
    --root-cert pki/certs/ca.cert.pem \
    --root-key pki/private/ca.key.pem \
    --root-pass-file secrets/root.pass \
    --subject "CN=MicroPKI Intermediate CA,O=MicroPKI" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file secrets/intermediate.pass \
    --out-dir pki \
    --validity-days 1825 \
    --pathlen 0
```

### Выпуск сертификатов

Серверный сертификат:

```bash
micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template server \
    --subject "CN=example.com,O=MicroPKI" \
    --san dns:example.com \
    --san dns:www.example.com \
    --san ip:192.168.1.10 \
    --out-dir pki/certs \
    --validity-days 365 \
    --db-path pki/micropki.db
```

Клиентский сертификат:

```bash
micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template client \
    --subject "CN=Alice Smith" \
    --san email:alice@example.com \
    --db-path pki/micropki.db
```

Сертификат подписи кода:

```bash
micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template code_signing \
    --subject "CN=MicroPKI Code Signer" \
    --db-path pki/micropki.db
```

### Управление сертификатами

Просмотр списка:

```bash
micropki ca list-certs
micropki ca list-certs --status valid
micropki ca list-certs --format json
micropki ca show-cert 69C41A28D533E208
```

Отзыв сертификата:

```bash
micropki ca revoke 69C41A28D533E208 --reason keyCompromise
micropki ca revoke 69C41A28D533E208 --reason superseded --force
```

Допустимые причины: `unspecified`, `keyCompromise`, `cACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `removeFromCRL`, `privilegeWithdrawn`, `aACompromise`

### Генерация CRL

```bash
micropki ca gen-crl \
    --ca intermediate \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass

micropki ca gen-crl \
    --ca root \
    --ca-cert pki/certs/ca.cert.pem \
    --ca-key pki/private/ca.key.pem \
    --ca-pass-file secrets/root.pass \
    --next-update 14
```

### HTTP-сервер репозитория

```bash
micropki repo serve
micropki repo serve --host 127.0.0.1 --port 8080 --rate-limit 5 --rate-burst 10
```

Доступные эндпоинты:

```bash
curl http://localhost:8080/ca/root
curl http://localhost:8080/ca/intermediate
curl http://localhost:8080/certificate/69C41A28D533E208
curl http://localhost:8080/crl
curl http://localhost:8080/crl?ca=root
```

### OCSP-ответчик

Выпуск сертификата для ответчика:

```bash
micropki ca issue-ocsp-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --subject "CN=OCSP Responder,O=MicroPKI" \
    --key-type rsa \
    --key-size 2048 \
    --san dns:ocsp.example.com \
    --out-dir pki/certs \
    --validity-days 365 \
    --db-path pki/micropki.db
```

Запуск ответчика:

```bash
micropki ocsp serve \
    --host 127.0.0.1 \
    --port 8081 \
    --db-path pki/micropki.db \
    --responder-cert pki/certs/OCSP_Responder.cert.pem \
    --responder-key pki/certs/OCSP_Responder.key.pem \
    --ca-cert pki/certs/intermediate.cert.pem \
    --cache-ttl 120
```

Проверка статуса через OCSP:

```bash
openssl ocsp \
    -issuer pki/certs/intermediate.cert.pem \
    -cert pki/certs/test.example.com.cert.pem \
    -url http://127.0.0.1:8081/ocsp \
    -resp_text \
    -nonce \
    -CAfile pki/certs/ca-chain.pem \
    -verify_other pki/certs/OCSP_Responder.cert.pem
```

OCSP Nonce защищает от атак повтора: клиент генерирует случайное число и включает его в запрос, ответчик возвращает то же значение. Без nonce злоумышленник может подменить старый ответ со статусом good для уже отозванного сертификата.

### Клиентские операции

Генерация CSR:

```bash
micropki client gen-csr \
    --subject "CN=myapp.local,O=MyOrg" \
    --key-type rsa \
    --key-size 2048 \
    --san dns:myapp.local \
    --san dns:www.myapp.local \
    --out-key ./myapp.key.pem \
    --out-csr ./myapp.csr.pem
```

Запрос сертификата:

```bash
micropki client request-cert \
    --csr ./myapp.csr.pem \
    --template server \
    --ca-url http://localhost:8080 \
    --out-cert ./myapp.cert.pem
```

Проверка цепочки:

```bash
micropki client validate \
    --cert ./myapp.cert.pem \
    --untrusted pki/certs/intermediate.cert.pem \
    --trusted pki/certs/ca.cert.pem \
    --mode chain

micropki client validate \
    --cert ./myapp.cert.pem \
    --untrusted pki/certs/intermediate.cert.pem \
    --trusted pki/certs/ca.cert.pem \
    --mode full \
    --crl pki/crl/intermediate.crl.pem \
    --ocsp http://127.0.0.1:8081/ocsp
```

Коды завершения: `0` — успех, `1` — ошибка.

Проверка статуса отзыва:

```bash
micropki client check-status \
    --cert ./myapp.cert.pem \
    --ca-cert pki/certs/intermediate.cert.pem

micropki client check-status \
    --cert ./myapp.cert.pem \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ocsp-url http://127.0.0.1:8081/ocsp
```

Коды завершения: `0` — good, `1` — revoked, `2` — unknown.

### Аудит

Журнал создаётся автоматически при первой операции CA в `pki/audit/audit.log`.

```bash
micropki audit query --log-file pki/audit/audit.log
micropki audit query --log-file pki/audit/audit.log --operation policy_violation
micropki audit query --log-file pki/audit/audit.log --level AUDIT
micropki audit verify --log-file pki/audit/audit.log
```

### CT-журнал

Журнал прозрачности сертификатов находится в `pki/audit/ct.log`.

```bash
micropki audit ct-verify --serial <СЕРИЙНЫЙ_НОМЕР> --ct-log pki/audit/ct.log
cat pki/audit/ct.log
```

### Компрометация ключа

```bash
micropki ca compromise \
    --cert pki/certs/example.cert.pem \
    --reason keyCompromise \
    --force \
    --db-path pki/micropki.db

micropki ca compromise \
    --cert pki/certs/example.cert.pem \
    --reason keyCompromise \
    --force \
    --db-path pki/micropki.db \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --out-dir pki
```

## Структура проекта

```
MicroPKI/
├── micropki/
│   ├── __init__.py
│   ├── audit.py
│   ├── ca.py
│   ├── certificates.py
│   ├── chain.py
│   ├── cli.py
│   ├── client.py
│   ├── compromise.py
│   ├── config.py
│   ├── crl.py
│   ├── crypto_utils.py
│   ├── csr.py
│   ├── database.py
│   ├── logger.py
│   ├── ocsp.py
│   ├── ocsp_responder.py
│   ├── policy.py
│   ├── ratelimit.py
│   ├── repository.py
│   ├── revocation.py
│   ├── revocation_check.py
│   ├── serial.py
│   ├── server.py
│   ├── templates.py
│   ├── transparency.py
│   └── validation.py
├── tests/
│   ├── test_api.py
│   ├── test_csr.py
│   ├── test_integration_sprint7.sh
│   ├── test_negative.py
│   ├── test_san.py
│   ├── test_serial.py
│   └── test_templates.py
├── pyproject.toml
├── micropki.conf
└── README.md
```

## Выходные файлы

```
pki/
├── private/
│   ├── ca.key.pem
│   └── intermediate.key.pem
├── certs/
│   ├── ca.cert.pem
│   ├── intermediate.cert.pem
│   ├── example.com.cert.pem
│   ├── example.com.key.pem
│   ├── Alice_Smith.cert.pem
│   ├── Alice_Smith.key.pem
│   ├── MicroPKI_Code_Signer.cert.pem
│   └── MicroPKI_Code_Signer.key.pem
├── audit/
│   ├── audit.log
│   ├── chain.dat
│   └── ct.log
├── csrs/
│   └── intermediate.csr.pem
├── crl/
│   └── intermediate.crl.pem
├── micropki.db
└── policy.txt
```
