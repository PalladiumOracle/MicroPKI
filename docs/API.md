# MicroPKI — Справочник REST API

Сервер репозитория запускается командой `micropki repo serve`.
По умолчанию: `http://127.0.0.1:8080`.

---

## GET /certificate/{serial_hex}

Возвращает сертификат по серийному номеру.

**Параметры пути:**
- `serial_hex` — серийный номер в шестнадцатеричном формате (регистронезависимо)

**Ответы:**

| Код | Описание |
| ----- |---------- |
| 200 | PEM-сертификат (`application/x-pem-file`) |
| 400 | Некорректный формат серийного номера |
| 404 | Сертификат не найден |

**Пример:**
```bash
curl http://localhost:8080/certificate/6A2042C281B469D7
```

## GET /ca/{level}
Возвращает сертификат удостоверяющего центра.

**Параметры пути:**

- `level` — root или intermediate
Ответы:

|Код |	Описание |
|---|-----|
|200 |	PEM-сертификат CA |
|400 |	Неподдерживаемый уровень |
|404 |	Файл сертификата не найден |
**Пример:**
```bash
curl http://localhost:8080/ca/root
curl http://localhost:8080/ca/intermediate
```

## GET /crl
Возвращает список отозванных сертификатов (CRL).

**Query-параметры:**

- `ca — root` или `intermediate` (по умолчанию: intermediate)
Ответы:

|Код|	Описание|
|-----|------|
|200|	PEM-файл CRL (application/pkix-crl)|
|404|	CRL не найден (не был сгенерирован)|
**Пример:**
```bash
curl http://localhost:8080/crl
curl "http://localhost:8080/crl?ca=root"
curl "http://localhost:8080/crl?ca=intermediate"
```

## POST /request-cert
Выпускает сертификат по CSR.

**Query-параметры:**

- `template` — шаблон сертификата: `server`, `client`, `code_signing` (обязательно)

**Заголовки запроса:**

- `Content-Type: application/x-pem-file` — обязательно
- `X-API-Key: <ключ>` — если задана переменная окружения `MICROPKI_API_KEY`

**Тело запроса:** CSR в формате PEM

Ответы:

|Код|	Описание|
|------|------|
|201|	PEM-сертификат (application/x-pem-file)|
|400|	Некорректный CSR, недействительная подпись, нарушение политики|
|401|	Неверный или отсутствующий API-ключ|
|500|	Внутренняя ошибка (ключ CA недоступен)|

**Пример:**
```bash
# Без аутентификации (если MICROPKI_API_KEY не задан)
curl -X POST \
    -H "Content-Type: application/x-pem-file" \
    --data-binary @app.csr.pem \
    "http://localhost:8080/request-cert?template=server" \
    -o app.cert.pem

# С аутентификацией
curl -X POST \
    -H "Content-Type: application/x-pem-file" \
    -H "X-API-Key: mysecretkey" \
    --data-binary @app.csr.pem \
    "http://localhost:8080/request-cert?template=server" \
    -o app.cert.pem
```

**Примечание по безопасности:**
Если переменная окружения `MICROPKI_API_KEY` не задана, эндпоинт работает без аутентификации с предупреждением в лог. Это небезопасно для production.

---

## OCSP-ответчик

OCSP-ответчик запускается командой `micropki ocsp serve`.
По умолчанию: `http://127.0.0.1:8081`.

## POST /ocsp
Обрабатывает OCSP-запрос.

**Заголовки:**

- `Content-Type: application/ocsp-request`

**Тело:** OCSP-запрос в формате DER

**Ответ:** OCSP-ответ в формате DER (`application/ocsp-response`)

**Пример через OpenSSL:**

```bash
openssl ocsp \
    -issuer pki/certs/intermediate.cert.pem \
    -cert pki/certs/example.cert.pem \
    -url http://127.0.0.1:8081/ocsp \
    -resp_text
```

## GET /health
Проверка работоспособности OCSP-ответчика.

**Ответ:**

```JSON
{"status": "ok", "service": "MicroPKI OCSP Responder"}
```
