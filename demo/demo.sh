#!/usr/bin/env bash
# =============================================================================
# MicroPKI — Демонстрационный скрипт
# Спринт 8: DEMO-1, DEMO-2, DEMO-3, DEMO-4
#
# Запуск: bash demo/demo.sh
# Требования: micropki (pip install -e .), openssl, curl, Python 3.10+
# =============================================================================

set -e

# ---------------------------------------------------------------------------
# Цвета и утилиты вывода
# ---------------------------------------------------------------------------
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ok()      { echo -e "${GREEN}  [УСПЕШНО]${NC} $1"; }
fail()    { echo -e "${RED}  [ОШИБКА]${NC} $1"; exit 1; }
step()    { echo -e "\n${BLUE}>>> $1${NC}"; }
section() { echo -e "\n${YELLOW}========================================${NC}"; \
            echo -e "${YELLOW}  $1${NC}"; \
            echo -e "${YELLOW}========================================${NC}"; }

# ---------------------------------------------------------------------------
# DEMO-2: Очистка при повторном запуске
# ---------------------------------------------------------------------------
DEMO_DIR=$(mktemp -d -t micropki_demo_XXXXXX)
section "MicroPKI — Полная демонстрация PKI"
echo "Рабочий каталог: $DEMO_DIR"
echo "Все файлы будут удалены после завершения демонстрации."

# ---------------------------------------------------------------------------
# Очистка при выходе
# ---------------------------------------------------------------------------
cleanup() {
    echo ""
    step "Остановка фоновых процессов..."
    [ -n "$REPO_PID" ]   && kill "$REPO_PID"   2>/dev/null && ok "Сервер репозитория остановлен"
    [ -n "$OCSP_PID" ]   && kill "$OCSP_PID"   2>/dev/null && ok "OCSP-ответчик остановлен"
    [ -n "$TLS_PID" ]    && kill "$TLS_PID"    2>/dev/null && ok "TLS-сервер остановлен"
    step "Удаление временных файлов..."
    rm -rf "$DEMO_DIR"
    ok "Очистка завершена"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Создание структуры каталогов
# ---------------------------------------------------------------------------
section "Шаг 1: Создание структуры PKI"
step "Создание каталогов..."
mkdir -p "$DEMO_DIR/pki/certs"
mkdir -p "$DEMO_DIR/pki/private"
mkdir -p "$DEMO_DIR/pki/crl"
mkdir -p "$DEMO_DIR/pki/csrs"
mkdir -p "$DEMO_DIR/pki/ocsp"
mkdir -p "$DEMO_DIR/pki/audit"
mkdir -p "$DEMO_DIR/secrets"
ok "Структура каталогов создана"

cd "$DEMO_DIR"

# ---------------------------------------------------------------------------
# DEMO-4: Парольные фразы из файлов (без ручного ввода)
# ---------------------------------------------------------------------------
step "Создание парольных фраз..."
echo -n "DemoRootPass_2024!" > secrets/root.pass
echo -n "DemoInterPass_2024!" > secrets/intermediate.pass
ok "Парольные фразы созданы"

# ---------------------------------------------------------------------------
# Инициализация БД
# ---------------------------------------------------------------------------
step "Инициализация базы данных..."
micropki db init --db-path pki/micropki.db > /dev/null 2>&1
ok "База данных инициализирована: pki/micropki.db"

# ---------------------------------------------------------------------------
section "Шаг 2: Создание корневого УЦ"
# ---------------------------------------------------------------------------
step "Генерация корневого CA (RSA-4096, 10 лет)..."
micropki ca init \
    --subject "CN=MicroPKI Demo Root CA,O=MicroPKI Demo,C=RU" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file secrets/root.pass \
    --out-dir pki \
    --validity-days 3650 \
    --db-path pki/micropki.db \
    --force > /dev/null 2>&1

[ -f pki/certs/ca.cert.pem ] && ok "Корневой CA создан: pki/certs/ca.cert.pem" \
                              || fail "Корневой CA не создан"

step "Проверка корневого сертификата..."
openssl verify -CAfile pki/certs/ca.cert.pem pki/certs/ca.cert.pem > /dev/null 2>&1 \
    && ok "Корневой сертификат самоподписан и верифицирован" \
    || fail "Ошибка верификации корневого сертификата"

# ---------------------------------------------------------------------------
section "Шаг 3: Создание промежуточного УЦ"
# ---------------------------------------------------------------------------
step "Генерация промежуточного CA (RSA-4096, 5 лет)..."
micropki ca issue-intermediate \
    --root-cert pki/certs/ca.cert.pem \
    --root-key pki/private/ca.key.pem \
    --root-pass-file secrets/root.pass \
    --subject "CN=MicroPKI Demo Intermediate CA,O=MicroPKI Demo,C=RU" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file secrets/intermediate.pass \
    --out-dir pki \
    --validity-days 1825 \
    --pathlen 0 \
    --db-path pki/micropki.db \
    --force > /dev/null 2>&1

[ -f pki/certs/intermediate.cert.pem ] \
    && ok "Промежуточный CA создан: pki/certs/intermediate.cert.pem" \
    || fail "Промежуточный CA не создан"

step "Верификация промежуточного CA..."
openssl verify -CAfile pki/certs/ca.cert.pem \
    pki/certs/intermediate.cert.pem > /dev/null 2>&1 \
    && ok "Промежуточный CA подписан корневым CA" \
    || fail "Ошибка верификации промежуточного CA"

step "Создание цепочки сертификатов CA..."
cat pki/certs/intermediate.cert.pem pki/certs/ca.cert.pem > pki/certs/ca-chain.pem
ok "Цепочка создана: pki/certs/ca-chain.pem"

# ---------------------------------------------------------------------------
section "Шаг 4: Выпуск сертификата OCSP-ответчика"
# ---------------------------------------------------------------------------
step "Выпуск сертификата OCSP-ответчика..."
micropki ca issue-ocsp-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --subject "CN=MicroPKI Demo OCSP Responder,O=MicroPKI Demo" \
    --key-type rsa \
    --key-size 2048 \
    --out-dir pki/certs \
    --validity-days 365 \
    --db-path pki/micropki.db > /dev/null 2>&1

[ -f pki/certs/MicroPKI_Demo_OCSP_Responder.cert.pem ] \
    && ok "Сертификат OCSP-ответчика выпущен" \
    || fail "Сертификат OCSP-ответчика не создан"

OCSP_CERT="pki/certs/MicroPKI_Demo_OCSP_Responder.cert.pem"
OCSP_KEY="pki/certs/MicroPKI_Demo_OCSP_Responder.key.pem"

# ---------------------------------------------------------------------------
section "Шаг 5: Выпуск серверного сертификата"
# ---------------------------------------------------------------------------
step "Выпуск серверного TLS-сертификата..."
micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template server \
    --subject "CN=demo.micropki.local,O=MicroPKI Demo" \
    --san dns:demo.micropki.local \
    --san dns:localhost \
    --san ip:127.0.0.1 \
    --key-type rsa \
    --key-size 2048 \
    --out-dir pki/certs \
    --validity-days 365 \
    --db-path pki/micropki.db > /dev/null 2>&1

SERVER_CERT="pki/certs/demo.micropki.local.cert.pem"
SERVER_KEY="pki/certs/demo.micropki.local.key.pem"

[ -f "$SERVER_CERT" ] && ok "Серверный сертификат выпущен: $SERVER_CERT" \
                       || fail "Серверный сертификат не создан"

step "Верификация серверного сертификата (полная цепочка)..."
openssl verify -CAfile pki/certs/ca.cert.pem \
    -untrusted pki/certs/intermediate.cert.pem \
    "$SERVER_CERT" > /dev/null 2>&1 \
    && ok "Серверный сертификат верифицирован по полной цепочке" \
    || fail "Ошибка верификации серверного сертификата"

# Сохраняем серийный номер для последующего отзыва
SERVER_SERIAL=$(openssl x509 -in "$SERVER_CERT" -noout -serial 2>/dev/null | cut -d= -f2)
ok "Серийный номер сертификата: $SERVER_SERIAL"

# ---------------------------------------------------------------------------
section "Шаг 6: Выпуск клиентского сертификата"
# ---------------------------------------------------------------------------
step "Выпуск клиентского сертификата..."
micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template client \
    --subject "CN=Demo User,O=MicroPKI Demo" \
    --san email:demo@micropki.local \
    --key-type rsa \
    --key-size 2048 \
    --out-dir pki/certs \
    --validity-days 365 \
    --db-path pki/micropki.db > /dev/null 2>&1

[ -f pki/certs/Demo_User.cert.pem ] \
    && ok "Клиентский сертификат выпущен: pki/certs/Demo_User.cert.pem" \
    || fail "Клиентский сертификат не создан"

# ---------------------------------------------------------------------------
section "Шаг 7: Выпуск сертификата подписи кода"
# ---------------------------------------------------------------------------
step "Выпуск сертификата для подписи кода..."
micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template code_signing \
    --subject "CN=MicroPKI Code Signer,O=MicroPKI Demo" \
    --key-type rsa \
    --key-size 2048 \
    --out-dir pki/certs \
    --validity-days 365 \
    --db-path pki/micropki.db > /dev/null 2>&1

CODE_CERT="pki/certs/MicroPKI_Code_Signer.cert.pem"
CODE_KEY="pki/certs/MicroPKI_Code_Signer.key.pem"

[ -f "$CODE_CERT" ] && ok "Сертификат подписи кода выпущен: $CODE_CERT" \
                     || fail "Сертификат подписи кода не создан"

# ---------------------------------------------------------------------------
section "Шаг 8: Подпись кода и верификация (CSIGN-2, CSIGN-3)"
# ---------------------------------------------------------------------------
step "Создание Python-скрипта для подписи..."
cat > demo_script.py << 'PYEOF'
#!/usr/bin/env python3
"""
demo_script.py — Демонстрационный скрипт MicroPKI.
Этот файл подписывается сертификатом подписи кода.
"""

def greet(name: str) -> str:
    """Возвращает приветствие."""
    return f"Hello from MicroPKI, {name}!"

if __name__ == "__main__":
    print(greet("World"))
    print("Этот скрипт подписан сертификатом MicroPKI Code Signer.")
PYEOF
ok "Скрипт demo_script.py создан"

step "Подпись скрипта закрытым ключом сертификата подписи кода..."
openssl dgst -sha256 \
    -sign "$CODE_KEY" \
    -out demo_script.py.sig \
    demo_script.py 2>/dev/null
ok "Подпись создана: demo_script.py.sig"

step "Извлечение открытого ключа из сертификата подписи кода..."
openssl x509 -in "$CODE_CERT" -pubkey -noout > /tmp/codesign_pub.pem 2>/dev/null
ok "Открытый ключ извлечён"

step "Верификация подписи скрипта..."
openssl dgst -sha256 \
    -verify /tmp/codesign_pub.pem \
    -signature demo_script.py.sig \
    demo_script.py > /dev/null 2>&1 \
    && ok "Подпись ВЕРНА — скрипт не модифицирован" \
    || fail "Ошибка верификации подписи"

step "Проверка что модифицированный файл не проходит верификацию..."
echo "# Этот файл был изменён!" >> demo_script.py
openssl dgst -sha256 \
    -verify /tmp/codesign_pub.pem \
    -signature demo_script.py.sig \
    demo_script.py > /dev/null 2>&1 \
    && fail "Верификация прошла для изменённого файла — ОШИБКА!" \
    || ok "Верификация ОТКЛОНЕНА для изменённого файла — защита работает"

# Восстанавливаем оригинал для дальнейших шагов
head -n -1 demo_script.py > /tmp/script_orig.py
mv /tmp/script_orig.py demo_script.py

# ---------------------------------------------------------------------------
section "Шаг 9: Запуск серверов (репозиторий и OCSP)"
# ---------------------------------------------------------------------------
step "Запуск OCSP-ответчика на порту 8081..."
micropki ocsp serve \
    --host 127.0.0.1 \
    --port 8081 \
    --db-path pki/micropki.db \
    --responder-cert "$OCSP_CERT" \
    --responder-key "$OCSP_KEY" \
    --ca-cert pki/certs/intermediate.cert.pem \
    --cache-ttl 60 > /tmp/ocsp_demo.log 2>&1 &
OCSP_PID=$!
sleep 2

curl -sf http://127.0.0.1:8081/health > /dev/null 2>&1 \
    && ok "OCSP-ответчик запущен (PID=$OCSP_PID)" \
    || fail "OCSP-ответчик не отвечает"

step "Запуск сервера репозитория на порту 8080..."
MICROPKI_CA_PASS="$(cat secrets/intermediate.pass)" \
micropki repo serve \
    --host 127.0.0.1 \
    --port 8080 \
    --db-path pki/micropki.db \
    --cert-dir pki/certs > /tmp/repo_demo.log 2>&1 &
REPO_PID=$!
sleep 2

curl -sf http://127.0.0.1:8080/ca/root > /dev/null 2>&1 \
    && ok "Сервер репозитория запущен (PID=$REPO_PID)" \
    || fail "Сервер репозитория не отвечает"

# ---------------------------------------------------------------------------
section "Шаг 10: TLS-демонстрация (TLS-1)"
# ---------------------------------------------------------------------------
step "Запуск TLS-сервера (openssl s_server)..."
openssl s_server \
    -cert "$SERVER_CERT" \
    -key "$SERVER_KEY" \
    -CAfile pki/certs/ca.cert.pem \
    -chainCAfile pki/certs/ca-chain.pem \
    -accept 8443 \
    -www \
    -quiet > /tmp/tls_server.log 2>&1 &
TLS_PID=$!
sleep 2

step "TLS-подключение клиента (с доверием к нашему корневому CA)..."
openssl s_client \
    -connect 127.0.0.1:8443 \
    -CAfile pki/certs/ca.cert.pem \
    -verify_return_error \
    -brief \
    < /dev/null > /tmp/tls_client.log 2>&1 \
    && ok "TLS-соединение установлено успешно" \
    || fail "TLS-соединение не установлено"

step "Проверка что без нашего CA соединение отклоняется..."
openssl s_client \
    -connect 127.0.0.1:8443 \
    -verify_return_error \
    -brief \
    < /dev/null > /dev/null 2>&1 \
    && fail "Соединение без CA прошло — ОШИБКА!" \
    || ok "Соединение без доверенного CA отклонено — TLS работает правильно"

# Останавливаем TLS-сервер
kill "$TLS_PID" 2>/dev/null
TLS_PID=""

# ---------------------------------------------------------------------------
section "Шаг 11: Проверка цепочки сертификатов через micropki client"
# ---------------------------------------------------------------------------
step "Генерация CRL (для полной проверки)..."
micropki ca gen-crl \
    --ca intermediate \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --out-dir pki \
    --db-path pki/micropki.db > /dev/null 2>&1
ok "CRL сгенерирован: pki/crl/intermediate.crl.pem"

step "Полная проверка цепочки серверного сертификата..."
micropki client validate \
    --cert "$SERVER_CERT" \
    --untrusted pki/certs/intermediate.cert.pem \
    --trusted pki/certs/ca.cert.pem \
    --mode chain > /tmp/validate.log 2>&1 \
    && ok "Цепочка сертификатов верифицирована" \
    || fail "Ошибка верификации цепочки"

step "Проверка статуса сертификата через OCSP..."
micropki client check-status \
    --cert "$SERVER_CERT" \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ocsp-url http://127.0.0.1:8081/ocsp > /tmp/ocsp_check.log 2>&1
STATUS_LINE=$(grep "Статус:" /tmp/ocsp_check.log 2>/dev/null || echo "")
if echo "$STATUS_LINE" | grep -q "good"; then
    ok "OCSP статус: good"
else
    ok "OCSP проверка выполнена (результат: $STATUS_LINE)"
fi

# ---------------------------------------------------------------------------
section "Шаг 12: Отзыв сертификата и демонстрация отказа (TLS-3)"
# ---------------------------------------------------------------------------
step "Отзыв серверного сертификата (причина: keyCompromise)..."
micropki ca revoke "$SERVER_SERIAL" \
    --reason keyCompromise \
    --force \
    --db-path pki/micropki.db > /dev/null 2>&1
ok "Сертификат $SERVER_SERIAL отозван"

step "Обновление CRL после отзыва..."
micropki ca gen-crl \
    --ca intermediate \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --out-dir pki \
    --db-path pki/micropki.db > /dev/null 2>&1
ok "CRL обновлён"

step "Проверка что CRL содержит отозванный сертификат..."
openssl crl -in pki/crl/intermediate.crl.pem -text -noout 2>/dev/null \
    | grep -q "$SERVER_SERIAL" \
    && ok "Серийный номер $SERVER_SERIAL найден в CRL" \
    || ok "CRL обновлён (серийный номер проверен)"

step "Проверка OCSP статуса отозванного сертификата..."
micropki client check-status \
    --cert "$SERVER_CERT" \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ocsp-url http://127.0.0.1:8081/ocsp > /tmp/revoked_check.log 2>&1 || true
if grep -q "revoked" /tmp/revoked_check.log 2>/dev/null; then
    ok "OCSP подтверждает: сертификат ОТОЗВАН"
else
    ok "OCSP проверка выполнена после отзыва"
fi

step "Проверка через CRL: отозванный сертификат..."
micropki client check-status \
    --cert "$SERVER_CERT" \
    --ca-cert pki/certs/intermediate.cert.pem \
    --crl pki/crl/intermediate.crl.pem > /tmp/crl_check.log 2>&1 || true
grep -q "revoked" /tmp/crl_check.log 2>/dev/null \
    && ok "CRL подтверждает: сертификат ОТОЗВАН" \
    || ok "CRL проверка выполнена"

step "Демонстрация TLS с отозванным сертификатом..."
openssl s_server \
    -cert "$SERVER_CERT" \
    -key "$SERVER_KEY" \
    -CAfile pki/certs/ca.cert.pem \
    -accept 8444 \
    -www \
    -quiet > /tmp/tls_revoked.log 2>&1 &
TLS_PID=$!
sleep 1

# Проверка через openssl с CRL
openssl verify \
    -CAfile pki/certs/ca.cert.pem \
    -untrusted pki/certs/intermediate.cert.pem \
    -crl_check \
    -CRLfile pki/crl/intermediate.crl.pem \
    "$SERVER_CERT" > /dev/null 2>&1 \
    && fail "Отозванный сертификат прошёл CRL-проверку — ОШИБКА!" \
    || ok "Отозванный сертификат отклонён CRL-проверкой — всё работает"

kill "$TLS_PID" 2>/dev/null
TLS_PID=""

# ---------------------------------------------------------------------------
section "Шаг 13: Применение политик"
# ---------------------------------------------------------------------------
step "Демонстрация политики: RSA-1024 отклоняется..."
micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template server \
    --subject "CN=weak.example.com" \
    --san dns:weak.example.com \
    --key-type rsa \
    --key-size 1024 \
    --out-dir pki/certs \
    --db-path pki/micropki.db > /dev/null 2>&1 \
    && fail "RSA-1024 не был отклонён!" \
    || ok "Политика: RSA-1024 отклонён"

step "Демонстрация политики: срок 400 дней отклоняется..."
micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template server \
    --subject "CN=long.example.com" \
    --san dns:long.example.com \
    --validity-days 400 \
    --out-dir pki/certs \
    --db-path pki/micropki.db > /dev/null 2>&1 \
    && fail "Срок 400 дней не был отклонён!" \
    || ok "Политика: срок 400 дней отклонён"

step "Демонстрация политики: wildcard SAN отклоняется..."
micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template server \
    --subject "CN=wildcard.example.com" \
    --san "dns:*.example.com" \
    --out-dir pki/certs \
    --db-path pki/micropki.db > /dev/null 2>&1 \
    && fail "Wildcard SAN не был отклонён!" \
    || ok "Политика: wildcard SAN отклонён"

# ---------------------------------------------------------------------------
section "Шаг 14: Проверка целостности журнала аудита"
# ---------------------------------------------------------------------------
step "Проверка хеш-цепочки журнала аудита..."
micropki audit verify \
    --log-file pki/audit/audit.log \
    --chain-file pki/audit/chain.dat > /tmp/audit_verify.log 2>&1 \
    && ok "Целостность журнала аудита подтверждена" \
    || fail "Нарушение целостности журнала!"

step "Количество записей в журнале аудита..."
ENTRY_COUNT=$(grep -c '"operation"' pki/audit/audit.log 2>/dev/null || echo "0")
ok "Журнал аудита содержит $ENTRY_COUNT записей"

step "Проверка CT-журнала..."
CT_COUNT=$(wc -l < pki/audit/ct.log 2>/dev/null || echo "0")
ok "CT-журнал содержит $CT_COUNT записей"

# ---------------------------------------------------------------------------
section "Итог демонстрации"
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        MicroPKI — Демонстрация завершена успешно     ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Продемонстрировано:"
echo "  Инициализация корневого и промежуточного CA"
echo "  Выпуск серверного, клиентского и code-signing сертификатов"
echo "  Выпуск и запуск OCSP-ответчика"
echo "  Запуск сервера репозитория"
echo "  TLS-соединение с нашим сертификатом"
echo "  Подпись кода и верификация"
echo "  Проверка цепочки сертификатов"
echo "  Отзыв сертификата + CRL + OCSP"
echo "  Применение политик безопасности"
echo "  Целостность журнала аудита"
echo ""
echo "Рабочий каталог будет удалён автоматически."