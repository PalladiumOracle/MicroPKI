#!/usr/bin/env bash
# =============================================================================
# TEST-60: Полный интеграционный тест усиления безопасности (спринт 7)
#
# Требования:
#   - установленный MicroPKI (pip install -e .)
#   - Python 3.10+
#   - openssl
#   - curl
#   - порты 8080, 8081 свободны
#
# Запуск:
#   chmod +x tests/test_integration_sprint7.sh
#   ./tests/test_integration_sprint7.sh
# =============================================================================

set -e  # прервать при ошибке

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # без цвета

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

pass_test() {
    PASS_COUNT=$((PASS_COUNT + 1))
    TOTAL=$((TOTAL + 1))
    echo -e "${GREEN}  PASS: $1${NC}"
}

fail_test() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    TOTAL=$((TOTAL + 1))
    echo -e "${RED}  FAIL: $1${NC}"
}

section() {
    echo ""
    echo -e "${YELLOW}=== $1 ===${NC}"
}

cleanup() {
    echo ""
    echo "Очистка..."
    # Убиваем фоновые процессы
    [ -n "$REPO_PID" ] && kill $REPO_PID 2>/dev/null || true
    # Удаляем временные файлы
    rm -rf "$WORKDIR"
    echo "Очистка завершена"
}

trap cleanup EXIT

# =============================================================================
# Подготовка
# =============================================================================

section "Подготовка рабочей среды"

WORKDIR=$(mktemp -d -t micropki_test_XXXXXX)
echo "Рабочий каталог: $WORKDIR"
cd "$WORKDIR"

# Создаём структуру
mkdir -p pki/certs pki/private pki/crl pki/csrs pki/ocsp pki/audit
mkdir -p secrets

# Создаём пароли
echo -n "TestRootPass123" > secrets/root.pass
echo -n "TestInterPass123" > secrets/intermediate.pass

# Инициализируем БД
micropki db init --db-path pki/micropki.db
pass_test "Инициализация БД"

# Корневой CA
micropki ca init \
    --subject "CN=Test Root CA,O=Integration Test" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file secrets/root.pass \
    --out-dir pki \
    --validity-days 3650 \
    --db-path pki/micropki.db \
    --force

if [ -f pki/certs/ca.cert.pem ]; then
    pass_test "Корневой CA создан"
else
    fail_test "Корневой CA не создан"
fi

# Промежуточный CA
micropki ca issue-intermediate \
    --root-cert pki/certs/ca.cert.pem \
    --root-key pki/private/ca.key.pem \
    --root-pass-file secrets/root.pass \
    --subject "CN=Test Intermediate CA,O=Integration Test" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file secrets/intermediate.pass \
    --out-dir pki \
    --validity-days 1825 \
    --pathlen 0 \
    --db-path pki/micropki.db \
    --force

if [ -f pki/certs/intermediate.cert.pem ]; then
    pass_test "Промежуточный CA создан"
else
    fail_test "Промежуточный CA не создан"
fi

# =============================================================================
# Шаг 1: Запуск репозитория с rate limiting
# =============================================================================

section "Шаг 1: Запуск репозитория с rate limiting"

MICROPKI_CA_PASS="$(cat secrets/intermediate.pass)" \
micropki repo serve \
    --host 127.0.0.1 \
    --port 8080 \
    --rate-limit 2 \
    --rate-burst 3 \
    --db-path pki/micropki.db \
    --cert-dir pki/certs &
REPO_PID=$!

sleep 2

# Проверяем что сервер запущен
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/ca/root 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    pass_test "Репозиторий запущен на порту 8080"
else
    fail_test "Репозиторий не отвечает (HTTP $HTTP_CODE)"
fi

# =============================================================================
# Шаг 2: Нарушения политик — все должны быть заблокированы
# =============================================================================

section "Шаг 2: Нарушения политик"

# 2.1 Маленький ключ
echo -n "Попытка RSA-1024... "
OUTPUT=$(micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template server \
    --subject "CN=small.example.com" \
    --san dns:small.example.com \
    --key-type rsa \
    --key-size 1024 \
    --out-dir pki/certs \
    --db-path pki/micropki.db 2>&1 || true)

if echo "$OUTPUT" | grep -qi "политик\|policy\|1024\|2048"; then
    pass_test "RSA-1024 отклонён"
else
    fail_test "RSA-1024 не отклонён: $OUTPUT"
fi

# 2.2 Длинный срок действия
echo -n "Попытка 400 дней... "
OUTPUT=$(micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template server \
    --subject "CN=longlife.example.com" \
    --san dns:longlife.example.com \
    --validity-days 400 \
    --out-dir pki/certs \
    --db-path pki/micropki.db 2>&1 || true)

if echo "$OUTPUT" | grep -qi "политик\|policy\|365\|400"; then
    pass_test "Срок 400 дней отклонён"
else
    fail_test "Срок 400 дней не отклонён: $OUTPUT"
fi

# 2.3 Wildcard SAN
echo -n "Попытка wildcard SAN... "
OUTPUT=$(micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template server \
    --subject "CN=wildcard.example.com" \
    --san "dns:*.example.com" \
    --out-dir pki/certs \
    --db-path pki/micropki.db 2>&1 || true)

if echo "$OUTPUT" | grep -qi "wildcard\|политик\|policy"; then
    pass_test "Wildcard SAN отклонён"
else
    fail_test "Wildcard SAN не отклонён: $OUTPUT"
fi

# 2.4 Запрещённый тип SAN для code_signing
echo -n "Попытка email SAN для code_signing... "
OUTPUT=$(micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template code_signing \
    --subject "CN=badsigner.example.com" \
    --san "email:dev@example.com" \
    --out-dir pki/certs \
    --db-path pki/micropki.db 2>&1 || true)

if echo "$OUTPUT" | grep -qi "email\|запрещён\|политик\|policy"; then
    pass_test "email SAN для code_signing отклонён"
else
    fail_test "email SAN для code_signing не отклонён: $OUTPUT"
fi

# =============================================================================
# Шаг 3: Валидный выпуск сертификата с записью в CT и аудит
# =============================================================================

section "Шаг 3: Валидный выпуск с CT и аудитом"

micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template server \
    --subject "CN=valid-cert.example.com" \
    --san dns:valid-cert.example.com \
    --out-dir pki/certs \
    --db-path pki/micropki.db

if [ -f pki/certs/valid-cert.example.com.cert.pem ]; then
    pass_test "Валидный сертификат выпущен"
else
    fail_test "Валидный сертификат не выпущен"
fi

# Проверяем CT-журнал
SERIAL_VALID=$(micropki ca list-certs --db-path pki/micropki.db --format json 2>/dev/null | \
    python3 -c "import sys,json; \
    [print(c['serial_hex']) for c in json.load(sys.stdin) \
     if 'valid-cert' in c.get('subject','')]" 2>/dev/null | head -1)

if [ -n "$SERIAL_VALID" ] && grep -q "$SERIAL_VALID" pki/audit/ct.log 2>/dev/null; then
    pass_test "Запись в CT-журнале найдена (serial=$SERIAL_VALID)"
else
    fail_test "Запись в CT-журнале не найдена (serial=$SERIAL_VALID)"
fi

# Проверяем аудит
if [ -f pki/audit/audit.log ] && grep -q "issue_certificate" pki/audit/audit.log; then
    pass_test "Запись аудита о выпуске сертификата присутствует"
else
    fail_test "Запись аудита о выпуске не найдена"
fi

# Проверяем записи о нарушениях политик в аудите
POLICY_COUNT=$(grep -c "policy_violation" pki/audit/audit.log 2>/dev/null || echo "0")
if [ "$POLICY_COUNT" -ge 4 ]; then
    pass_test "Все 4 нарушения политик зафиксированы в аудите ($POLICY_COUNT записей)"
else
    fail_test "Не все нарушения в аудите (найдено: $POLICY_COUNT, ожидалось >= 4)"
fi

# =============================================================================
# Шаг 4: Компрометация ключа → экстренный CRL → блокировка повторного выпуска
# =============================================================================

section "Шаг 4: Компрометация ключа"

micropki ca compromise \
    --cert pki/certs/valid-cert.example.com.cert.pem \
    --reason keyCompromise \
    --force \
    --db-path pki/micropki.db \
    --out-dir pki \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass

# Проверяем статус — должен быть revoked
STATUS=$(micropki ca list-certs --db-path pki/micropki.db --format json 2>/dev/null | \
    python3 -c "import sys,json; \
    [print(c['status']) for c in json.load(sys.stdin) \
     if 'valid-cert' in c.get('subject','')]" 2>/dev/null | head -1)

if [ "$STATUS" = "revoked" ]; then
    pass_test "Сертификат отозван после компрометации"
else
    fail_test "Сертификат НЕ отозван после компрометации (статус: $STATUS)"
fi

# Проверяем CRL обновлён
if [ -f pki/crl/intermediate.crl.pem ]; then
    pass_test "Экстренный CRL создан"
else
    fail_test "Экстренный CRL не создан"
fi

# Проверяем аудит компрометации
if grep -q "key_compromise" pki/audit/audit.log 2>/dev/null; then
    pass_test "Запись аудита о компрометации присутствует"
else
    fail_test "Запись аудита о компрометации не найдена"
fi

# Попытка повторного выпуска с тем же ключом (если ключ существует)
KEY_FILE="pki/certs/valid-cert.example.com.key.pem"
if [ -f "$KEY_FILE" ]; then
    openssl req -new \
        -key "$KEY_FILE" \
        -subj "/CN=reuse-key.example.com" \
        -addext "subjectAltName=DNS:reuse-key.example.com" \
        -out /tmp/reuse.csr.pem 2>/dev/null || true

    if [ -f /tmp/reuse.csr.pem ]; then
        OUTPUT=$(micropki ca issue-cert \
            --ca-cert pki/certs/intermediate.cert.pem \
            --ca-key pki/private/intermediate.key.pem \
            --ca-pass-file secrets/intermediate.pass \
            --template server \
            --csr /tmp/reuse.csr.pem \
            --out-dir pki/certs \
            --db-path pki/micropki.db 2>&1 || true)

        if echo "$OUTPUT" | grep -qi "скомпрометирован\|compromis"; then
            pass_test "Повторный выпуск со скомпрометированным ключом заблокирован"
        else
            fail_test "Повторный выпуск НЕ заблокирован: $OUTPUT"
        fi
    else
        echo "  (пропуск: не удалось создать CSR для повторного выпуска)"
    fi
else
    echo "  (пропуск: ключ сертификата не найден для повторного теста)"
fi

# =============================================================================
# Шаг 5: Проверяем целостность аудита до подделки
# =============================================================================

section "Шаг 5: Проверка целостности аудита"

OUTPUT=$(micropki audit verify \
    --log-file pki/audit/audit.log \
    --chain-file pki/audit/chain.dat 2>&1)

if echo "$OUTPUT" | grep -q "подтверждена\|Целостность"; then
    pass_test "Целостность журнала подтверждена (до подделки)"
else
    fail_test "Целостность не подтверждена: $OUTPUT"
fi

# Делаем копию для подделки
cp pki/audit/audit.log pki/audit/audit.log.backup

# Подделываем один байт
python3 -c "
data = open('pki/audit/audit.log', 'rb').read()
lines = data.split(b'\n')
# Меняем байт во второй строке
content_lines = [l for l in lines if l.strip()]
if len(content_lines) >= 2:
    mid = len(content_lines[1]) // 2
    line = bytearray(content_lines[1])
    line[mid] ^= 1
    idx = lines.index(content_lines[1])
    lines[idx] = bytes(line)
open('pki/audit/audit.log', 'wb').write(b'\n'.join(lines))
"

# Проверяем после подделки
OUTPUT=$(micropki audit verify \
    --log-file pki/audit/audit.log \
    --chain-file pki/audit/chain.dat 2>&1 || true)
EXIT_CODE=$?

if echo "$OUTPUT" | grep -qi "НАРУШЕНИЕ\|integrity\|нарушен\|не совпадает"; then
    pass_test "Подделка журнала обнаружена"
else
    fail_test "Подделка журнала НЕ обнаружена: $OUTPUT"
fi

# Восстанавливаем
cp pki/audit/audit.log.backup pki/audit/audit.log

# =============================================================================
# Шаг 6: Rate limiting
# =============================================================================

section "Шаг 6: Проверка rate limiting"

# Отправляем 6 быстрых запросов
RATE_RESULTS=""
for i in $(seq 1 6); do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/ca/root 2>/dev/null || echo "000")
    RATE_RESULTS="$RATE_RESULTS $CODE"
done

# Проверяем что есть хотя бы один 429
if echo "$RATE_RESULTS" | grep -q "429"; then
    pass_test "Rate limiting работает (коды: $RATE_RESULTS)"
else
    fail_test "Rate limiting не сработал (коды: $RATE_RESULTS)"
fi

# =============================================================================
# Итог
# =============================================================================

echo ""
echo "==========================================="
echo -e "Результат: ${GREEN}$PASS_COUNT PASS${NC} / ${RED}$FAIL_COUNT FAIL${NC} / $TOTAL TOTAL"
echo "==========================================="

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo -e "${RED}ЕСТЬ ОШИБКИ!${NC}"
    exit 1
else
    echo -e "${GREEN}ВСЕ ТЕСТЫ ПРОЙДЕНЫ!${NC}"
    exit 0
fi