Зависимости:
- Python 3.8
- cryptography >= 41.0.0
- pytest

Установка и запуск
1. Клонируйте репозиторий
git clone repository-url
cd micropki

2. Установите зависимости
pip install -r requirements.txt

3. Установите пакет в режиме разработки
pip install -e .

4. Создайте файл с парольной фразой
echo "my-secure-passphrase" > passphrase.txt

5. Инициализируйте Root CA
python -m micropki.cli ca init --subject "/CN=Demo Root CA/O=MicroPKI/C=US" --key-type rsa --key-size 4096 --passphrase-file ./passphrase.txt --out-dir ./pki --validity-days 3650 --log-file ./ca-init.log

6. Запустите тесты
make test

Makefile
install:
	pip install -r requirements.txt
	pip install -e .

test:
	pytest tests/ -v

coverage:
	pytest tests/ --cov=micropki --cov-report=term --cov-report=html

Что готово:
- Структура проекта(в процессе)
  
- CLI с аргументами согласно требованиям

- Генерация ключей RSA (4096) и ECC (P-384)

- Самоподписанный сертификат

- Безопасное хранение ключей (шифрование PKCS#8)

- Права доступа к файлам

- Логирование

- Тесты 
