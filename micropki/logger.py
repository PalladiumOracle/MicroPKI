"""
Настройка логирования для MicroPKI.

Каждая запись содержит:
- временную метку ISO 8601 с миллисекундами
- уровень (INFO / WARNING / ERROR)
- описательное сообщение

Если указан --log-file, записи дописываются в файл.
Иначе — выводятся в stderr.
"""

import logging
import sys
from pathlib import Path


def setup_logger(log_file: Path | None = None) -> logging.Logger:
    logger = logging.getLogger("micropki")
    logger.setLevel(logging.DEBUG)

    # не добавляем дублирующие обработчики при повторном вызове
    if logger.handlers:
        logger.handlers.clear()

    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    formatter.default_msec_format = "%s.%03d"

    if log_file is not None:
        # создаём директорию для лог-файла, если её нет
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(str(log_file), mode="a", encoding="utf-8")
    else:
        handler = logging.StreamHandler(sys.stderr)

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger