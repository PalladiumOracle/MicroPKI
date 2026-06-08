"""
Конфигурация pytest для MicroPKI.

Маркеры:
  perf — тесты производительности (медленные, пропускаются по умолчанию)
"""

import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "perf: тесты производительности (запускать с -m perf)",
    )