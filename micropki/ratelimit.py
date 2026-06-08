"""
Ограничение скорости запросов (CTL-1, CLI-34).

Реализует алгоритм token bucket на IP-клиента.
Потокобезопасен.
"""

import time
import threading
from collections import defaultdict
from typing import Optional


class TokenBucket:
    """
    Алгоритм token bucket для одного IP-адреса.

    :param rate: количество токенов в секунду (запросов/сек)
    :param burst: максимальный запас токенов
    """

    def __init__(self, rate: float, burst: int) -> None:
        self.rate = rate
        self.burst = burst
        self._tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, tokens: int = 1) -> tuple[bool, float]:
        """
        Пытается потребить tokens токенов.

        :param tokens: количество токенов
        :return: (allowed: bool, retry_after: float) — секунд до следующего разрешения
        """
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._last_refill = now

            # Пополняем токены
            self._tokens = min(
                self.burst,
                self._tokens + elapsed * self.rate,
            )

            if self._tokens >= tokens:
                self._tokens -= tokens
                return True, 0.0
            else:
                # Сколько ждать до следующего разрешения
                retry_after = (tokens - self._tokens) / self.rate
                return False, retry_after


class RateLimiter:
    """
    Ограничитель скорости запросов на IP-клиента.

    Потокобезопасен. Автоматически очищает устаревшие записи.
    """

    def __init__(self, rate: float, burst: int) -> None:
        """
        :param rate: запросов в секунду (0 = отключено)
        :param burst: максимальная вспышка запросов
        """
        self.rate = rate
        self.burst = burst
        self.enabled = rate > 0
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()
        self._cleanup_counter = 0

    def check(self, client_ip: str) -> tuple[bool, float]:
        """
        Проверяет, разрешён ли запрос с данного IP.

        :param client_ip: IP-адрес клиента
        :return: (allowed: bool, retry_after_seconds: float)
        """
        if not self.enabled:
            return True, 0.0

        with self._lock:
            if client_ip not in self._buckets:
                self._buckets[client_ip] = TokenBucket(self.rate, self.burst)
            bucket = self._buckets[client_ip]

            # Периодическая очистка (каждые 1000 запросов)
            self._cleanup_counter += 1
            if self._cleanup_counter >= 1000:
                self._cleanup_counter = 0
                self._cleanup()

        return bucket.consume()

    def _cleanup(self) -> None:
        """Удаляет неактивные bucket'ы (вызывается под блокировкой)."""
        now = time.monotonic()
        to_delete = [
            ip for ip, bucket in self._buckets.items()
            if (now - bucket._last_refill) > 300  # 5 минут неактивности
        ]
        for ip in to_delete:
            del self._buckets[ip]


# Глобальный ограничитель (None = отключён)
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> Optional[RateLimiter]:
    """Возвращает глобальный ограничитель скорости."""
    return _rate_limiter


def init_rate_limiter(rate: float, burst: int) -> Optional[RateLimiter]:
    """
    Инициализирует глобальный ограничитель скорости.

    :param rate: запросов в секунду (0 = отключено)
    :param burst: максимальная вспышка
    :return: экземпляр RateLimiter или None если отключён
    """
    global _rate_limiter
    if rate <= 0:
        _rate_limiter = None
        return None
    _rate_limiter = RateLimiter(rate=rate, burst=burst)
    return _rate_limiter