"""Rate limiter de type token bucket, asynchrone, utilise pour limiter le
nombre de requetes/seconde envoyees a une cible (DC) donnee."""

from __future__ import annotations

import asyncio
import time


class TokenBucketRateLimiter:
    """Limite le debit a `rate` acquisitions par seconde, avec une capacite
    de rafale (`burst`) permettant d'absorber de courtes pointes."""

    def __init__(self, rate: float, burst: int | None = None) -> None:
        if rate <= 0:
            raise ValueError("rate doit etre strictement positif")
        self._rate = rate
        self._capacity = float(burst if burst is not None else max(1, int(rate)))
        self._tokens = self._capacity
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        self._last_refill = now

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                deficit = 1.0 - self._tokens
                wait_time = deficit / self._rate
            await asyncio.sleep(wait_time)
