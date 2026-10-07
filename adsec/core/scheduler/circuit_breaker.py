"""Circuit breaker par cle (ex: par controleur de domaine).

Objectif : proteger l'environnement audite et le scan lui-meme en arretant
d'envoyer des requetes vers une cible qui echoue de maniere repetee, plutot
que de continuer a la marteler."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(Exception):
    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(f"Circuit ouvert pour {key!r} : cible temporairement ecartee")


@dataclass
class _CircuitInfo:
    state: CircuitState = CircuitState.CLOSED
    consecutive_failures: int = 0
    opened_at: float | None = None
    half_open_probe_in_flight: bool = False


@dataclass
class CircuitBreaker:
    """Un circuit breaker par cle, avec seuil d'echecs et delai de reset."""

    failure_threshold: int = 5
    reset_timeout_seconds: float = 30.0
    _circuits: dict[str, _CircuitInfo] = field(default_factory=dict)

    def _get(self, key: str) -> _CircuitInfo:
        if key not in self._circuits:
            self._circuits[key] = _CircuitInfo()
        return self._circuits[key]

    def before_call(self, key: str) -> None:
        info = self._get(key)
        if info.state == CircuitState.OPEN:
            opened_at = info.opened_at
            if opened_at is None:
                # Invariant du circuit breaker : un circuit OPEN a toujours
                # une date d'ouverture. On la restaure defensivement plutot
                # que de faire confiance a un assert desactivable.
                opened_at = time.monotonic()
                info.opened_at = opened_at
            if time.monotonic() - opened_at >= self.reset_timeout_seconds:
                info.state = CircuitState.HALF_OPEN
                info.half_open_probe_in_flight = True
            else:
                raise CircuitOpenError(key)
        elif info.state == CircuitState.HALF_OPEN and info.half_open_probe_in_flight:
            # Une seule sonde a la fois pendant la phase half-open.
            raise CircuitOpenError(key)

    def on_success(self, key: str) -> None:
        info = self._get(key)
        info.consecutive_failures = 0
        info.state = CircuitState.CLOSED
        info.opened_at = None
        info.half_open_probe_in_flight = False

    def on_failure(self, key: str) -> None:
        info = self._get(key)
        info.half_open_probe_in_flight = False
        info.consecutive_failures += 1
        if info.consecutive_failures >= self.failure_threshold:
            info.state = CircuitState.OPEN
            info.opened_at = time.monotonic()

    def state_of(self, key: str) -> CircuitState:
        return self._get(key).state
