"""Event bus interne minimal (pub/sub synchrone) utilise par le scheduler
pour notifier la progression sans coupler le moteur a la CLI/au logging."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from typing import Any


class EventBus:
    def __init__(self) -> None:
        self._subscribers: dict[str, list[Callable[[dict[str, Any]], None]]] = defaultdict(list)

    def subscribe(self, event_name: str, handler: Callable[[dict[str, Any]], None]) -> None:
        self._subscribers[event_name].append(handler)

    def publish(self, event_name: str, payload: dict[str, Any]) -> None:
        for handler in self._subscribers.get(event_name, []):
            handler(payload)

    def unsubscribe_all(self, event_name: str) -> None:
        self._subscribers[event_name].clear()
