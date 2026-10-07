"""Scheduler asynchrone : coeur de l'orchestration des taches de scan.

Fonctionnalites : worker pool, limite globale de concurrence, limite par
cle (ex: par DC), timeout par tache, retry avec exponential backoff + jitter,
circuit breaker par cle, priorites, cancellation cooperative, suivi de
progression, arret propre preservant les resultats deja obtenus.
"""

from __future__ import annotations

import asyncio
import itertools
import random
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import IntEnum

from adsec.core.events.event_bus import EventBus
from adsec.core.scheduler.circuit_breaker import CircuitBreaker, CircuitOpenError
from adsec.core.scheduler.rate_limiter import TokenBucketRateLimiter


class TaskPriority(IntEnum):
    """Plus la valeur est basse, plus la tache est executee tot."""

    DISCOVERY = 0
    COLLECTION = 10
    ANALYSIS = 20
    DEFAULT = 50


class TaskStatus(IntEnum):
    PENDING = 0
    RUNNING = 1
    SUCCEEDED = 2
    FAILED = 3
    CANCELLED = 4
    SKIPPED_CIRCUIT_OPEN = 5
    SKIPPED_OUT_OF_SCOPE = 6


_task_counter: itertools.count[int] = itertools.count(1)


@dataclass
class Task:
    """Une unite de travail planifiable.

    `target_key` identifie la ressource protegee par le rate limiter et le
    circuit breaker (typiquement l'adresse d'un DC). `scope_check` est un
    callable optionnel invoque juste avant execution : s'il retourne False,
    la tache est ecartee sans jamais s'executer (defense en profondeur,
    en plus du controle fait par les collectors eux-memes via ScopeManager).
    """

    name: str
    coro_factory: Callable[[], Awaitable[object]]
    target_key: str = "default"
    priority: TaskPriority = TaskPriority.DEFAULT
    timeout_seconds: float = 30.0
    max_retries: int = 2
    scope_check: Callable[[], bool] | None = None
    id: str = field(default_factory=lambda: f"task-{next(_task_counter)}")


@dataclass
class TaskResult:
    task: Task
    status: TaskStatus
    result: object | None = None
    error: str | None = None
    attempts: int = 0
    duration_seconds: float = 0.0


@dataclass
class SchedulerSafetyConfig:
    max_workers: int = 10
    max_requests_per_second: float = 20.0
    max_duration_minutes: float = 120.0
    stop_on_error_rate: float = 0.30
    per_key_concurrency: int = 4
    retry_base_delay_seconds: float = 0.5
    retry_max_delay_seconds: float = 8.0
    circuit_breaker_failure_threshold: int = 5
    circuit_breaker_reset_seconds: float = 30.0
    min_tasks_before_error_rate_check: int = 5


class ScanAbortedError(Exception):
    """Levee lorsque le scan est interrompu (kill switch, duree max, taux
    d'erreur trop eleve) - les resultats deja obtenus restent disponibles
    via `Scheduler.results`."""


class Scheduler:
    """Ordonnance et execute des `Task` en respectant les contraintes de
    securite operationnelle (voir SchedulerSafetyConfig)."""

    def __init__(
        self,
        config: SchedulerSafetyConfig | None = None,
        event_bus: EventBus | None = None,
    ) -> None:
        self._config = config or SchedulerSafetyConfig()
        self._events = event_bus or EventBus()
        self._global_semaphore = asyncio.Semaphore(self._config.max_workers)
        self._per_key_semaphores: dict[str, asyncio.Semaphore] = {}
        self._rate_limiter = TokenBucketRateLimiter(self._config.max_requests_per_second)
        self._circuit_breaker = CircuitBreaker(
            failure_threshold=self._config.circuit_breaker_failure_threshold,
            reset_timeout_seconds=self._config.circuit_breaker_reset_seconds,
        )
        self._cancel_event = asyncio.Event()
        self._results: list[TaskResult] = []
        self._completed_count = 0
        self._failed_count = 0
        self._deadline: float | None = None

    @property
    def results(self) -> list[TaskResult]:
        return list(self._results)

    @property
    def events(self) -> EventBus:
        return self._events

    def request_stop(self) -> None:
        """Kill switch : demande l'arret cooperatif du scheduler."""
        self._cancel_event.set()

    def is_stopping(self) -> bool:
        return self._cancel_event.is_set()

    def _per_key_semaphore(self, key: str) -> asyncio.Semaphore:
        if key not in self._per_key_semaphores:
            self._per_key_semaphores[key] = asyncio.Semaphore(self._config.per_key_concurrency)
        return self._per_key_semaphores[key]

    async def run(self, tasks: list[Task]) -> list[TaskResult]:
        """Execute un ensemble de taches (une 'phase') en parallele, en
        respectant priorites, limites et kill switch. Retourne quand toutes
        les taches ont ete traitees ou que le scan a ete interrompu."""
        self._deadline = time.monotonic() + self._config.max_duration_minutes * 60.0

        queue: asyncio.Queue[tuple[int, int, Task]] = asyncio.PriorityQueue()
        for seq, task in enumerate(tasks):
            queue.put_nowait((int(task.priority), seq, task))

        workers = [
            asyncio.create_task(self._worker_loop(queue)) for _ in range(self._config.max_workers)
        ]
        await queue.join()
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        return self.results

    async def _worker_loop(self, queue: asyncio.Queue[tuple[int, int, Task]]) -> None:
        while True:
            try:
                _, _, task = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                await self._execute_with_guards(task)
            finally:
                queue.task_done()

    async def _should_abort(self) -> str | None:
        if self._cancel_event.is_set():
            return "arret demande (kill switch)"
        if self._deadline is not None and time.monotonic() >= self._deadline:
            return "duree maximale de scan atteinte"
        total = self._completed_count + self._failed_count
        if total >= self._config.min_tasks_before_error_rate_check:
            error_rate = self._failed_count / total
            if error_rate > self._config.stop_on_error_rate:
                return f"taux d'erreur trop eleve ({error_rate:.0%})"
        return None

    async def _execute_with_guards(self, task: Task) -> None:
        abort_reason = await self._should_abort()
        if abort_reason is not None:
            self._cancel_event.set()
            result = TaskResult(task=task, status=TaskStatus.CANCELLED, error=abort_reason)
            self._results.append(result)
            self._events.publish("task.cancelled", {"task": task.name, "reason": abort_reason})
            return

        if task.scope_check is not None and not task.scope_check():
            result = TaskResult(task=task, status=TaskStatus.SKIPPED_OUT_OF_SCOPE)
            self._results.append(result)
            self._events.publish("task.skipped_out_of_scope", {"task": task.name})
            return

        try:
            self._circuit_breaker.before_call(task.target_key)
        except CircuitOpenError as exc:
            result = TaskResult(task=task, status=TaskStatus.SKIPPED_CIRCUIT_OPEN, error=str(exc))
            self._results.append(result)
            self._events.publish("task.circuit_open", {"task": task.name, "key": task.target_key})
            return

        async with self._global_semaphore, self._per_key_semaphore(task.target_key):
            result = await self._run_with_retries(task)

        self._results.append(result)
        if result.status == TaskStatus.SUCCEEDED:
            self._completed_count += 1
            self._circuit_breaker.on_success(task.target_key)
        elif result.status == TaskStatus.FAILED:
            self._failed_count += 1
            self._circuit_breaker.on_failure(task.target_key)
        self._events.publish(
            "task.finished",
            {"task": task.name, "status": result.status.name, "attempts": result.attempts},
        )

    async def _run_with_retries(self, task: Task) -> TaskResult:
        attempts = 0
        last_error: str | None = None
        start = time.monotonic()

        while attempts <= task.max_retries:
            attempts += 1
            if self._cancel_event.is_set():
                return TaskResult(
                    task=task,
                    status=TaskStatus.CANCELLED,
                    error="annule pendant retry",
                    attempts=attempts,
                    duration_seconds=time.monotonic() - start,
                )
            await self._rate_limiter.acquire()
            try:
                coro = task.coro_factory()
                value = await asyncio.wait_for(coro, timeout=task.timeout_seconds)
                return TaskResult(
                    task=task,
                    status=TaskStatus.SUCCEEDED,
                    result=value,
                    attempts=attempts,
                    duration_seconds=time.monotonic() - start,
                )
            except TimeoutError:
                last_error = f"timeout apres {task.timeout_seconds}s"
            except Exception as exc:  # noqa: BLE001 - isolation deliberee des taches
                last_error = f"{type(exc).__name__}: {exc}"

            if attempts <= task.max_retries:
                delay = min(
                    self._config.retry_max_delay_seconds,
                    self._config.retry_base_delay_seconds * (2 ** (attempts - 1)),
                )
                delay += random.uniform(0, delay * 0.1)  # nosec B311 - jitter non cryptographique
                await asyncio.sleep(delay)

        return TaskResult(
            task=task,
            status=TaskStatus.FAILED,
            error=last_error,
            attempts=attempts,
            duration_seconds=time.monotonic() - start,
        )
