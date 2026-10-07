from __future__ import annotations

import asyncio

import pytest

from adsec.core.scheduler.circuit_breaker import CircuitBreaker, CircuitOpenError, CircuitState
from adsec.core.scheduler.rate_limiter import TokenBucketRateLimiter
from adsec.core.scheduler.scheduler import (
    Scheduler,
    SchedulerSafetyConfig,
    Task,
    TaskStatus,
)


@pytest.mark.asyncio
async def test_all_tasks_succeed() -> None:
    async def ok() -> str:
        return "done"

    scheduler = Scheduler(SchedulerSafetyConfig(max_workers=4, max_requests_per_second=50))
    tasks = [Task(name=f"t{i}", coro_factory=ok, target_key="dc1") for i in range(10)]
    results = await scheduler.run(tasks)

    assert len(results) == 10
    assert all(r.status == TaskStatus.SUCCEEDED for r in results)


@pytest.mark.asyncio
async def test_task_retries_then_succeeds() -> None:
    attempts = {"count": 0}

    async def flaky() -> str:
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise RuntimeError("erreur transitoire")
        return "ok"

    scheduler = Scheduler(
        SchedulerSafetyConfig(
            max_workers=1,
            max_requests_per_second=50,
            retry_base_delay_seconds=0.01,
            retry_max_delay_seconds=0.02,
        )
    )
    task = Task(name="flaky", coro_factory=flaky, target_key="dc1", max_retries=3)
    results = await scheduler.run([task])

    assert results[0].status == TaskStatus.SUCCEEDED
    assert results[0].attempts == 3


@pytest.mark.asyncio
async def test_task_fails_after_exhausting_retries() -> None:
    async def always_fails() -> None:
        raise RuntimeError("boom")

    scheduler = Scheduler(
        SchedulerSafetyConfig(
            max_workers=1,
            max_requests_per_second=50,
            retry_base_delay_seconds=0.01,
            retry_max_delay_seconds=0.02,
            stop_on_error_rate=1.1,  # desactive l'arret auto pour ce test
        )
    )
    task = Task(name="fail", coro_factory=always_fails, target_key="dc1", max_retries=2)
    results = await scheduler.run([task])

    assert results[0].status == TaskStatus.FAILED
    assert results[0].attempts == 3  # 1 essai + 2 retries
    assert "boom" in (results[0].error or "")


@pytest.mark.asyncio
async def test_timeout_is_treated_as_failure() -> None:
    async def slow() -> None:
        await asyncio.sleep(1.0)

    scheduler = Scheduler(SchedulerSafetyConfig(max_workers=1, max_requests_per_second=50))
    task = Task(
        name="slow", coro_factory=slow, target_key="dc1", timeout_seconds=0.05, max_retries=0
    )
    results = await scheduler.run([task])

    assert results[0].status == TaskStatus.FAILED
    assert "timeout" in (results[0].error or "")


@pytest.mark.asyncio
async def test_kill_switch_stops_pending_tasks() -> None:
    async def slow_success() -> str:
        await asyncio.sleep(0.05)
        return "ok"

    scheduler = Scheduler(SchedulerSafetyConfig(max_workers=1, max_requests_per_second=50))
    scheduler.request_stop()
    tasks = [Task(name=f"t{i}", coro_factory=slow_success, target_key="dc1") for i in range(5)]
    results = await scheduler.run(tasks)

    assert all(r.status == TaskStatus.CANCELLED for r in results)


@pytest.mark.asyncio
async def test_scope_check_skips_task() -> None:
    async def ok() -> str:
        return "ok"

    scheduler = Scheduler(SchedulerSafetyConfig(max_workers=1, max_requests_per_second=50))
    task = Task(name="out-of-scope", coro_factory=ok, target_key="dc1", scope_check=lambda: False)
    results = await scheduler.run([task])

    assert results[0].status == TaskStatus.SKIPPED_OUT_OF_SCOPE


@pytest.mark.asyncio
async def test_stop_on_error_rate_triggers_after_min_tasks() -> None:
    async def always_fails() -> None:
        raise RuntimeError("boom")

    scheduler = Scheduler(
        SchedulerSafetyConfig(
            max_workers=1,
            max_requests_per_second=50,
            retry_base_delay_seconds=0.001,
            retry_max_delay_seconds=0.001,
            stop_on_error_rate=0.3,
            min_tasks_before_error_rate_check=3,
        )
    )
    tasks = [
        Task(name=f"t{i}", coro_factory=always_fails, target_key="dc1", max_retries=0)
        for i in range(10)
    ]
    results = await scheduler.run(tasks)

    statuses = {r.status for r in results}
    assert TaskStatus.CANCELLED in statuses
    assert scheduler.is_stopping()


def test_rate_limiter_enforces_delay() -> None:
    async def run_test() -> float:
        import time

        limiter = TokenBucketRateLimiter(rate=10, burst=1)
        await limiter.acquire()
        start = time.monotonic()
        await limiter.acquire()
        return time.monotonic() - start

    elapsed = asyncio.run(run_test())
    assert elapsed >= 0.08  # ~1/10s attendu entre deux jetons avec burst=1


def test_circuit_breaker_opens_after_threshold() -> None:
    breaker = CircuitBreaker(failure_threshold=3, reset_timeout_seconds=60)
    for _ in range(3):
        breaker.on_failure("dc1")
    assert breaker.state_of("dc1") == CircuitState.OPEN
    with pytest.raises(CircuitOpenError):
        breaker.before_call("dc1")


def test_circuit_breaker_closes_on_success() -> None:
    breaker = CircuitBreaker(failure_threshold=2, reset_timeout_seconds=60)
    breaker.on_failure("dc1")
    breaker.on_success("dc1")
    assert breaker.state_of("dc1") == CircuitState.CLOSED
    breaker.before_call("dc1")  # ne doit pas lever
