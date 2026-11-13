import pytest

from lab.retry import backoff_delays, retry, seconds_until_next


def test_backoff_doubles_then_caps():
    assert backoff_delays(5, base=2, cap=30) == [2, 4, 8, 16]
    assert backoff_delays(7, base=2, cap=10) == [2, 4, 8, 10, 10, 10]
    assert backoff_delays(1) == []


def test_zero_attempts_is_rejected():
    with pytest.raises(ValueError):
        backoff_delays(0)


def test_retry_returns_first_success_without_sleeping():
    slept = []
    assert retry(lambda: "ok", sleep=slept.append) == "ok"
    assert slept == []


def test_retry_recovers_after_failures_and_reports_each_wait():
    calls, slept, seen = [], [], []

    def flaky():
        calls.append(1)
        if len(calls) < 3:
            raise OSError("down")
        return "ok"

    result = retry(
        flaky, attempts=3, sleep=slept.append, on_retry=lambda n, e, d: seen.append((n, d))
    )
    assert result == "ok"
    assert slept == [2, 4]
    assert seen == [(1, 2), (2, 4)]


def test_retry_gives_up_and_raises_the_last_error():
    slept = []

    def always():
        raise OSError("still down")

    with pytest.raises(OSError, match="still down"):
        retry(always, attempts=3, sleep=slept.append)
    assert slept == [2, 4]


def test_retry_does_not_catch_unlisted_errors():
    slept = []

    def boom():
        raise KeyError("bug")

    with pytest.raises(KeyError):
        retry(boom, catch=(OSError,), sleep=slept.append)
    assert slept == []


def test_seconds_until_next():
    assert seconds_until_next(60, 5.5) == 54.5
    assert seconds_until_next(60, 75) == 0.0
