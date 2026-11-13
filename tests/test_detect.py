from datetime import UTC, datetime, timedelta

from lab.detect import watch_until_suspect
from lab.health import evaluate

T0 = datetime(2026, 11, 13, 0, 0, tzinfo=UTC)


def clean():
    return evaluate(email_total=100, email_valid=100, ransom_table_exists=False, row_counts={})


def suspect():
    return evaluate(email_total=100, email_valid=0, ransom_table_exists=True, row_counts={})


class Clock:
    def __init__(self):
        self.t, self.sleeps = T0, []

    def now(self):
        return self.t

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.t += timedelta(seconds=seconds)


def test_alarm_comes_at_the_first_suspect_poll_five_seconds_apart():
    clock = Clock()
    results = iter([clean(), clean(), suspect(), suspect()])
    found = watch_until_suspect(lambda: next(results), interval=5, sleep=clock.sleep, now=clock.now)
    report, moment = found
    assert not report.is_clean
    assert moment == T0 + timedelta(seconds=10)
    assert clock.sleeps == [5, 5]


def test_unreadable_database_is_not_an_alarm_and_polling_continues():
    clock = Clock()
    results = iter([None, None, suspect()])
    report, moment = watch_until_suspect(
        lambda: next(results), interval=5, sleep=clock.sleep, now=clock.now
    )
    assert moment == T0 + timedelta(seconds=10)


def test_gives_up_after_max_polls_when_always_clean():
    clock = Clock()
    assert (
        watch_until_suspect(clean, interval=5, max_polls=3, sleep=clock.sleep, now=clock.now)
        is None
    )
    assert clock.sleeps == [5, 5]


def test_on_poll_sees_every_check():
    seen = []
    clock = Clock()
    results = iter([clean(), suspect()])
    watch_until_suspect(
        lambda: next(results), sleep=clock.sleep, now=clock.now,
        on_poll=lambda moment, report: seen.append(report.is_clean),
    )  # fmt: skip
    assert seen == [True, False]
