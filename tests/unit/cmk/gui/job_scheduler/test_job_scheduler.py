#!/usr/bin/env python3
# Copyright (C) 2019 Checkmk GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

import threading
from datetime import datetime, timedelta, UTC

import pytest
import time_machine

from cmk.gui.cron import CronJob
from cmk.gui.job_scheduler._scheduler import run_scheduled_jobs


def reraise_exception(exc: Exception) -> str:
    raise exc


def test_run_scheduled_jobs() -> None:
    called = {
        "job1": 0,
        "job2": 0,
    }
    job_threads: dict[str, threading.Thread] = {}
    jobs = [
        CronJob(
            name="job1",
            callable=lambda: called.update({"job1": called["job1"] + 1}),
            interval=timedelta(minutes=1),
        ),
        CronJob(
            name="job2",
            callable=lambda: called.update({"job2": called["job2"] + 1}),
            interval=timedelta(minutes=5),
        ),
    ]

    with time_machine.travel(datetime.fromtimestamp(0, tz=UTC), tick=False):
        run_scheduled_jobs(jobs, job_threads, crash_report_callback=reraise_exception)

    assert called["job1"] == 1
    assert called["job2"] == 1
    assert not job_threads

    with time_machine.travel(datetime.fromtimestamp(60, tz=UTC), tick=False):
        run_scheduled_jobs(jobs, job_threads, crash_report_callback=reraise_exception)

    assert called["job1"] == 2
    assert called["job2"] == 1
    assert not job_threads

    with time_machine.travel(datetime.fromtimestamp(300, tz=UTC), tick=False):
        run_scheduled_jobs(jobs, job_threads, crash_report_callback=reraise_exception)

    assert called["job1"] == 3
    assert called["job2"] == 2
    assert not job_threads


def test_run_scheduled_jobs_in_thread() -> None:
    called = threading.Event()
    job_threads: dict[str, threading.Thread] = {}
    jobs = [
        CronJob(
            name="threaded_job",
            callable=called.set,
            run_in_thread=True,
            interval=timedelta(minutes=5),
        ),
    ]

    run_scheduled_jobs(jobs, job_threads, crash_report_callback=reraise_exception)

    assert "threaded_job" in job_threads
    job_threads["threaded_job"].join()
    assert called.is_set()


@pytest.mark.skip(reason="test is flaky")
def test_run_scheduled_jobs_in_thread_does_not_start_twice(
    caplog: pytest.LogCaptureFixture,
) -> None:
    shall_terminate = threading.Event()
    job_threads: dict[str, threading.Thread] = {}

    jobs = [
        CronJob(
            name="threaded_job",
            callable=shall_terminate.wait,
            run_in_thread=True,
            interval=timedelta(minutes=1),
        ),
    ]

    try:
        with time_machine.travel(datetime.fromtimestamp(60, tz=UTC), tick=False):
            run_scheduled_jobs(jobs, job_threads, crash_report_callback=reraise_exception)

        with (
            time_machine.travel(datetime.fromtimestamp(180, tz=UTC), tick=False),
            caplog.at_level("DEBUG", "cmk.web"),
        ):
            run_scheduled_jobs(jobs, job_threads, crash_report_callback=reraise_exception)

        assert any("is already running" in r.message for r in caplog.records)
    finally:
        shall_terminate.set()
        assert "threaded_job" in job_threads
        job_threads["threaded_job"].join()
