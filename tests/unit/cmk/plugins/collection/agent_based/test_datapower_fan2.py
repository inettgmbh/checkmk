#!/usr/bin/env python3
# Copyright (C) 2019 Checkmk GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.


import pytest

from cmk.agent_based.v2 import Result, Service, State
from cmk.plugins.collection.agent_based.datapower_fan import (
    check_datapower_fan,
    Fan,
    inventory_datapower_fan,
)

_SECTION = {
    "Tray 1 Fan 1": Fan(
        state="4",
        state_txt="operating normally",
        speed="9700",
    ),
    "Tray 1 Fan 2": Fan(
        state="5",
        state_txt="reached upper non-critical limit",
        speed="5600",
    ),
    "Tray 1 Fan 3": Fan(
        state="7",
        state_txt="reached upper non-recoverable limit",
        speed="9800",
    ),
    "Tray 1 Fan 4": Fan(
        state="10",
        state_txt="Invalid",
        speed="5400",
    ),
}


def test_discover_datapower_fan() -> None:
    assert list(inventory_datapower_fan(_SECTION)) == [
        Service(item="Tray 1 Fan 1"),
        Service(item="Tray 1 Fan 2"),
        Service(item="Tray 1 Fan 3"),
        Service(item="Tray 1 Fan 4"),
    ]


@pytest.mark.parametrize(
    "item, expected_result",
    [
        pytest.param(
            "Tray 1 Fan 1",
            Result(
                state=State.OK,
                summary="operating normally, 9700 rpm",
            ),
            id="normal",
        ),
        pytest.param(
            "Tray 1 Fan 3",
            Result(
                state=State.CRIT,
                summary="reached upper non-recoverable limit, 9800 rpm",
            ),
            id="upper critical limit",
        ),
    ],
)
def test_check_datapower_fan(
    item: str,
    expected_result: Result,
) -> None:
    assert list(check_datapower_fan(item, _SECTION)) == [expected_result]
