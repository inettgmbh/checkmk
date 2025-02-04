#!/usr/bin/env python3
# Copyright (C) 2019 Checkmk GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.


import json

import pytest

from tests.testlib.repo import repo_path

from livestatus import RRDResponse

from cmk.utils.prediction import _prediction


def _load_fake_rrd_response(start: int, end: int) -> RRDResponse:
    raw = json.loads(
        (
            repo_path()
            / "tests/unit/cmk/utils/prediction/test-files/input"
            / f"test-prediction-CPU_load-load15-{start}-{end}"
        ).read_text()
    )
    return RRDResponse(
        window=range(*raw["range"]),
        values=raw["values"],
    )


@pytest.mark.parametrize(
    "timezone, timegroup, time_windows",
    [
        (
            "Europe/Berlin",
            "thursday",
            [
                (1543446000, 1543532400),
                (1542841200, 1542927600),
                (1542236400, 1542322800),
                (1541631600, 1541718000),
                (1541026800, 1541113200),
                (1540418400, 1540504800),
                (1539813600, 1539900000),
                (1539208800, 1539295200),
                (1538604000, 1538690400),
                (1537999200, 1538085600),
                (1537394400, 1537480800),
                (1536789600, 1536876000),
                (1536184800, 1536271200),
            ],
        ),
        (
            "Europe/Berlin",
            "26",
            [(1543186800, 1543273200), (1540504800, 1540591200), (1537912800, 1537999200)],
        ),
        (
            "Europe/Berlin",
            "everyday",
            [
                (1541804400, 1541890800),
                (1541718000, 1541804400),
                (1541631600, 1541718000),
                (1541545200, 1541631600),
                (1541458800, 1541545200),
                (1541372400, 1541458800),
                (1541286000, 1541372400),
                (1541199600, 1541286000),
                (1541113200, 1541199600),
                (1541026800, 1541113200),
                (1540940400, 1541026800),
                (1540854000, 1540940400),
                (1540767600, 1540854000),
                (1540681200, 1540767600),
                (1540591200, 1540677600),
                (1540504800, 1540591200),
                (1540418400, 1540504800),
                (1540332000, 1540418400),
                (1540245600, 1540332000),
                (1540159200, 1540245600),
                (1540072800, 1540159200),
                (1539986400, 1540072800),
                (1539900000, 1539986400),
                (1539813600, 1539900000),
                (1539727200, 1539813600),
                (1539640800, 1539727200),
                (1539554400, 1539640800),
                (1539468000, 1539554400),
                (1539381600, 1539468000),
                (1539295200, 1539381600),
                (1539208800, 1539295200),
                (1539122400, 1539208800),
                (1539036000, 1539122400),
                (1538949600, 1539036000),
                (1538863200, 1538949600),
                (1538776800, 1538863200),
                (1538690400, 1538776800),
                (1538604000, 1538690400),
                (1538517600, 1538604000),
                (1538431200, 1538517600),
                (1538344800, 1538431200),
                (1538258400, 1538344800),
                (1538172000, 1538258400),
                (1538085600, 1538172000),
                (1537999200, 1538085600),
                (1537912800, 1537999200),
                (1537826400, 1537912800),
                (1537740000, 1537826400),
                (1537653600, 1537740000),
                (1537567200, 1537653600),
                (1537480800, 1537567200),
                (1537394400, 1537480800),
                (1537308000, 1537394400),
                (1537221600, 1537308000),
                (1537135200, 1537221600),
                (1537048800, 1537135200),
                (1536962400, 1537048800),
                (1536876000, 1536962400),
                (1536789600, 1536876000),
                (1536703200, 1536789600),
                (1536616800, 1536703200),
                (1536530400, 1536616800),
                (1536444000, 1536530400),
                (1536357600, 1536444000),
                (1536271200, 1536357600),
                (1536184800, 1536271200),
                (1536098400, 1536184800),
                (1536012000, 1536098400),
                (1535925600, 1536012000),
                (1535839200, 1535925600),
                (1535752800, 1535839200),
                (1535666400, 1535752800),
                (1535580000, 1535666400),
                (1535493600, 1535580000),
                (1535407200, 1535493600),
                (1535320800, 1535407200),
                (1535234400, 1535320800),
                (1535148000, 1535234400),
                (1535061600, 1535148000),
                (1534975200, 1535061600),
                (1534888800, 1534975200),
                (1534802400, 1534888800),
                (1534716000, 1534802400),
                (1534629600, 1534716000),
                (1534543200, 1534629600),
                (1534456800, 1534543200),
                (1534370400, 1534456800),
                (1534284000, 1534370400),
                (1534197600, 1534284000),
                (1534111200, 1534197600),
            ],
        ),
        (
            "America/New_York",
            "everyday",
            [
                (1531627200, 1531713600),
                (1531540800, 1531627200),
                (1531454400, 1531540800),
                (1531368000, 1531454400),
                (1531281600, 1531368000),
                (1531195200, 1531281600),
                (1531108800, 1531195200),
                (1531022400, 1531108800),
                (1530936000, 1531022400),
                (1530849600, 1530936000),
            ],
        ),
        (
            "UTC",
            "sunday",
            [(1531612800, 1531699200), (1531008000, 1531094400)],
        ),
    ],
)
def test_calculate_data_for_prediction(
    timezone: str,
    timegroup: str,
    time_windows: list[tuple[int, int]],
) -> None:
    from_time = time_windows[0][0]

    raw_slices = [
        (
            response.window,
            response.values,
            from_time - start,
        )
        for start, end in time_windows
        for response in [_load_fake_rrd_response(start, end)]
    ]

    data_for_pred = _prediction._calculate_data_for_prediction(raw_slices[0][0], raw_slices)

    expected_reference = _prediction.PredictionData.model_validate_json(
        (
            repo_path()
            / "tests/unit/cmk/utils/prediction/test-files/output"
            / str(timezone)
            / str(timegroup)
        ).read_text()
    )

    assert expected_reference.model_dump(exclude={"points"}) == data_for_pred.model_dump(
        exclude={"points"}
    )
    assert len(expected_reference.points) == len(data_for_pred.points)
    for cal, ref in zip(data_for_pred.points, expected_reference.points):
        assert cal == pytest.approx(ref, rel=1e-12, abs=1e-12)
