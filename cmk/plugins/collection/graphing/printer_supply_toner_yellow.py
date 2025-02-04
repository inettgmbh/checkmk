#!/usr/bin/env python3
# Copyright (C) 2024 Checkmk GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

from cmk.graphing.v1 import graphs, metrics, perfometers, Title

UNIT_PERCENTAGE = metrics.Unit(metrics.DecimalNotation("%"))

metric_supply_toner_yellow = metrics.Metric(
    name="supply_toner_yellow",
    title=Title("Supply toner yellow"),
    unit=UNIT_PERCENTAGE,
    color=metrics.Color.YELLOW,
)

perfometer_supply_toner_yellow = perfometers.Perfometer(
    name="supply_toner_yellow",
    focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Closed(100.0)),
    segments=["supply_toner_yellow"],
)

graph_supply_toner_yellow = graphs.Graph(
    name="supply_toner_yellow",
    title=Title("Supply toner yellow"),
    minimal_range=graphs.MinimalRange(0, 100),
    compound_lines=["supply_toner_yellow"],
)
