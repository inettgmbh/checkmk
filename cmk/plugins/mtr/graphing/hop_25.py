#!/usr/bin/env python3
# Copyright (C) 2024 Checkmk GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

from cmk.graphing.v1 import graphs, metrics, perfometers, Title

UNIT_PERCENTAGE = metrics.Unit(metrics.DecimalNotation("%"))
UNIT_TIME = metrics.Unit(metrics.TimeNotation())

metric_hop_25_pl = metrics.Metric(
    name="hop_25_pl",
    title=Title("Hop 25 packet loss"),
    unit=UNIT_PERCENTAGE,
    color=metrics.Color.BROWN,
)
metric_hop_25_rta = metrics.Metric(
    name="hop_25_rta",
    title=Title("Hop 25 round trip average"),
    unit=UNIT_TIME,
    color=metrics.Color.ORANGE,
)
metric_hop_25_rtmax = metrics.Metric(
    name="hop_25_rtmax",
    title=Title("Hop 25 round trip maximum"),
    unit=UNIT_TIME,
    color=metrics.Color.BLUE,
)
metric_hop_25_rtmin = metrics.Metric(
    name="hop_25_rtmin",
    title=Title("Hop 25 round trip minimum"),
    unit=UNIT_TIME,
    color=metrics.Color.GREEN,
)
metric_hop_25_rtstddev = metrics.Metric(
    name="hop_25_rtstddev",
    title=Title("Hop 25 round trip standard devation"),
    unit=UNIT_TIME,
    color=metrics.Color.PINK,
)

perfometer_hop_25_pl_hop_25_rta = perfometers.Bidirectional(
    name="hop_25_pl_hop_25_rta",
    left=perfometers.Perfometer(
        name="hop_25_pl",
        focus_range=perfometers.FocusRange(
            perfometers.Closed(0),
            perfometers.Closed(100.0),
        ),
        segments=["hop_25_pl"],
    ),
    right=perfometers.Perfometer(
        name="hop_25_rta",
        focus_range=perfometers.FocusRange(
            perfometers.Closed(0),
            perfometers.Open(1),
        ),
        segments=["hop_25_rta"],
    ),
)

graph_hop_25_round_trip_average = graphs.Graph(
    name="hop_25_round_trip_average",
    title=Title("Hop 25 round trip average"),
    simple_lines=[
        "hop_25_rtmax",
        "hop_25_rtmin",
        "hop_25_rta",
        "hop_25_rtstddev",
    ],
)

graph_hop_25_packet_loss = graphs.Graph(
    name="hop_25_packet_loss",
    title=Title("Hop 25 packet loss"),
    compound_lines=["hop_25_pl"],
)
