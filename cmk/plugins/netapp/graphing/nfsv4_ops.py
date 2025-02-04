#!/usr/bin/env python3
# Copyright (C) 2024 Checkmk GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

from cmk.graphing.v1 import graphs, metrics, Title

UNIT_PER_SECOND = metrics.Unit(metrics.DecimalNotation("/s"))

metric_nfsv4_read_ops = metrics.Metric(
    name="nfsv4_read_ops",
    title=Title("NFSv4 read ops"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.BLUE,
)
metric_nfsv4_write_ops = metrics.Metric(
    name="nfsv4_write_ops",
    title=Title("NFSv4 write ops"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.GREEN,
)

graph_nfsv4_ops = graphs.Bidirectional(
    name="nfsv4_ops",
    title=Title("NFSv4 operations"),
    lower=graphs.Graph(
        name="nfsv4_ops_lower",
        title=Title("NFSv4 operations"),
        compound_lines=["nfsv4_read_ops"],
    ),
    upper=graphs.Graph(
        name="nfsv4_ops_upper",
        title=Title("NFSv4 operations"),
        compound_lines=["nfsv4_write_ops"],
    ),
)
