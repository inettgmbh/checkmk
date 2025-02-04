#!/usr/bin/env python3
# Copyright (C) 2023 Checkmk GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

from cmk.graphing.v1 import graphs, metrics, Title

UNIT_NUMBER = metrics.Unit(metrics.DecimalNotation(""), metrics.StrictPrecision(2))

metric_aws_ec2_running_ondemand_instances_r4_16xlarge = metrics.Metric(
    name="aws_ec2_running_ondemand_instances_r4.16xlarge",
    title=Title("Total running on-demand r4.16xlarge instances"),
    unit=UNIT_NUMBER,
    color=metrics.Color.DARK_GRAY,
)

metric_aws_ec2_running_ondemand_instances_r4_2xlarge = metrics.Metric(
    name="aws_ec2_running_ondemand_instances_r4.2xlarge",
    title=Title("Total running on-demand r4.2xlarge instances"),
    unit=UNIT_NUMBER,
    color=metrics.Color.LIGHT_GRAY,
)

metric_aws_ec2_running_ondemand_instances_r4_4xlarge = metrics.Metric(
    name="aws_ec2_running_ondemand_instances_r4.4xlarge",
    title=Title("Total running on-demand r4.4xlarge instances"),
    unit=UNIT_NUMBER,
    color=metrics.Color.DARK_RED,
)

metric_aws_ec2_running_ondemand_instances_r4_8xlarge = metrics.Metric(
    name="aws_ec2_running_ondemand_instances_r4.8xlarge",
    title=Title("Total running on-demand r4.8xlarge instances"),
    unit=UNIT_NUMBER,
    color=metrics.Color.DARK_GREEN,
)

metric_aws_ec2_running_ondemand_instances_r4_large = metrics.Metric(
    name="aws_ec2_running_ondemand_instances_r4.large",
    title=Title("Total running on-demand r4.large instances"),
    unit=UNIT_NUMBER,
    color=metrics.Color.DARK_BLUE,
)

metric_aws_ec2_running_ondemand_instances_r4_xlarge = metrics.Metric(
    name="aws_ec2_running_ondemand_instances_r4.xlarge",
    title=Title("Total running on-demand r4.xlarge instances"),
    unit=UNIT_NUMBER,
    color=metrics.Color.BROWN,
)

graph_aws_ec2_running_ondemand_instances_r4 = graphs.Graph(
    name="aws_ec2_running_ondemand_instances_r4",
    title=Title("Total running on-demand instances of type r4"),
    compound_lines=[
        "aws_ec2_running_ondemand_instances_r4.16xlarge",
        "aws_ec2_running_ondemand_instances_r4.2xlarge",
        "aws_ec2_running_ondemand_instances_r4.4xlarge",
        "aws_ec2_running_ondemand_instances_r4.8xlarge",
        "aws_ec2_running_ondemand_instances_r4.large",
        "aws_ec2_running_ondemand_instances_r4.xlarge",
    ],
    optional=[
        "aws_ec2_running_ondemand_instances_r4.16xlarge",
        "aws_ec2_running_ondemand_instances_r4.2xlarge",
        "aws_ec2_running_ondemand_instances_r4.4xlarge",
        "aws_ec2_running_ondemand_instances_r4.8xlarge",
        "aws_ec2_running_ondemand_instances_r4.large",
        "aws_ec2_running_ondemand_instances_r4.xlarge",
    ],
)
