#!/usr/bin/env python3
# Copyright (C) 2023 Checkmk GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

from cmk.graphing.v1 import graphs, metrics, Title

UNIT_NUMBER = metrics.Unit(metrics.DecimalNotation(""), metrics.StrictPrecision(2))

metric_aws_ec2_running_ondemand_instances_m5ad_12xlarge = metrics.Metric(
    name="aws_ec2_running_ondemand_instances_m5ad.12xlarge",
    title=Title("Total running on-demand m5ad.12xlarge instances"),
    unit=UNIT_NUMBER,
    color=metrics.Color.LIGHT_GRAY,
)

metric_aws_ec2_running_ondemand_instances_m5ad_16xlarge = metrics.Metric(
    name="aws_ec2_running_ondemand_instances_m5ad.16xlarge",
    title=Title("Total running on-demand m5ad.16xlarge instances"),
    unit=UNIT_NUMBER,
    color=metrics.Color.RED,
)

metric_aws_ec2_running_ondemand_instances_m5ad_24xlarge = metrics.Metric(
    name="aws_ec2_running_ondemand_instances_m5ad.24xlarge",
    title=Title("Total running on-demand m5ad.24xlarge instances"),
    unit=UNIT_NUMBER,
    color=metrics.Color.DARK_GREEN,
)

metric_aws_ec2_running_ondemand_instances_m5ad_2xlarge = metrics.Metric(
    name="aws_ec2_running_ondemand_instances_m5ad.2xlarge",
    title=Title("Total running on-demand m5ad.2xlarge instances"),
    unit=UNIT_NUMBER,
    color=metrics.Color.DARK_BLUE,
)

metric_aws_ec2_running_ondemand_instances_m5ad_4xlarge = metrics.Metric(
    name="aws_ec2_running_ondemand_instances_m5ad.4xlarge",
    title=Title("Total running on-demand m5ad.4xlarge instances"),
    unit=UNIT_NUMBER,
    color=metrics.Color.DARK_YELLOW,
)

metric_aws_ec2_running_ondemand_instances_m5ad_8xlarge = metrics.Metric(
    name="aws_ec2_running_ondemand_instances_m5ad.8xlarge",
    title=Title("Total running on-demand m5ad.8xlarge instances"),
    unit=UNIT_NUMBER,
    color=metrics.Color.DARK_PURPLE,
)

metric_aws_ec2_running_ondemand_instances_m5ad_large = metrics.Metric(
    name="aws_ec2_running_ondemand_instances_m5ad.large",
    title=Title("Total running on-demand m5ad.large instances"),
    unit=UNIT_NUMBER,
    color=metrics.Color.DARK_GRAY,
)

metric_aws_ec2_running_ondemand_instances_m5ad_xlarge = metrics.Metric(
    name="aws_ec2_running_ondemand_instances_m5ad.xlarge",
    title=Title("Total running on-demand m5ad.xlarge instances"),
    unit=UNIT_NUMBER,
    color=metrics.Color.LIGHT_GRAY,
)

graph_aws_ec2_running_ondemand_instances_m5ad = graphs.Graph(
    name="aws_ec2_running_ondemand_instances_m5ad",
    title=Title("Total running on-demand instances of type m5ad"),
    compound_lines=[
        "aws_ec2_running_ondemand_instances_m5ad.12xlarge",
        "aws_ec2_running_ondemand_instances_m5ad.16xlarge",
        "aws_ec2_running_ondemand_instances_m5ad.24xlarge",
        "aws_ec2_running_ondemand_instances_m5ad.2xlarge",
        "aws_ec2_running_ondemand_instances_m5ad.4xlarge",
        "aws_ec2_running_ondemand_instances_m5ad.8xlarge",
        "aws_ec2_running_ondemand_instances_m5ad.large",
        "aws_ec2_running_ondemand_instances_m5ad.xlarge",
    ],
    optional=[
        "aws_ec2_running_ondemand_instances_m5ad.12xlarge",
        "aws_ec2_running_ondemand_instances_m5ad.16xlarge",
        "aws_ec2_running_ondemand_instances_m5ad.24xlarge",
        "aws_ec2_running_ondemand_instances_m5ad.2xlarge",
        "aws_ec2_running_ondemand_instances_m5ad.4xlarge",
        "aws_ec2_running_ondemand_instances_m5ad.8xlarge",
        "aws_ec2_running_ondemand_instances_m5ad.large",
        "aws_ec2_running_ondemand_instances_m5ad.xlarge",
    ],
)
