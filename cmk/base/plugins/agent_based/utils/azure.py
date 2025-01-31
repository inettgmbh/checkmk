#!/usr/bin/env python3
# Copyright (C) 2022 tribe29 GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

import json
from typing import Any, Callable, Iterable, Mapping, NamedTuple, Sequence, Tuple

from ..agent_based_api.v1 import check_levels, IgnoreResultsError, render, Service
from ..agent_based_api.v1.type_defs import CheckResult, DiscoveryResult, StringTable

AZURE_AGENT_SEPARATOR = "|"


class AzureMetric(NamedTuple):
    name: str
    aggregation: str
    value: float
    unit: str


class Resource(NamedTuple):
    id: str
    name: str
    type: str
    group: str
    kind: str | None = None
    location: str | None = None
    tags: Mapping[str, str] = {}
    properties: Mapping[str, str | int] = {}
    specific_info: Mapping[str, str | int] = {}
    metrics: Mapping[str, AzureMetric] = {}


Section = Mapping[str, Resource]


#   .--Parse---------------------------------------------------------------.
#   |                      ____                                            |
#   |                     |  _ \ __ _ _ __ ___  ___                        |
#   |                     | |_) / _` | '__/ __|/ _ \                       |
#   |                     |  __/ (_| | |  \__ \  __/                       |
#   |                     |_|   \__,_|_|  |___/\___|                       |
#   |                                                                      |
#   '----------------------------------------------------------------------'


def _get_metrics_number(row: Sequence[str]) -> int:
    if str(row[0]) != "metrics following":
        return 0
    try:
        return int(row[1])
    except ValueError:
        return 0


def _get_metrics(metrics_data: Sequence[Sequence[str]]) -> Iterable[Tuple[str, AzureMetric]]:
    for metric_line in metrics_data:
        metric_dict = json.loads(AZURE_AGENT_SEPARATOR.join(metric_line))

        key = f"{metric_dict['aggregation']}_{metric_dict['name'].replace(' ', '_')}"
        yield key, AzureMetric(
            metric_dict["name"],
            metric_dict["aggregation"],
            metric_dict["value"],
            metric_dict["unit"],
        )


def _get_resource(resource: Mapping[str, Any], metrics=None):
    return Resource(
        resource["id"],
        resource["name"],
        resource["type"],
        resource["group"],
        resource.get("kind"),
        resource.get("location"),
        resource.get("tags", {}),
        resource.get("properties", {}),
        resource.get("specific_info", {}),
        metrics or {},
    )


def _parse_resource(resource_data: Sequence[Sequence[str]]) -> Resource | None:
    """read resource json and parse metric lines

    Metrics are stored in a dict. Key is name, prefixed by their aggregation,
    spaces become underscores:
      Disk Read Bytes|average|0.0|...
    is stored at
      resource.metrics["average_Disk_Read_Bytes"]
    """
    try:
        resource = json.loads(AZURE_AGENT_SEPARATOR.join(resource_data[0]))
    except (ValueError, IndexError):
        return None

    if len(resource_data) < 3:
        return _get_resource(resource)

    metrics_num = _get_metrics_number(resource_data[1])
    if metrics_num == 0:
        return _get_resource(resource)

    metrics = dict(_get_metrics(resource_data[2 : 2 + metrics_num]))
    return _get_resource(resource, metrics=metrics)


def parse_resources(string_table: StringTable) -> Mapping[str, Resource]:
    raw_resources: list[list[Sequence[str]]] = []

    # create list of lines per resource
    for row in string_table:
        if row == ["Resource"]:
            raw_resources.append([])
            continue
        if raw_resources:
            raw_resources[-1].append(row)

    parsed_resources = (_parse_resource(r) for r in raw_resources)

    return {r.name: r for r in parsed_resources if r}


#   .--Discovery-----------------------------------------------------------.
#   |              ____  _                                                 |
#   |             |  _ \(_)___  ___ _____   _____ _ __ _   _               |
#   |             | | | | / __|/ __/ _ \ \ / / _ \ '__| | | |              |
#   |             | |_| | \__ \ (_| (_) \ V /  __/ |  | |_| |              |
#   |             |____/|_|___/\___\___/ \_/ \___|_|   \__, |              |
#   |                                                  |___/               |
#   +----------------------------------------------------------------------+


def discover_azure_by_metrics(
    *desired_metrics: Iterable[str],
) -> Callable[[Section], DiscoveryResult]:
    """Return a discovery function, that will discover if any of the metrics are found"""

    def discovery_function(section: Section) -> DiscoveryResult:
        for item, resource in section.items():
            if set(desired_metrics) & set(resource.metrics):
                yield Service(item=item)

    return discovery_function


#   .--Checks--------------------------------------------------------------.
#   |                    ____ _               _                            |
#   |                   / ___| |__   ___  ___| | _____                     |
#   |                  | |   | '_ \ / _ \/ __| |/ / __|                    |
#   |                  | |___| | | |  __/ (__|   <\__ \                    |
#   |                   \____|_| |_|\___|\___|_|\_\___/                    |
#   |                                                                      |
#   +----------------------------------------------------------------------+


def check_azure_metric(
    azure_metric_name: str,
    metric_name: str,
    metric_label: str,
    render_func: Callable[[float], str],
) -> Callable[[str, Mapping[str, Any], Section], CheckResult]:
    def check_metric(item: str, params: Mapping[str, Any], section: Section) -> CheckResult:
        resource = section.get(item)
        if not resource:
            raise IgnoreResultsError("Data not present at the moment")

        metric = resource.metrics.get(azure_metric_name)
        if not metric:
            raise IgnoreResultsError("Data not present at the moment")

        yield from check_levels(
            metric.value,
            levels_upper=params.get("levels"),
            metric_name=metric_name,
            label=metric_label,
            render_func=render_func,
        )

    return check_metric


def check_memory() -> Callable[[str, Mapping[str, Any], Section], CheckResult]:
    return check_azure_metric(
        "average_memory_percent",
        "mem_used_percent",
        "Memory utilization",
        render.percent,
    )


def check_cpu() -> Callable[[str, Mapping[str, Any], Section], CheckResult]:
    return check_azure_metric(
        "average_cpu_percent",
        "util",
        "CPU utilization",
        render.percent,
    )
