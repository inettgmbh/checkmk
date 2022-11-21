#!/usr/bin/env python3
# Copyright (C) 2022 tribe29 GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.
"""
Module which contains functions to parse and write out the performance data collected from the
Cluster Collector for the Kubernetes Monitoring solution
"""
from __future__ import annotations

import enum
import itertools
import json
import os
import tempfile
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Generic, Literal, NewType, TypeVar

from pydantic import BaseModel, Field, parse_raw_as, ValidationError

import cmk.utils

from cmk.special_agents.utils.agent_common import ConditionalPiggybackSection, SectionWriter
from cmk.special_agents.utils_kubernetes.common import (
    LOGGER,
    lookup_name,
    Piggyback,
    PodLookupName,
    PodsToHost,
    SectionName,
)
from cmk.special_agents.utils_kubernetes.schemata import section

AGENT_TMP_PATH = Path(
    cmk.utils.paths.tmp_dir if os.environ.get("OMD_SITE") else tempfile.gettempdir(), "agent_kube"
)
ContainerName = NewType("ContainerName", str)


class UsedMetric(str, enum.Enum):
    container_memory_working_set_bytes = "container_memory_working_set_bytes"
    container_cpu_usage_seconds_total = "container_cpu_usage_seconds_total"


class IdentifiableSample(BaseModel):
    namespace: str
    pod_name: str

    def pod_lookup_from_metric(self) -> PodLookupName:
        return lookup_name(self.namespace, self.pod_name)


class PerformanceSample(IdentifiableSample):
    """BaseModel for parsing data obtained from the `/container_metrics` endpoint.

    From https://prometheus.io/docs/concepts/data_model/
    > Prometheus fundamentally stores all data as time series: streams of timestamped values
    > belonging to the same metric and the same set of labeled dimensions. Every time series is
    > uniquely identified by its metric name and optional key-value pairs called labels.
    > Samples form the actual time series data. Each sample consists of:
    > - a float64 value
    > - a millisecond-precision timestamp

    Here, we additionally includes the metric labels inside a `Sample`. This is similiar to the HTTP
    API of Prometheus.

    The sample matching mechanism between different timeseries objects behaves as follows:
    - Prometheus: matches the samples based on the full set of labels
    - cAdvisor: matches the samples through the `container_name` label
    agent_kube implements matching in the same manner as the cAdvisor approach.
    """

    container_name: ContainerName
    metric_name: UsedMetric
    value: float = Field(..., alias="metric_value_string")
    timestamp: float


class MemorySample(PerformanceSample):
    metric_name: Literal[UsedMetric.container_memory_working_set_bytes]


class CPUSample(PerformanceSample):
    metric_name: Literal[UsedMetric.container_cpu_usage_seconds_total]


class UnusedSample(BaseModel):
    pass


class CPURateSample(IdentifiableSample):
    rate: float


class ContainersStore(BaseModel):
    cpu: Sequence[CPUSample]


@dataclass
class Samples:
    cpu: Sequence[CPUSample]
    memory: Sequence[MemorySample]


_AllSamples = MemorySample | CPUSample | UnusedSample


@dataclass(frozen=True)
class WriteableSection:
    piggyback_name: str
    section_name: SectionName
    section: section.Section


def parse_performance_metrics(cluster_collector_metrics: bytes) -> Sequence[_AllSamples]:
    return parse_raw_as(list[_AllSamples], cluster_collector_metrics)


def create_selectors(
    cluster_name: str, container_metrics: Sequence[_AllSamples]
) -> tuple[Selector[CPURateSample], Selector[MemorySample]]:
    """Converts parsed metrics into Selectors."""

    metrics = _group_metric_types(container_metrics)
    cpu_rate_metrics = _create_cpu_rate_metrics(cluster_name, metrics.cpu)
    return (
        Selector(cpu_rate_metrics, aggregator=_aggregate_cpu_metrics),
        Selector(metrics.memory, aggregator=_aggregate_memory_metrics),
    )


def write_sections(items: Iterator[WriteableSection]) -> None:
    def key_function(item: WriteableSection) -> str:
        return item.piggyback_name

    # Optimize for size of agent output
    for key, group in itertools.groupby(sorted(items, key=key_function), key_function):
        with ConditionalPiggybackSection(key):
            for item in group:
                with SectionWriter(item.section_name) as writer:
                    writer.append(item.section.json())


T = TypeVar("T", bound=IdentifiableSample)


class Selector(Generic[T]):
    def __init__(self, metrics: Sequence[T], aggregator: Callable[[Sequence[T]], section.Section]):
        self.aggregator = aggregator
        self.metrics_map: dict[PodLookupName, list[T]] = {}
        for m in metrics:
            key = m.pod_lookup_from_metric()
            self.metrics_map.setdefault(key, []).append(m)

    def get_section(
        self, piggyback: Piggyback, section_name: SectionName
    ) -> Iterator[WriteableSection]:
        metrics = [
            m for pod_name in piggyback.pod_names for m in self.metrics_map.get(pod_name, [])
        ]
        if metrics:
            yield WriteableSection(
                piggyback_name=piggyback.piggyback,
                section_name=section_name,
                section=self.aggregator(metrics),
            )


def create_sections(
    cpu_selector: Selector[CPURateSample],
    memory_selector: Selector[MemorySample],
    pods_to_host: PodsToHost,
) -> Iterator[WriteableSection]:
    for piggyback in pods_to_host.piggybacks:
        yield from memory_selector.get_section(
            piggyback,
            SectionName("kube_performance_memory_v1"),
        )
        yield from cpu_selector.get_section(
            piggyback,
            SectionName("kube_performance_cpu_v1"),
        )

    for piggyback in pods_to_host.namespace_piggies:
        yield from memory_selector.get_section(
            piggyback,
            SectionName("kube_resource_quota_performance_memory_v1"),
        )
        yield from cpu_selector.get_section(
            piggyback,
            SectionName("kube_resource_quota_performance_cpu_v1"),
        )


def _aggregate_memory_metrics(metrics: Iterable[MemorySample]) -> section.PerformanceUsage:
    return section.PerformanceUsage(
        resource=section.Memory(usage=sum((m.value for m in metrics), start=0.0))
    )


def _aggregate_cpu_metrics(metrics: Iterable[CPURateSample]) -> section.PerformanceUsage:
    return section.PerformanceUsage(
        resource=section.Cpu(usage=sum((m.rate for m in metrics), start=0.0))
    )


def _group_metric_types(metrics: Sequence[_AllSamples]) -> Samples:
    cpu_metrics = []
    memory_metrics = []
    for metric in metrics:
        if isinstance(metric, MemorySample):
            memory_metrics.append(metric)
        elif isinstance(metric, CPUSample):
            cpu_metrics.append(metric)
        elif isinstance(metric, UnusedSample):
            continue
        else:
            raise NotImplementedError()
    return Samples(memory=memory_metrics, cpu=cpu_metrics)


def _create_cpu_rate_metrics(
    cluster_name: str, cpu_metrics: Sequence[CPUSample]
) -> Sequence[CPURateSample]:
    # We only persist the relevant counter metrics (not all metrics)
    current_cycle_store = ContainersStore(cpu=cpu_metrics)
    store_file_name = f"{cluster_name}_containers_counters.json"
    previous_cycle_store = _load_containers_store(
        path=AGENT_TMP_PATH,
        file_name=store_file_name,
    )

    # The agent will store the latest counter values returned by the collector overwriting the
    # previous ones. The collector will return the same metric values for a certain time interval
    # while the values are not updated or outdated. This will result in no rate value if the agent
    # is polled too frequently (no performance section for the checks). All cases where no
    # performance section can be generated should be handled on the check side (reusing the same
    # value, etc.)
    _persist_containers_store(current_cycle_store, path=AGENT_TMP_PATH, file_name=store_file_name)
    return _determine_cpu_rate_metrics(current_cycle_store.cpu, previous_cycle_store.cpu)


def _load_containers_store(path: Path, file_name: str) -> ContainersStore:
    LOGGER.debug("Load previous cycle containers store from %s", file_name)
    try:
        return ContainersStore.parse_file(f"{path}/{file_name}")
    except FileNotFoundError as e:
        LOGGER.info("Could not find metrics file. This is expected if the first run.")
        LOGGER.debug("Exception: %s", e)
    except (ValidationError, json.decoder.JSONDecodeError):
        LOGGER.exception("Found metrics file, but could not parse it.")

    return ContainersStore(cpu=[])


def _persist_containers_store(
    containers_store: ContainersStore, path: Path, file_name: str
) -> None:
    file_path = f"{path}/{file_name}"
    LOGGER.debug("Creating directory %s for containers store file", path)
    path.mkdir(parents=True, exist_ok=True)
    LOGGER.debug("Persisting current containers store under %s", file_path)
    with open(file_path, "w") as f:
        f.write(containers_store.json())


def _determine_cpu_rate_metrics(
    cpu_metrics: Sequence[CPUSample],
    cpu_metrics_old: Sequence[CPUSample],
) -> Sequence[CPURateSample]:
    """Determine the rate metrics for each container based on the current and previous
    counter metric values"""

    LOGGER.debug("Determine rate metrics from the latest containers counters stores")
    cpu_metrics_old_map = {metric.container_name: metric for metric in cpu_metrics_old}
    return [
        CPURateSample(
            pod_name=metric.pod_name,
            namespace=metric.namespace,
            rate=_calculate_rate(metric, old_metric),
        )
        for metric in cpu_metrics
        if (old_metric := cpu_metrics_old_map.get(metric.container_name)) is not None
        and old_metric.timestamp != metric.timestamp
    ]


def _calculate_rate(counter_metric: CPUSample, old_counter_metric: CPUSample) -> float:
    """Calculate the rate value based on two counter metric values
    Examples:
        >>> from pydantic_factories import ModelFactory
        >>> class SampleFactory(ModelFactory):
        ...    __model__ = CPUSample
        >>> _calculate_rate(SampleFactory.build(metric_value_string="40", timestamp=60),
        ... SampleFactory.build(metric_value_string="10", timestamp=30))
        1.0
    """
    time_delta = counter_metric.timestamp - old_counter_metric.timestamp
    return (counter_metric.value - old_counter_metric.value) / time_delta
