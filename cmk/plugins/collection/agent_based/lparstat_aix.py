#!/usr/bin/env python3
# Copyright (C) 2019 Checkmk GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

from collections.abc import Mapping
from typing import TypedDict

from cmk.agent_based.v2 import (
    AgentSection,
    Attributes,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    InventoryPlugin,
    InventoryResult,
    Metric,
    Result,
    Service,
    State,
    StringTable,
)


class Section(TypedDict, total=False):
    system_config: Mapping[str, str]
    update_required: bool
    cpu: Mapping[str, float]
    util: Mapping[str, tuple[float, str]]


def parse_lparstat_aix(string_table: StringTable) -> Section | None:
    if not string_table:
        return None

    if len(string_table) < 4:
        return {"update_required": True}

    # get system config:
    kv_pairs = (word for word in string_table[0] if "=" in word)
    system_config = dict(kv.split("=", 1) for kv in kv_pairs)
    # from ibm.com: 'If there are two SMT threads, the row is displayed as "on."'
    if system_config.get("smt", "").lower() == "on":
        system_config["smt"] = "2"

    cpu = {}
    util = {}
    for index, key in enumerate(string_table[1]):
        name = key.lstrip("%")
        uom = "%" if "%" in key else ""
        try:
            value = float(string_table[3][index])
        except (IndexError, ValueError):
            continue

        if name in ("user", "sys", "idle", "wait"):
            cpu[name] = value
        else:
            util[name] = (value, uom)

    return {
        "system_config": system_config,
        "util": util,
        "cpu": cpu,
    }


agent_section_lparstat_aix = AgentSection(
    name="lparstat_aix",
    parse_function=parse_lparstat_aix,
)


def inventory_lparstat_aix(section: Section) -> InventoryResult:
    data = section.get("system_config", {})
    attr = {}

    sharing_mode = "-".join(v for k in ("type", "mode") if (v := data.get(k)))
    if sharing_mode:
        attr["sharing_mode"] = sharing_mode

    for nkey, dkey in [
        ("smt_threads", "smt"),
        ("entitlement", "ent"),
        ("cpus", "psize"),
        ("logical_cpus", "lcpu"),
    ]:
        try:
            attr[nkey] = data[dkey]
        except KeyError:
            pass

    yield Attributes(
        path=["hardware", "cpu"],
        inventory_attributes=attr,
    )


inventory_plugin_lparstat_aix = InventoryPlugin(
    name="lparstat_aix",
    inventory_function=inventory_lparstat_aix,
)


def inventory_lparstat(section: Section) -> DiscoveryResult:
    if section.get("util"):
        yield Service()


def check_lparstat(section: Section) -> CheckResult:
    if section.get("update_required"):
        yield Result(state=State.UNKNOWN, summary="Please upgrade your AIX agent.")
        return

    utilization = section.get("util", {})
    for name, (value, uom) in utilization.items():
        yield Result(state=State.OK, summary=f"{name.title()}: {value}{uom}")
        yield Metric(name, value)


check_plugin_lparstat_aix = CheckPlugin(
    name="lparstat_aix",
    service_name="lparstat",
    discovery_function=inventory_lparstat,
    check_function=check_lparstat,
)
