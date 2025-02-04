#!/usr/bin/env python3
# Copyright (C) 2019 Checkmk GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.


from cmk.agent_based.v2 import (
    all_of,
    any_of,
    CheckPlugin,
    contains,
    SNMPSection,
    SNMPTree,
    startswith,
)
from cmk.plugins.lib.hp_hh3c import (
    check_hp_hh3c_device,
    discover_hp_hh3c_device,
    OID_SysDesc,
    OID_SysObjectID,
    parse_hp_hh3c_device,
)

snmp_section_hp_hh3c_power = SNMPSection(
    name="hp_hh3c_power",
    parse_function=parse_hp_hh3c_device,
    fetch=[
        SNMPTree(
            base=".1.3.6.1.4.1.25506.8.35.9.1.2.1",
            oids=[
                "1",
                "2",
            ],
        ),
    ],
    detect=all_of(
        startswith(OID_SysObjectID, ".1.3.6.1.4.1.25506"),
        any_of(contains(OID_SysDesc, "H3C"), contains(OID_SysDesc, "HPE")),
    ),
)

check_plugin_hp_hh3c_power = CheckPlugin(
    name="hp_hh3c_power",
    service_name="Power %s",
    discovery_function=discover_hp_hh3c_device,
    check_function=check_hp_hh3c_device,
)
