#!/usr/bin/env python3
# Copyright (C) 2024 Checkmk GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

from cmk_addons.plugins.redfish.lib import (
    parse_redfish_multiple,
)

from cmk.agent_based.v2 import AgentSection

agent_section_redfish_power = AgentSection(
    name="redfish_power",
    parse_function=parse_redfish_multiple,
    parsed_section_name="redfish_power",
)
