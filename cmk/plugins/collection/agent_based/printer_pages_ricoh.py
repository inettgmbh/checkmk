#!/usr/bin/env python3
# Copyright (C) 2019 Checkmk GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

from collections.abc import Sequence

from cmk.agent_based.v2 import CheckPlugin, SNMPSection, SNMPTree, StringTable
from cmk.plugins.lib.printer import (
    check_printer_pages_types,
    DETECT_RICOH,
    discovery_printer_pages,
    Section,
)

METRIC_NAMES = {
    "Counter: Machine Total": "pages_total",
    "Total Prints: Color": "pages_color",
    "Total Prints: Black & White": "pages_bw",
}


def parse_printer_pages_ricoh(string_table: Sequence[StringTable]) -> Section | None:
    """
    >>> parse_printer_pages_ricoh([[
    ...   ['Counter: Machine Total', '118722'],
    ...   ['Counter:Print:Full Color', '55876'],
    ...   ['Total Prints: Full Color', '55876'],
    ...   ['Printer: Black & White', '62846'],
    ...   ['Total Prints: Color', '55876'],
    ...   ['Total Prints: Black & White', '62846'],
    ... ]])
    {'pages_total': 118722, 'pages_color': 55876, 'pages_bw': 62846}
    """
    return {
        METRIC_NAMES[name]: int(pages_text)
        for name, pages_text in string_table[0]
        if name in METRIC_NAMES
    } or None


snmp_section_printer_pages_ricoh = SNMPSection(
    name="printer_pages_ricoh",
    detect=DETECT_RICOH,
    supersedes=["printer_pages"],
    parse_function=parse_printer_pages_ricoh,
    fetch=[
        SNMPTree(
            base=".1.3.6.1.4.1.367.3.2.1.2.19.5.1",
            oids=[
                "5",
                "9",
            ],
        ),
    ],
)

check_plugin_printer_pages_ricoh = CheckPlugin(
    name="printer_pages_ricoh",
    service_name="Pages",
    discovery_function=discovery_printer_pages,
    check_function=check_printer_pages_types,
)
