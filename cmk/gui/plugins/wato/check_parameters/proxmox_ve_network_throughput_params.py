#!/usr/bin/env python3
# Copyright (C) 2019 Checkmk GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

from cmk.gui.i18n import _
from cmk.gui.plugins.wato.utils import (
    CheckParameterRulespecWithoutItem,
    rulespec_registry,
    RulespecGroupCheckParametersOperatingSystem,
)
from cmk.gui.valuespec import Dictionary, Alternative, Tuple, FixedValue, Integer


def _parameter_valuespec_proxmox_ve_network_throughput():
    return Dictionary(
        required_keys=["in_levels", "out_levels"],
        elements=[
            (
                "in_levels",
                Alternative(
                    title=_("Inbound levels"),
                    elements=[
                        Tuple(
                            title=_("Set conditions"),
                            elements=[
                                Integer(unit="MB/s", title=_("Warning at")),
                                Integer(unit="MB/s", title=_("Critical at")),
                            ],
                        ),
                        FixedValue(value=None, title=_("No Conditions"), totext=""),
                    ],
                ),
            ),
            (
                "out_levels",
                Alternative(
                    title=_("Outbound levels"),
                    elements=[
                        Tuple(
                            title=_("Set conditions"),
                            elements=[
                                Integer(unit="MB/s", title=_("Warning at")),
                                Integer(unit="MB/s", title=_("Critical at")),
                            ],
                        ),
                        FixedValue(value=None, title=_("No Conditions"), totext=""),
                    ],
                ),
            ),
        ],
    )


rulespec_registry.register(
    CheckParameterRulespecWithoutItem(
        check_group_name="proxmox_ve_network_throughput",
        group=RulespecGroupCheckParametersOperatingSystem,
        match_type="dict",
        parameter_valuespec=_parameter_valuespec_proxmox_ve_network_throughput,
        title=lambda: _("Proxmox VE network throughput"),
    )
)
