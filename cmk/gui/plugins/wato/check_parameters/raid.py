#!/usr/bin/env python3
# Copyright (C) 2019 Checkmk GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

from cmk.gui.i18n import _
from cmk.gui.plugins.wato.utils import (
    ManualCheckParameterRulespec,
    rulespec_registry,
    RulespecGroupEnforcedServicesStorage,
)
from cmk.gui.valuespec import Dictionary, TextInput


def _item_spec_raid():
    return TextInput(
        title=_("Name of the device"),
        help=_(
            "For Linux MD specify the device name without the "
            "<tt>/dev/</tt>, e.g. <tt>md0</tt>, for hardware raids "
            "please refer to the manual of the actual check being used."
        ),
    )


rulespec_registry.register(
    ManualCheckParameterRulespec(
        check_group_name="raid",
        group=RulespecGroupEnforcedServicesStorage,
        item_spec=_item_spec_raid,
        parameter_valuespec=lambda: Dictionary(
            elements=(),
            title=_("This plug-in has no paramaters"),
            empty_text=_("This plug-in has no paramaters"),
        ),
        title=lambda: _("RAID: overall state"),
    )
)
