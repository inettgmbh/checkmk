#!/usr/bin/env python3
# Copyright (C) 2023 tribe29 GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

from ..agent_based_api.v1 import any_of, contains

DETECT_GENUA = any_of(
    contains(".1.3.6.1.2.1.1.1.0", "genuscreen"),
    contains(".1.3.6.1.2.1.1.1.0", "genubox"),
    contains(".1.3.6.1.2.1.1.1.0", "genucrypt"),
)
