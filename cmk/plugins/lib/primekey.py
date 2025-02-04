#!/usr/bin/env python3
# Copyright (C) 2019 Checkmk GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

from cmk.agent_based.v2 import equals

DETECT_PRIMEKEY = equals(".1.3.6.1.2.1.1.2.0", ".1.3.6.1.4.1.8072.3.2.10")
