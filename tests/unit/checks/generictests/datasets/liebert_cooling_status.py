#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2019 tribe29 GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

# yapf: disable
# type: ignore



checkname = 'liebert_cooling_status'


info = [
    ['Fancy cooling device', 'awesome'],
]


discovery = {
    '': [
        ('Fancy cooling device', {}),
    ],
}


checks = {
    '': [
        ('Fancy cooling device', {}, [(0, "awesome", [])]),
    ],
}
