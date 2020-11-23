#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2019 tribe29 GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

import pytest  # type: ignore[import]
from testlib import Check  # type: ignore[import]

pytestmark = pytest.mark.checks

info_1 = [['[[[site:heute:test]]]'], ['{'], ['"bytes_per_second":', '1578215.4167199447,'],
          ['"finished":', '1511788263.410466,'], ['"next_schedule":', '1511874660.0,'],
          [
              '"output":', '"2017-11-27', '14:11:02', '---', 'Starting', 'backup',
              '(Check_MK-klappfel-heute-test', 'to', 'testtgt)', '---\\n2017-11-27',
              '14:11:03', 'Verifying', 'backup', 'consistency\\n2017-11-27', '14:11:03',
              '---', 'Backup', 'completed', '(Duration:', '0:00:01,', 'Size:', '1.80',
              'MB,', 'IO:', '1.51', 'MB/s)', '---\\n",'
          ], ['"pid":', '20963,'], ['"size":', '1883330,'],
          ['"started":', '1511788262.20002,'], ['"state":', '"finished",'],
          ['"success":', 'true'], ['}']]

info_2 = [['[[[site:heute:test]]]'], ['{'], ['"bytes_per_second":', '1578215.4167199447,'],
          ['"finished":', '1511788263.410466,'], ['"next_schedule":', '1511874660.0,'],
          [
              '"output":', '"2017-11-27', '14:11:02', '---', 'Starting', 'backup',
              '(Check_MK-klappfel-heute-test', 'to', 'testtgt)', '---\\n2017-11-27',
              '14:11:03', 'Verifying', 'backup', 'consistency\\n2017-11-27', '14:11:03',
              '---', 'Backup', 'completed', '(Duration:', '0:00:01,', 'Size:', '1.80',
              'MB,', 'IO:', '1.51', 'MB/s)', '---\\n",'
          ], ['"pid":', '20963,'], ['"size":', '1883330,'],
          ['"started":', '1511788262.20002,'], ['"state":', '"finished",'],
          ['"success":', 'true'], ['}'], ['[[[site:heute:test2]]]'], ['{'],
          ['"bytes_per_second":', '0,'], ['"finished":', '1511788748.77112,'],
          ['"next_schedule":', 'null,'],
          [
              '"output":', '"2017-11-27', '14:19:07', '---', 'Starting', 'backup',
              '(Check_MK-klappfel-heute-test2', 'to', 'testtgt2)', '---\\n2017-11-27',
              '14:19:08', 'Verifying', 'backup', 'consistency\\n2017-11-27', '14:19:08',
              '---', 'Backup', 'completed', '(Duration:', '0:00:00,', 'Size:', '87.07',
              'MB,', 'IO:', '0.00', 'B/s)', '---\\n",'
          ], ['"pid":', '24201,'], ['"size":', '91299840,'],
          ['"started":', '1511788747.898509,'], ['"state":', '"finished",'],
          ['"success":', 'true'], ['}']]

info_3 = [['[[[system:test1]]]'], ['{'], ['"bytes_per_second":', '0,'],
          ['"finished":', '1474547810.309871,'], ['"next_schedule":', 'null,'],
          [
              '"output":', '"2016-09-22', '14:36:50', '---', 'Starting', 'backup',
              '(Check_MK_Appliance-luss028-test1', 'to', 'test1)', '---\\nFailed', 'to',
              'create', 'the', 'backup', 'directory:', '[Errno', '13]', 'Permission',
              'denied:',
              '\'/mnt/auto/DIDK7838/Anwendungen/Check_MK_Appliance-luss028-test1-incomplete\'\\n",'
          ], ['"pid":', '29567,'], ['"started":', '1474547810.30425,'],
          ['"state":', '"finished",'], ['"success":', 'false'], ['}']]


# This only tests whether the parse function crashes or not
@pytest.mark.parametrize("info", [
    [],
    info_1,
    info_2,
    info_3,
])
@pytest.mark.usefixtures("config_load_all_checks")
def test_mkbackup_parse(info):
    check = Check("mkbackup")
    check.run_parse(info)
