#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2019 tribe29 GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

# yapf: disable
# type: ignore
checkname = 'openbsd_sensors'

info = [
    ['temp0', '0', '30.00', 'degC', '0'],
    ['sd0', '13', 'online', '', '1'],
    ['CPU1 Temp', '0', '35.00', 'degC', '1'],
    ['CPU2 Temp', '0', '36.00', 'degC', '1'],
    ['PCH Temp', '0', '36.00', 'degC', '1'],
    ['System Temp', '0', '23.00', 'degC', '1'],
    ['Peripheral Temp', '0', '34.00', 'degC', '1'],
    ['Vcpu1VRM Temp', '0', '30.00', 'degC', '1'],
    ['Vcpu2VRM Temp', '0', '34.00', 'degC', '1'],
    ['VmemABVRM Temp', '0', '26.00', 'degC', '1'],
    ['VmemCDVRM Temp', '0', '34.00', 'degC', '1'],
    ['VmemEFVRM Temp', '0', '29.00', 'degC', '1'],
    ['VmemGHVRM Temp', '0', '28.00', 'degC', '1'],
    ['P1-DIMMA1 Temp', '0', '25.00', 'degC', '1'],
    ['P1-DIMMB1 Temp', '0', '25.00', 'degC', '1'],
    ['P1-DIMMC1 Temp', '0', '26.00', 'degC', '1'],
    ['P1-DIMMD1 Temp', '0', '24.00', 'degC', '1'],
    ['P2-DIMME1 Temp', '0', '28.00', 'degC', '1'],
    ['P2-DIMMF1 Temp', '0', '26.00', 'degC', '1'],
    ['P2-DIMMG1 Temp', '0', '27.00', 'degC', '1'],
    ['P2-DIMMH1 Temp', '0', '28.00', 'degC', '1'],
    ['MB/AOM_SAS Temp', '0', '46.00', 'degC', '1'],
    ['FAN1', '1', '3100', 'RPM', '1'],
    ['FAN3', '1', '3100', 'RPM', '1'],
    ['FANA', '1', '2600', 'RPM', '1'],
    ['12V', '2', '12.06', 'V DC', '1'],
    ['5VCC', '2', '5.08', 'V DC', '1'],
    ['3.3VCC', '2', '3.38', 'V DC', '1'],
    ['VBAT', '2', '2.98', 'V DC', '1'],
    ['Vcpu1', '2', '1.84', 'V DC', '1'],
    ['Vcpu2', '2', '1.84', 'V DC', '1'],
    ['VDIMMAB', '2', '1.21', 'V DC', '1'],
    ['VDIMMCD', '2', '1.21', 'V DC', '1'],
    ['VDIMMEF', '2', '1.21', 'V DC', '1'],
    ['VDIMMGH', '2', '1.21', 'V DC', '1'],
    ['5VSB', '2', '4.97', 'V DC', '1'],
    ['3.3VSB', '2', '3.30', 'V DC', '1'],
    ['1.5V PCH', '2', '1.52', 'V DC', '1'],
    ['1.2V BMC', '2', '1.22', 'V DC', '1'],
    ['1.05V PCH', '2', '1.06', 'V DC', '1'],
    ['Chassis Intru', '9', 'off', '', '1'],
    ['PS1 Status', '21', 'present', '', '1'],
    ['PS2 Status', '21', 'present', '', '1']
]

discovery = {
    '': [
        ('CPU1 Temp', {}), ('CPU2 Temp', {}), ('MB/AOM_SAS Temp', {}),
        ('P1-DIMMA1 Temp', {}), ('P1-DIMMB1 Temp', {}),
        ('P1-DIMMC1 Temp', {}), ('P1-DIMMD1 Temp', {}),
        ('P2-DIMME1 Temp', {}), ('P2-DIMMF1 Temp', {}),
        ('P2-DIMMG1 Temp', {}), ('P2-DIMMH1 Temp', {}), ('PCH Temp', {}),
        ('Peripheral Temp', {}), ('System Temp', {}), ('Vcpu1VRM Temp', {}),
        ('Vcpu2VRM Temp', {}), ('VmemABVRM Temp', {}),
        ('VmemCDVRM Temp', {}), ('VmemEFVRM Temp', {}),
        ('VmemGHVRM Temp', {}), ('temp0', {})
    ],
    'indicator': [('Chassis Intru', {})],
    'drive': [('sd0', {})],
    'powersupply': [('PS1 Status', {}), ('PS2 Status', {})],
    'fan': [('FAN1', {}), ('FAN3', {}), ('FANA', {})],
    'voltage': [
        ('1.05V PCH', {}), ('1.2V BMC', {}), ('1.5V PCH', {}), ('12V', {}),
        ('3.3VCC', {}), ('3.3VSB', {}), ('5VCC', {}), ('5VSB', {}),
        ('VBAT', {}), ('VDIMMAB', {}), ('VDIMMCD', {}), ('VDIMMEF', {}),
        ('VDIMMGH', {}), ('Vcpu1', {}), ('Vcpu2', {})
    ]
}

checks = {
    '': [
        (
            'CPU1 Temp', {}, [
                (0, '35.0 \xb0C', [('temp', 35.0, None, None, None, None)])
            ]
        ),
        (
            'CPU2 Temp', {}, [
                (0, '36.0 \xb0C', [('temp', 36.0, None, None, None, None)])
            ]
        ),
        (
            'MB/AOM_SAS Temp', {}, [
                (0, '46.0 \xb0C', [('temp', 46.0, None, None, None, None)])
            ]
        ),
        (
            'P1-DIMMA1 Temp', {}, [
                (0, '25.0 \xb0C', [('temp', 25.0, None, None, None, None)])
            ]
        ),
        (
            'P1-DIMMB1 Temp', {}, [
                (0, '25.0 \xb0C', [('temp', 25.0, None, None, None, None)])
            ]
        ),
        (
            'P1-DIMMC1 Temp', {}, [
                (0, '26.0 \xb0C', [('temp', 26.0, None, None, None, None)])
            ]
        ),
        (
            'P1-DIMMD1 Temp', {}, [
                (0, '24.0 \xb0C', [('temp', 24.0, None, None, None, None)])
            ]
        ),
        (
            'P2-DIMME1 Temp', {}, [
                (0, '28.0 \xb0C', [('temp', 28.0, None, None, None, None)])
            ]
        ),
        (
            'P2-DIMMF1 Temp', {}, [
                (0, '26.0 \xb0C', [('temp', 26.0, None, None, None, None)])
            ]
        ),
        (
            'P2-DIMMG1 Temp', {}, [
                (0, '27.0 \xb0C', [('temp', 27.0, None, None, None, None)])
            ]
        ),
        (
            'P2-DIMMH1 Temp', {}, [
                (0, '28.0 \xb0C', [('temp', 28.0, None, None, None, None)])
            ]
        ),
        (
            'PCH Temp', {}, [
                (0, '36.0 \xb0C', [('temp', 36.0, None, None, None, None)])
            ]
        ),
        (
            'Peripheral Temp', {}, [
                (0, '34.0 \xb0C', [('temp', 34.0, None, None, None, None)])
            ]
        ),
        (
            'System Temp', {}, [
                (0, '23.0 \xb0C', [('temp', 23.0, None, None, None, None)])
            ]
        ),
        (
            'Vcpu1VRM Temp', {}, [
                (0, '30.0 \xb0C', [('temp', 30.0, None, None, None, None)])
            ]
        ),
        (
            'Vcpu2VRM Temp', {}, [
                (0, '34.0 \xb0C', [('temp', 34.0, None, None, None, None)])
            ]
        ),
        (
            'VmemABVRM Temp', {}, [
                (0, '26.0 \xb0C', [('temp', 26.0, None, None, None, None)])
            ]
        ),
        (
            'VmemCDVRM Temp', {}, [
                (0, '34.0 \xb0C', [('temp', 34.0, None, None, None, None)])
            ]
        ),
        (
            'VmemEFVRM Temp', {}, [
                (0, '29.0 \xb0C', [('temp', 29.0, None, None, None, None)])
            ]
        ),
        (
            'VmemGHVRM Temp', {}, [
                (0, '28.0 \xb0C', [('temp', 28.0, None, None, None, None)])
            ]
        ),
        (
            'temp0', {}, [
                (0, '30.0 \xb0C', [('temp', 30.0, None, None, None, None)])
            ]
        )
    ],
    'indicator': [('Chassis Intru', {}, [(0, 'Status: off', [])])],
    'drive': [('sd0', {}, [(0, 'Status: online', [])])],
    'powersupply': [
        ('PS1 Status', {}, [(0, 'Status: present', [])]),
        ('PS2 Status', {}, [(0, 'Status: present', [])])
    ],
    'fan': [
        (
            'FAN1', {
                'upper': (8000, 8400),
                'lower': (500, 300)
            }, [(0, 'Speed: 3100 RPM', [])]
        ),
        (
            'FAN3', {
                'upper': (8000, 8400),
                'lower': (500, 300)
            }, [(0, 'Speed: 3100 RPM', [])]
        ),
        (
            'FANA', {
                'upper': (8000, 8400),
                'lower': (500, 300)
            }, [(0, 'Speed: 2600 RPM', [])]
        )
    ],
    'voltage': [
        (
            '1.05V PCH', {}, [
                (
                    0, 'Voltage: 1.1 V', [
                        ('voltage', 1.06, None, None, None, None)
                    ]
                )
            ]
        ),
        (
            '1.2V BMC', {}, [
                (
                    0, 'Voltage: 1.2 V', [
                        ('voltage', 1.22, None, None, None, None)
                    ]
                )
            ]
        ),
        (
            '1.5V PCH', {}, [
                (
                    0, 'Voltage: 1.5 V', [
                        ('voltage', 1.52, None, None, None, None)
                    ]
                )
            ]
        ),
        (
            '12V', {}, [
                (
                    0, 'Voltage: 12.1 V', [
                        ('voltage', 12.06, None, None, None, None)
                    ]
                )
            ]
        ),
        (
            '3.3VCC', {}, [
                (
                    0, 'Voltage: 3.4 V', [
                        ('voltage', 3.38, None, None, None, None)
                    ]
                )
            ]
        ),
        (
            '3.3VSB', {}, [
                (
                    0, 'Voltage: 3.3 V', [
                        ('voltage', 3.3, None, None, None, None)
                    ]
                )
            ]
        ),
        (
            '5VCC', {}, [
                (
                    0, 'Voltage: 5.1 V', [
                        ('voltage', 5.08, None, None, None, None)
                    ]
                )
            ]
        ),
        (
            '5VSB', {}, [
                (
                    0, 'Voltage: 5.0 V', [
                        ('voltage', 4.97, None, None, None, None)
                    ]
                )
            ]
        ),
        (
            'VBAT', {}, [
                (
                    0, 'Voltage: 3.0 V', [
                        ('voltage', 2.98, None, None, None, None)
                    ]
                )
            ]
        ),
        (
            'VDIMMAB', {}, [
                (
                    0, 'Voltage: 1.2 V', [
                        ('voltage', 1.21, None, None, None, None)
                    ]
                )
            ]
        ),
        (
            'VDIMMCD', {}, [
                (
                    0, 'Voltage: 1.2 V', [
                        ('voltage', 1.21, None, None, None, None)
                    ]
                )
            ]
        ),
        (
            'VDIMMEF', {}, [
                (
                    0, 'Voltage: 1.2 V', [
                        ('voltage', 1.21, None, None, None, None)
                    ]
                )
            ]
        ),
        (
            'VDIMMGH', {}, [
                (
                    0, 'Voltage: 1.2 V', [
                        ('voltage', 1.21, None, None, None, None)
                    ]
                )
            ]
        ),
        (
            'Vcpu1', {}, [
                (
                    0, 'Voltage: 1.8 V', [
                        ('voltage', 1.84, None, None, None, None)
                    ]
                )
            ]
        ),
        (
            'Vcpu2', {}, [
                (
                    0, 'Voltage: 1.8 V', [
                        ('voltage', 1.84, None, None, None, None)
                    ]
                )
            ]
        )
    ]
}
