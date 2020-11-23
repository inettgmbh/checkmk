#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2019 tribe29 GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

# yapf: disable
# type: ignore

checkname = 'wmi_webservices'

info = [
    [
        'AnonymousUsersPersec', 'BytesReceivedPersec', 'BytesSentPersec', 'BytesTotalPersec',
        'Caption', 'CGIRequestsPersec', 'ConnectionAttemptsPersec', 'CopyRequestsPersec',
        'CurrentAnonymousUsers', 'CurrentBlockedAsyncIORequests', 'Currentblockedbandwidthbytes',
        'CurrentCALcountforauthenticatedusers', 'CurrentCALcountforSSLconnections',
        'CurrentCGIRequests', 'CurrentConnections', 'CurrentISAPIExtensionRequests',
        'CurrentNonAnonymousUsers', 'DeleteRequestsPersec', 'Description', 'FilesPersec',
        'FilesReceivedPersec', 'FilesSentPersec', 'Frequency_Object', 'Frequency_PerfTime',
        'Frequency_Sys100NS', 'GetRequestsPersec', 'HeadRequestsPersec',
        'ISAPIExtensionRequestsPersec', 'LockedErrorsPersec', 'LockRequestsPersec',
        'LogonAttemptsPersec', 'MaximumAnonymousUsers', 'MaximumCALcountforauthenticatedusers',
        'MaximumCALcountforSSLconnections', 'MaximumCGIRequests', 'MaximumConnections',
        'MaximumISAPIExtensionRequests', 'MaximumNonAnonymousUsers',
        'MeasuredAsyncIOBandwidthUsage', 'MkcolRequestsPersec', 'MoveRequestsPersec', 'Name',
        'NonAnonymousUsersPersec', 'NotFoundErrorsPersec', 'OptionsRequestsPersec',
        'OtherRequestMethodsPersec', 'PostRequestsPersec', 'PropfindRequestsPersec',
        'ProppatchRequestsPersec', 'PutRequestsPersec', 'SearchRequestsPersec', 'ServiceUptime',
        'Timestamp_Object', 'Timestamp_PerfTime', 'Timestamp_Sys100NS',
        'TotalAllowedAsyncIORequests', 'TotalAnonymousUsers', 'TotalBlockedAsyncIORequests',
        'Totalblockedbandwidthbytes', 'TotalBytesReceived', 'TotalBytesSent',
        'TotalBytesTransferred', 'TotalCGIRequests', 'TotalConnectionAttemptsallinstances',
        'TotalCopyRequests', 'TotalcountoffailedCALrequestsforauthenticatedusers',
        'TotalcountoffailedCALrequestsforSSLconnections', 'TotalDeleteRequests',
        'TotalFilesReceived', 'TotalFilesSent', 'TotalFilesTransferred', 'TotalGetRequests',
        'TotalHeadRequests', 'TotalISAPIExtensionRequests', 'TotalLockedErrors',
        'TotalLockRequests', 'TotalLogonAttempts', 'TotalMethodRequests',
        'TotalMethodRequestsPersec', 'TotalMkcolRequests', 'TotalMoveRequests',
        'TotalNonAnonymousUsers', 'TotalNotFoundErrors', 'TotalOptionsRequests',
        'TotalOtherRequestMethods', 'TotalPostRequests', 'TotalPropfindRequests',
        'TotalProppatchRequests', 'TotalPutRequests', 'TotalRejectedAsyncIORequests',
        'TotalSearchRequests', 'TotalTraceRequests', 'TotalUnlockRequests',
        'TraceRequestsPersec', 'UnlockRequestsPersec'
    ],
    [
        '146391', '2034500749', '6383942732', '8418443481', '', '0', '821014', '0', '0',
        '0', '0', '0', '0', '0', '11', '8', '8', '0', '', '33', '0', '33', '0',
        '1953125', '10000000', '275760', '0', '231138', '0', '0', '1305777', '7', '0',
        '0', '0', '39', '16', '35', '0', '0', '0', '_Total', '577164', '8', '0',
        '491115', '779171', '0', '0', '0', '0', '2778588', '0', '6743176430643',
        '130951777566120000', '0', '146391', '0', '0', '2034500749', '6383942732',
        '8418443481', '0', '821014', '0', '0', '0', '0', '0', '33', '33', '275760', '0',
        '231138', '0', '0', '1305777', '1546056', '1546056', '0', '0', '577164', '8',
        '0', '491115', '779171', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        '44682', '388339380', '3109860488', '3498199868', '', '0', '141001', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '', '3', '0', '3', '0',
        '1953125', '10000000', '137000', '0', '0', '0', '0', '226055', '5', '0', '0',
        '0', '17', '0', '14', '0', '0', '0', 'Default Web Site', '133797', '8', '0',
        '28836', '60246', '0', '0', '0', '0', '2778588', '0', '6743176430643',
        '130951777566120000', '0', '44682', '0', '0', '388339380', '3109860488',
        '3498199868', '0', '141001', '0', '0', '0', '0', '0', '3', '3', '137000', '0',
        '0', '0', '0', '226055', '226086', '226086', '0', '0', '133797', '8', '0',
        '28836', '60246', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        '101709', '1646161369', '3274082244', '4920243613', '', '0', '680013', '0', '0',
        '0', '0', '0', '0', '0', '11', '8', '8', '0', '', '30', '0', '30', '0',
        '1953125', '10000000', '138760', '0', '231138', '0', '0', '1079722', '2', '0',
        '0', '0', '22', '16', '21', '0', '0', '0', 'Exchange Back End', '443367', '0',
        '0', '462279', '718925', '0', '0', '0', '0', '2778588', '0', '6743176430643',
        '130951777566120000', '0', '101709', '0', '0', '1646161369', '3274082244',
        '4920243613', '0', '680013', '0', '0', '0', '0', '0', '30', '30', '138760', '0',
        '231138', '0', '0', '1079722', '1319970', '1319970', '0', '0', '443367', '0',
        '0', '462279', '718925', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ]
]

discovery = {'': [('Default Web Site', None), ('Exchange Back End', None)]}

checks = {
    '': [
        (
            'Default Web Site',
            {},
            [(0, 'Connections: 0.00', [('connections', 0.0, None, None, None, None)])],
        ),
        (
            'Exchange Back End',
            {},
            [(0, 'Connections: 0.00', [('connections', 0.0, None, None, None, None)])],
        ),
    ]
}
