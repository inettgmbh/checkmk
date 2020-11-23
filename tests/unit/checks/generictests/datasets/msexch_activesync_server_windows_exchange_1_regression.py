#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2019 tribe29 GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

# yapf: disable
# type: ignore

checkname = 'msexch_activesync'

info = [[
    'AvailabilityRequestsPersec', 'AvailabilityRequestsTotal', 'AverageHangTime',
    'AverageLDAPLatency', 'AverageRequestTime', 'AverageRPCLatency',
    'BadItemReportsGeneratedTotal', 'Caption', 'ConflictingConcurrentSyncPersec',
    'ConflictingConcurrentSyncTotal', 'CreateCollectionCommandsPersec', 'CreateCollectionTotal',
    'CurrentRequests', 'DeleteCollectionCommandsPersec', 'DeleteCollectionTotal', 'Description',
    'DocumentLibraryFetchCommandsPersec', 'DocumentLibraryFetchTotal',
    'DocumentLibrarySearchesPersec', 'DocumentLibrarySearchTotal', 'EmptyFolderContentsPersec',
    'EmptyFolderContentsTotal', 'FailedItemConversionTotal', 'FolderCreateCommandsPersec',
    'FolderCreateTotal', 'FolderDeleteCommandsPersec', 'FolderDeleteTotal',
    'FolderSyncCommandsPersec', 'FolderSyncTotal', 'FolderUpdateCommandsPersec',
    'FolderUpdateTotal', 'Frequency_Object', 'Frequency_PerfTime', 'Frequency_Sys100NS',
    'GALSearchesPersec', 'GALSearchTotal', 'GetAttachmentCommandsPersec', 'GetAttachmentTotal',
    'GetHierarchyCommandsPersec', 'GetHierarchyTotal', 'GetItemEstimateCommandsPersec',
    'GetItemEstimateTotal', 'HeartbeatInterval', 'IncomingProxyRequestsTotal',
    'IRMprotectedMessageDownloadsPersec', 'IRMprotectedMessageDownloadsTotal',
    'ItemOperationsCommandsPersec', 'ItemOperationsTotal',
    'MailboxAttachmentFetchCommandsPersec', 'MailboxAttachmentFetchTotal',
    'MailboxItemFetchCommandsPersec', 'MailboxItemFetchTotal', 'MailboxOfflineErrorsPerminute',
    'MailboxSearchesPersec', 'MailboxSearchTotal', 'MeetingResponseCommandsPersec',
    'MeetingResponseTotal', 'MoveCollectionCommandsPersec', 'MoveCollectionTotal',
    'MoveItemsCommandsPersec', 'MoveItemsTotal', 'Name', 'NumberofADPolicyQueriesonReconnect',
    'Numberofautoblockeddevices', 'NumberofNotificationManagerObjectsinMemory',
    'OptionsCommandsPersec', 'OptionsTotal', 'OutgoingProxyRequestsTotal',
    'PermanentActiveDirectoryErrorsPerminute', 'PermanentStorageErrorsPerminute', 'PID',
    'PingCommandsDroppedPersec', 'PingCommandsPending', 'PingCommandsPersec',
    'PingDroppedTotal', 'PingTotal', 'ProvisionCommandsPersec', 'ProvisionTotal',
    'ProxyLogonCommandsSentTotal', 'ProxyLogonReceivedTotal', 'RecoverySyncCommandsPersec',
    'RecoverySyncTotal', 'RequestsPersec', 'RequestsTotal', 'SearchCommandsPersec',
    'SearchTotal', 'SendIRMprotectedMessagesPersec', 'SendIRMprotectedMessagesTotal',
    'SendMailCommandsPersec', 'SendMailTotal', 'SettingsCommandsPersec', 'SettingsTotal',
    'SmartForwardCommandsPersec', 'SmartForwardTotal', 'SmartReplyCommandsPersec',
    'SmartReplyTotal', 'SyncCommandsDroppedPersec', 'SyncCommandsPending', 'SyncCommandsPersec',
    'SyncDroppedTotal', 'SyncStateKBytesLeftCompressed', 'SyncStateKBytesTotal', 'SyncTotal',
    'Timestamp_Object', 'Timestamp_PerfTime', 'Timestamp_Sys100NS',
    'TransientActiveDirectoryErrorsPerminute', 'TransientErrorsPerminute',
    'TransientMailboxConnectionFailuresPerminute', 'TransientStorageErrorsPerminute',
    'WrongCASProxyRequestsTotal'
],
        [
            '0', '0', '0', '0', '53', '0', '0', '', '0', '0', '0', '0', '0', '0',
            '0', '', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
            '0', '0', '0', '1953125', '10000000', '0', '0', '0', '0', '0', '0', '0',
            '0', '0', '15426', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
            '0', '0', '0', '0', '0', '0', '', '0', '0', '0', '0', '0', '0', '0', '0',
            '13604', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '15426',
            '15426', '0', '0', '0', '0', '0', '0', '15426', '15426', '0', '0', '0',
            '0', '0', '0', '0', '0', '0', '0', '0', '0', '6743176182062',
            '130951777564870000', '0', '0', '0', '0', '0'
        ]]

discovery = {'': [(None, None)]}

checks = {
    '': [(
        None,
        {},
        [(0, 'Requests/sec: 0.00', [('requests_per_sec', 0.0, None, None, None, None)])],
    )]
}
