#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2019 tribe29 GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

# yapf: disable
# type: ignore

checkname = 'msexch_owa'

info = [[
    'ActiveConversions', 'ActiveMailboxSubscriptions', 'AggregatedConfigurationReads',
    'AggregatedConfigurationRebuilds', 'AggregatedConfigurationRequests', 'ASQueries',
    'ASQueriesFailurePercent', 'AttachmentsUploadedSinceOWAStart', 'AverageCheckSpellingTime',
    'AverageConversionQueuingTime', 'AverageConversionTime', 'AverageResponseTime',
    'AverageSearchTime', 'CalendarViewRefreshed', 'CalendarViewsLoaded', 'Caption',
    'CASCrossSiteRedirectionEarliertoLaterVersion',
    'CASCrossSiteRedirectionLatertoEarlierVersion',
    'CASIntraSiteRedirectionEarliertoLaterVersion',
    'CASIntraSiteRedirectionLatertoEarlierVersion', 'ConnectionFailedTransientExceptionPercent',
    'ConversionRequestsKBPersec', 'ConversionResponsesKBPersec', 'Conversions',
    'ConversionsEndedbyTimeout', 'ConversionsEndedwithErrors', 'CurrentProxyUsers',
    'CurrentUniqueUsers', 'CurrentUniqueUsersLight', 'CurrentUniqueUsersPremium',
    'CurrentUsers', 'CurrentUsersLight', 'CurrentUsersPremium', 'Description',
    'FailedRequestsPersec', 'FailurerateofrequestsfromOWAtoEWS', 'Frequency_Object',
    'Frequency_PerfTime', 'Frequency_Sys100NS', 'IMAverageSignInTime',
    'IMMessageDeliveryFailuresPersec', 'IMMessagesReceivedPersec', 'IMMessagesSentPersec',
    'IMPresenceQueriesPersec', 'IMSentMessageDeliveryFailurePercent', 'IMSignInFailurePercent',
    'IMSignInFailures', 'IMSignInFailuresPersec', 'IMTotalMessageDeliveryFailures',
    'IMTotalMessagesReceived', 'IMTotalMessagesSent', 'IMTotalPresenceQueries', 'IMTotalUsers',
    'IMUsersCurrentlySignedIn', 'InvalidCanaryRequests', 'IRMprotectedMessagesSent',
    'ItemsCreatedSinceOWAStart', 'ItemsDeletedSinceOWAStart', 'ItemsUpdatedSinceOWAStart',
    'LogonsPersec', 'LogonsPersecLight', 'LogonsPersecPremium', 'MailboxNotificationsPersec',
    'MailboxOfflineExceptionFailurePercent', 'MailViewRefreshes', 'MailViewsLoaded',
    'MessagesSent', 'Name', 'NamesChecked', 'PasswordChanges', 'PeakUserCount',
    'PeakUserCountLight', 'PeakUserCountPremium', 'PID', 'ProxyRequestBytes',
    'ProxyResponseBytes', 'ProxyResponseTimeAverage', 'ProxyUserRequests',
    'ProxyUserRequestsPersec', 'QueuedConversionRequests', 'RejectedConversions', 'Requests',
    'RequestsFailed', 'RequestsPersec', 'RequestTimeOuts', 'Searches', 'SearchesTimedOut',
    'SenderPhotosLDAPcallsPersec', 'SenderPhotosTotalentriesinRecipientsNegativeCache',
    'SenderPhotosTotalLDAPcalls', 'SenderPhotosTotalLDAPcallsreturnednonemptyimagedata',
    'SenderPhotosTotalnumberofavoidedLDAPcallsduetocache', 'SessionDataCachebuildscompleted',
    'SessionDataCachebuildstarts', 'SessionDataCachetimeout', 'SessionDataCacheused',
    'SessionDataCachewaitedforpreloadtocomplete', 'SessionsEndedbyLogoff',
    'SessionsEndedbyTimeout', 'SpellingChecks', 'StoragePermanentExceptionFailurePercent',
    'StorageTransientExceptionFailurePercent', 'StoreLogonFailurePercent',
    'SuccessfulConversionRequestsKBPersec', 'Timestamp_Object', 'Timestamp_PerfTime',
    'Timestamp_Sys100NS', 'TotalMailboxNotifications', 'TotalUniqueUsers',
    'TotalUniqueUsersLight', 'TotalUniqueUsersPremium',
    'TotalUsercontextReInitializationrequests', 'TotalUsers', 'TotalUsersLight',
    'TotalUsersPremium', 'UNCRequests', 'UNCResponseBytes', 'UNCResponseBytesPersec',
    'WSSRequests', 'WSSResponseBytes', 'WSSResponseBytesPersec'
],
        [
            '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
            '0', '', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
            '0', '0', '0', '0', '', '0', '0', '0', '1953125', '10000000', '0', '0',
            '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
            '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '', '0', '0',
            '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
            '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
            '0', '0', '0', '0', '0', '0', '0', '6743176249526', '130951777565180000', '0',
            '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
        ]]

discovery = {'': [(None, None)]}

checks = {
    '': [
        (None, {}, [
            (0, 'Requests/sec: 0.00', [
                ('requests_per_sec', 0.0, None, None, None, None),
            ]),
            (0, 'Unique users: 0', [
                ('current_users', 0.0, None, None, None, None),
            ]),
        ]),
    ],
}
