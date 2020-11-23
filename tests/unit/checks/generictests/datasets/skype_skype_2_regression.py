#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2019 tribe29 GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

# yapf: disable
# type: ignore

checkname = 'skype'

info = [
    ['sampletime', '42', '1'], ['[LS:WEB - Address Book Web Query]'],
    [
        'instance', 'WEB - Search requests', 'WEB - Search requests/sec',
        'WEB - Successful search requests', 'WEB - Successful search requests/sec',
        'WEB - Failed search requests', 'WEB - Failed search requests/sec',
        'WEB - Average processing time for a search request in milliseconds', ' ',
        'WEB - Database queries/sec',
        'WEB - Average processing time per address book database query in milliseconds', ' ',
        'WEB - Change Search requests', 'WEB - Change Search requests/sec',
        'WEB - Failed change search requests', 'WEB - Failed change search requests/sec',
        'WEB - Average processing time per change search in milliseconds', ' ',
        'WEB - Change Search of DTMF requests', 'WEB - Change Search of DTMF requests/sec',
        'WEB - Organizational search requests', 'WEB - Organizational search requests/sec',
        'WEB - Failed organizational search requests',
        'WEB - Failed organizational search requests/sec',
        'WEB - Average processing time for organizational search request in milliseconds', ' ',
        'WEB - Basic and Org Search Request Exception Count',
        'WEB - Basic and Org Search Request Exception/sec', 'WEB - Basic Search requests',
        'WEB - Basic Search requests/sec', 'WEB - Failed basic search requests',
        'WEB - Failed Basic search requests/sec',
        'WEB - Average processing time for basic search request in milliseconds', ' ',
        'WEB - Prefix dial string search requests',
        'WEB - Prefix dial string search requests/sec',
        'WEB - One character prefix search requests',
        'WEB - One character prefix search requests/sec',
        'WEB - Average processing time for one character search requests in milliseconds', ' ',
        'WEB - Two character prefix search requests',
        'WEB - Two character prefix search requests/sec',
        'WEB - Average processing time for two character search requests in milliseconds', ' ',
        'WEB - Three or more character prefix search requests',
        'WEB - Three or more character prefix search requests/sec',
        'WEB - Average processing time for three or more character search requests in milliseconds',
        ' ', 'WEB - Photo requests', 'WEB - Photo requests/sec', 'WEB - Photo failed requests',
        'WEB - Photo failed requests/sec', 'WEB - Photo requests throttled',
        'WEB - Photo hash cache entry update count',
        'WEB - Average processing time for photo cached locally in milliseconds', ' ',
        'WEB - Average processing time for photo not cached in milliseconds', ' ',
        'WEB - % Photo Local Cache Hit', ' ', 'WEB - Skype Public Directory Search Requests',
        'WEB - Skype Public Directory Search Requests/sec',
        'WEB - Failed Skype Public Directory Search Requests',
        'WEB - Failed Skype Public Directory Search Requests/sec',
        'WEB - Skype Public Search Average Processing Time', ' ',
        'WEB - Skype Public Directory Search Feedback Requests',
        'WEB - Skype Public Directory Search Feedback Requests/sec',
        'WEB - Failed Skype Public Directory Search Feedback Requests',
        'WEB - Failed Skype Public Directory Search Feedback Requests/sec',
        'WEB - Skype Public Search Feedback Average Processing Time', ' ',
        'WEB - Failed Skype Search Requests With 4xx Response Codes',
        'WEB - Failed Skype Search Requests Per Second With 4xx Response Codes',
        'WEB - Total Skype Search Requests Throttled',
        'WEB - Skype Search Requests Throttled Per Second',
        'WEB - Failed Skype Search Requests With 5xx Response Codes',
        'WEB - Failed Skype Search Requests Per Second With 5xx Response Codes',
        'WEB - Failed Skype Search Feedback Requests With 4xx Response Codes',
        'WEB - Failed Skype Search Feedback Requests Per Second With 4xx Response Codes',
        'WEB - Total Skype Search Feedback Requests Throttled',
        'WEB - Skype Search Feedback Requests Throttled Per Second',
        'WEB - Failed Skype Search Feedback Requests With 5xx Response Codes',
        'WEB - Failed Skype Search Feedback Requests Per Second With 5xx Response Codes',
        'WEB - Total Skype Search Requests Next Hop Connection Failures',
        'WEB - Skype Search Requests Next Hop Connection Failures Per Second',
        'WEB - Skype Search Or Feedback Requests In Processing',
        'WEB - Total Skype Search Or Feedback Requests Throttled By Local Server'
    ],
    [
        '""', '17740', '17740', '17740', '17740', '0', '0', '34282', '17740', '17740',
        '33925', '17740', '8332', '8332', '0', '0', '9852', '8332', '0', '0', '7', '7',
        '0', '0', '15', '7', '0', '0', '95', '95', '0', '0', '264', '95', '0', '0',
        '13', '13', '109', '13', '11', '11', '16', '11', '71', '71', '139', '71',
        '1593', '1593', '0', '0', '0', '208', '222', '1385', '7702', '208', '1385',
        '1593', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ], ['[LS:WEB - Location Information Service]'],
    [
        'instance', 'WEB - Succeeded Get Locations Requests',
        'WEB - Succeeded Get Locations Requests/Second',
        'WEB - Average processing time for a successful Get Locations request in milliseconds',
        ' ', 'WEB - Failed Get Locations Requests', 'WEB - Failed Get Locations Requests/Second',
        'WEB - Location matches by WAP', 'WEB - Location matches by WAP/Second',
        'WEB - Location matches by Subnet', 'WEB - Location matches by Subnet/Second',
        'WEB - Location matches by Switch', 'WEB - Location matches by Switch/Second',
        'WEB - Location matches by Port', 'WEB - LocationMatchesByPort/Second',
        'WEB - Location matches by MAC', 'WEB - Location matches by MAC/Second',
        'WEB - Succeeded Get Locations In City Requests',
        'WEB - Succeeded Get Locations In City Requests/Second',
        'WEB - Average processing time for a successful Get Locations In City request in milliseconds',
        ' ', 'WEB - Failed Get Locations In City Requests',
        'WEB - Failed Get Locations In City Requests/Second'
    ],
    [
        '""', '0', '0', '0', '0', '264', '264', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ], ['[LS:WEB - Distribution List Expansion]'],
    [
        'instance', 'WEB - Valid User Requests', 'WEB - Valid User Requests/sec',
        'WEB - Request Processing Time', ' ', 'WEB - Pending Active Directory Requests',
        'WEB - Average Active Directory Fetch time in milliseconds', ' ',
        'WEB - Pending Requests that fetch member properties',
        'WEB - Average member properties fetch time in milliseconds', ' ',
        'WEB - Timed out Active Directory Requests',
        'WEB - Timed out Active Directory Requests/sec',
        'WEB - Timed out Requests that fetch member properties',
        'WEB - Timed out Requests that fetch member properties/sec', 'WEB - Soap Exceptions',
        'WEB - Soap exceptions/sec', 'WEB - Database Errors', 'WEB - Database Errors/sec',
        'WEB - MSODS User Requests', 'WEB - MSODS User Requests/sec',
        'WEB - MSODS Responses that succeeded', 'WEB - MSODS Responses that failed',
        'WEB - Average MSODS query time in milliseconds', ' ',
        'WEB - Failed MSODS authorizations attempts', 'WEB - Empty MSODS results received',
        'WEB - Number of empty results from AD per second', 'WEB - Request Succeeded Count',
        'WEB - Request Success Rate (%)', ' ', 'WEB - Request Failed Count',
        'WEB - Request Failed Rate (%)', ' ', 'WEB - Request Exception Count',
        'WEB - Request Exception Rate (%)', ''
    ],
    [
        '""', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0'
    ], ['[LS:WEB - UCWA]'],
    [
        'instance', 'UCWA - Average Lifetime for Session (ms)', ' ',
        'UCWA - Average Application Startup Time (ms)', ' ', 'UCWA - Active Application Count',
        'UCWA - Active User Instance Count', 'UCWA - Active User Instances without application',
        'UCWA - Active Session Count',
        'UCWA - Active Session Count With Active Presence Subscriptions',
        'UCWA - HTTP 4xx Responses/Second', 'UCWA - HTTP 5xx Responses/Second',
        'UCWA - Requests Received/Second', 'UCWA - Requests Succeeded/Second',
        'UCWA - Application Creation Requests Received/Second',
        'UCWA - Succeeded Create Application Requests/Second',
        'UCWA - Total Requests Received on the Command Channel',
        'UCWA - Total HTTP 4xx Responses', 'UCWA - Total HTTP 5xx Responses',
        'UCWA - Total Requests Succeeded', 'UCWA - Total Application Creation Requests Received',
        'UCWA - Total Sessions Initiated',
        'UCWA - Total Sessions Terminated Because of Idle Timeout',
        'UCWA - Active Messaging Modality Count', 'UCWA - Active Audio Modality Count',
        'UCWA - Active Video Modality Count', 'UCWA - Active Panoramic Video Modality Count',
        'UCWA - Active Application Sharing Modality Count',
        'UCWA - Active Data Collaboration Modality Count',
        'UCWA - Exchange HD Photo Get Latency (ms)', ' ',
        'UCWA - Number of HD Photo Get Failures', 'UCWA - Exchange Contact Search Latency (ms)',
        ' ', 'UCWA - Currently Active Presence Subscription Count',
        'UCWA - Over The Maximum Subscriptions Per Application',
        'UCWA - Over The Maximum Subscriptions Per Batch',
        'UCWA - Retrieving Inband Data Failures', 'UCWA - Presence Subscription Failures',
        'UCWA - Registering Endpoint Failures', 'UCWA - Total Throttled Applications',
        'UCWA - IM MCU Join Failures', 'UCWA - AV MCU Join Failures',
        'UCWA - AS MCU Join Failures', 'UCWA - Data MCU Join Failures',
        'UCWA - Active Directory Photo Get Latency (ms)', ' ',
        'UCWA - Number of Active Directory Photo Get Failures',
        'UCWA - Number of Deserialization Failures', 'UCWA - Exchange Photo Get Requests/Second',
        'UCWA - Exchange Photo Get Success/Second', 'UCWA - Exchange Photo Get Latency (ms)',
        ' ', 'UCWA - Number of Photo Get Failures', 'UCWA - AD Photo Get Requests/Second',
        'UCWA - AD Photo Get Success/Second', 'UCWA - Number of Serialization Failures',
        'UCWA - Number of Presence Publications', 'UCWA - Presence Publications/Second',
        'UCWA - Number of Presence Deletions', 'UCWA - Presence Deletions/Second',
        'UCWA - Number of Presence Polling', 'UCWA - Presence Polling/Second',
        'UCWA - Number of External Presence Subscriptions',
        'UCWA - Current Number of External Presence Subscriptions',
        'UCWA - External Presence Subscriptions/Second',
        'UCWA - Address Book Search Requests/Second',
        'UCWA - Number of Address Book Search Request Failures',
        'UCWA - Exchange Search Requests/Second',
        'UCWA - Number of Exchange Search Request Failures',
        'UCWA - Number of UCS Subcription failures', 'UCWA - Current Number of AV Calls',
        'UCWA - Outbound AV Calls/Second', 'UCWA - Number of Outbound AV Call Failures',
        'UCWA - Inbound AV Calls/Second', 'UCWA - Number of Inbound AV Call Failures',
        'UCWA - Number of Inbound AV Calls Declined', 'UCWA - Push Notifications/Second',
        'UCWA - Number of Push Notification Failures',
        'UCWA - Number of PNCH returned Push Notification Failures',
        'UCWA - Number of Push Notifications Throttled', 'UCWA - DL Expansion Latency (ms)', ' ',
        'UCWA - Number of DL Expansion Failures', 'UCWA - DL Expansion Requests/Second',
        'UCWA - Inbound IM Calls/Second', 'UCWA - Number of Inbound IM Call Failures',
        'UCWA - Number of Inbound IM Calls Declined', 'UCWA - Outbound IM Calls/Second',
        'UCWA - Number of Outbound IM Call Failures', 'UCWA - IM Messages Sent/Second',
        'UCWA - IM Messages Received/Second', 'UCWA - Number of Outgoing IM Message Failures',
        'UCWA - Number of Incoming IM Message Failures',
        'UCWA - UCWA Application Instance Lifetime Bucket 0',
        'UCWA - UCWA Application Instance Lifetime Bucket 1',
        'UCWA - UCWA Application Instance Lifetime Bucket 2',
        'UCWA - Total Missed Conversations Pulled from Exchange',
        'UCWA - Total Archived Conversations Pulled from Exchange',
        'UCWA - Total Conversations History Requests to Exchange Failed',
        'UCWA - Total Conversations History Requests to Exchange Succeeded',
        'UCWA - Exchange Conversation History Request Latency (ms)', ' ',
        'UCWA - Number of Conversation History Message Format Transcription Failed',
        'UCWA - Conversation History Message Converted to Plain Text',
        'UCWA - Total Conversation History Messages Converted to HTML',
        'UCWA - Total Number of Start Modality Requested',
        'UCWA - Total Number of Continue Modality Requested',
        'UCWA - Conversation History Fallbacks To Mail Addresses',
        'UCWA - Total number of get conversation log requests',
        'UCWA - Total number of get conversation log batched requests',
        'UCWA - Total number of get conversation log effective batched requests',
        'UCWA - Total number of auto accepted incoming messaging invite requests',
        'UCWA - Total number of auto accepted incoming conference invite requests',
        'UCWA - Number of Address Book Search Request Succeeded',
        'UCWA - Number of Exchange Search Request Succeeded'
    ],
    [
        '_Total', '295600679', '463', '7844247', '640', '0', '0', '0', '0', '0', '5147',
        '1', '22864', '17716', '30', '640', '22864', '5147', '1', '17716', '30', '463',
        '18', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '4316', '610', '0', '0', '2185',
        '867', '264506', '2185', '1318', '610', '610', '0', '1125', '1125', '230', '230',
        '248', '248', '135', '0', '135', '66', '0', '0', '0', '0', '0', '21', '1',
        '1', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '52', '0', '0', '27',
        '3', '36', '10', '0', '0', '0', '0', '0', '255', '5613', '10', '413', '111947',
        '352', '0', '513', '0', '12', '6', '33', '441', '146', '44', '52', '1', '66',
        '0'
    ],
    [
        'Undefined', '0', '0', '0', '0', '0', '0', '0', '0', '0', '3140', '1', '6489',
        '3348', '0', '0', '6489', '3140', '1', '3348', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '4316', '610', '0', '0', '2185', '867', '264506', '2185',
        '1318', '610', '610', '0', '1125', '1125', '230', '230', '248', '248', '0', '0',
        '0', '66', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '513', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '66', '0'
    ],
    [
        'iPhoneLync', '177298156', '282', '7286806', '436', '0', '0', '0', '0', '0',
        '1777', '0', '13550', '11773', '8', '436', '13550', '1777', '0', '11773', '8',
        '282', '9', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '96', '0', '96',
        '0', '0', '0', '0', '0', '0', '8', '1', '1', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '19', '0', '0', '17', '3', '20', '0', '0', '0', '0', '0',
        '0', '123', '4173', '1', '296', '83674', '278', '0', '0', '0', '12', '5', '29',
        '311', '121', '35', '19', '0', '0', '0'
    ],
    [
        'AndroidLync', '76688062', '119', '4741', '138', '0', '0', '0', '0', '0', '91',
        '0', '1405', '1314', '3', '138', '1405', '91', '0', '1314', '3', '119', '4',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '32', '0', '32', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '16', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '128',
        '1236', '9', '103', '25301', '63', '0', '0', '0', '0', '0', '0', '97', '19',
        '6', '16', '1', '0', '0'
    ],
    [
        'LWA', '13635907', '16', '241', '16', '0', '0', '0', '0', '0', '62', '0',
        '523', '461', '16', '16', '523', '62', '0', '461', '16', '16', '4', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '11', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '9', '0', '16', '10', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0'
    ],
    [
        'iPadLync', '27978554', '46', '552459', '50', '0', '0', '0', '0', '0', '77',
        '0', '897', '820', '3', '50', '897', '77', '0', '820', '3', '46', '1', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '7', '0', '7', '0', '0', '0',
        '0', '0', '0', '2', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '17', '0', '0', '1', '0', '0', '0', '0', '0', '0', '0', '0', '4', '204',
        '0', '14', '2972', '11', '0', '0', '0', '0', '1', '4', '33', '6', '3', '17',
        '0', '0', '0'
    ], ['[LS:WEB - Mobile Communication Service]'],
    [
        'instance', 'WEB - Total Session Initiated Count',
        'WEB - Currently Active Session Count',
        'WEB - Currently Active Session Count With Active Presence Subscriptions',
        'WEB - Succeeded Initiate Session Requests/Second',
        'WEB - Total number of sessions terminated by user',
        'WEB - Total Sessions Terminated Because of User Idle Timeout',
        'WEB - Average life time for a session in milliseconds', ' ',
        'WEB - Total Requests received on the Command Channel', 'WEB - Requests received/Second',
        'WEB - Total Requests Rejected', 'WEB - Requests Rejected/Second',
        'WEB - Total Requests Succeeded', 'WEB - Requests Succeeded/Second',
        'WEB - Total Requests Failed', 'WEB - Requests Failed/Second',
        'WEB - Currently Active Poll Count', 'WEB - Currently Active Network Timeout Poll Count',
        'WEB - Total Succesful Outbound Voice Calls', 'WEB - Total Succesful Inbound Voice Calls',
        'WEB - Total Failed Outbound Voice Calls', 'WEB - Total Failed Inbound Voice Calls',
        'WEB - Total Declined Inbound Voice Calls',
        'WEB - Current Push Notification Subscriptions', 'WEB - Total Push Notification Requests',
        'WEB - Push Notification Requests/Second',
        'WEB - Total Push Notification Requests Succeeded',
        'WEB - Push Notification Requests Succeeded/Second',
        'WEB - Total Push Notification Requests Throttled',
        'WEB - Push Notification Requests Throttled/Second',
        'WEB - Total Push Notification Requests Failed',
        'WEB - Push Notification Requests Failed/Second'
    ],
    [
        '""', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0'
    ], ['[LS:WEB - Throttling and Authentication]'],
    [
        'instance', 'WEB - Unauthenticated Requests In Processing',
        'WEB - User Authenticated Requests In Processing',
        'WEB - Conference Authenticated Requests In Processing',
        'WEB - Total Requests In Processing', 'WEB - Entity Body Reads Outstanding',
        'WEB - Requests Exceeded Per-App Limit', 'WEB - Requests Exceeded Per-User Limit',
        'WEB - Requests Exceeded Per-Conference Limit',
        'WEB - Requests Exceeded Entity Body Read Time', 'WEB - Windows Authentication Requests',
        'WEB - Windows Authentication Requests/sec',
        'WEB - Failed Windows Authentication Requests',
        'WEB - Failed Windows Authentication Requests/sec',
        'WEB - Certificate Authentication Requests',
        'WEB - Certificate Authentication Requests/sec',
        'WEB - Failed Certificate Authentication Requests',
        'WEB - Failed Certificate Authentication Requests/sec',
        'WEB - Phone and PIN Authentication Requests',
        'WEB - Phone and PIN Authentication Requests/sec',
        'WEB - Failed Phone and PIN Authentication Requests',
        'WEB - Failed Phone and PIN Authentication Requests/sec',
        'WEB - Conference ID/PIN Authentication Requests',
        'WEB - Conference ID/PIN Authentication Requests/sec',
        'WEB - Failed Conference ID/PIN Authentication Requests',
        'WEB - Failed Conference ID/PIN Authentication Requests/sec',
        'WEB - Machine Certificate Authentication Requests',
        'WEB - Machine Certificate Authentication Requests/sec',
        'WEB - Failed Machine Certificate Authentication Requests',
        'WEB - Failed Machine Certificate Authentication Requests/sec',
        'WEB - WS Federated Authentication Requests',
        'WEB - WS Federated Authentication Requests/sec',
        'WEB - Failed WS Federated Authentication Requests',
        'WEB - Failed WS Federated Authentication Requests/sec',
        'WEB - Web Ticket Authentication Requests',
        'WEB - Web Ticket Authentication Requests/sec',
        'WEB - Failed Web Ticket Authentication Requests',
        'WEB - Failed Web Ticket Authentication Requests/sec',
        'WEB - Conference Ticket Authentication Requests',
        'WEB - Conference Ticket Authentication Requests/sec',
        'WEB - Failed Conference Ticket Authentication Requests',
        'WEB - Failed Conference Ticket Authentication Requests/sec',
        'WEB - Expired Web Tickets Rejected', 'WEB - Expired Web Tickets Rejected/sec',
        'WEB - Other Server Proof Tickets Rejected',
        'WEB - Other Server Proof Tickets Rejected/sec',
        'WEB - Time Skewed Proof Tickets Rejected',
        'WEB - Time Skewed Proof Tickets Rejected/sec',
        'WEB - Missing Credential Requests Challenged',
        'WEB - Missing Credential Requests Challenged/sec', 'WEB - Total Requests',
        'WEB - Total Requests/sec', 'WEB - WS-Federation Passive Authentication Requests',
        'WEB - WS-Federation Passive Authentication Requests/sec',
        'WEB - Failed WS-Federation Passive Authentication Requests',
        'WEB - Failed WS-Federation Passive Authentication Requests/sec',
        'WEB - OAuth Token Authentication Requests',
        'WEB - OAuth Token Authentication Requests/sec',
        'WEB - Failed OAuth Token Authentication Requests',
        'WEB - Failed OAuth Token Authentication Requests/sec',
        'WEB - Internal Mutual TLS Authentication Requests',
        'WEB - Internal Mutual TLS Authentication Requests/sec',
        'WEB - Failed Internal Mutual TLS Authentication Requests',
        'WEB - Failed Internal Mutual TLS Authentication Requests/sec',
        'WEB - Session Web Ticket Authentication Requests',
        'WEB - Session Web Ticket Authentication Requests/sec',
        'WEB - Failed Session Web Ticket Authentication Requests',
        'WEB - Failed Session Web Ticket Authentication Requests/sec',
        'WEB - HTTP Proxy Requests', 'WEB - HTTP Proxy Requests/sec',
        'WEB - Failed HTTP Proxy Requests', 'WEB - Failed HTTP Proxy Requests/sec',
        'WEB - Number of proxy requests awaiting completion.',
        'WEB - Deep lookup user Latency (ms)', ' ', 'WEB - Failed Deep Lookup Requests',
        'WEB - HTTP Proxy Server Request Latency (ms)', ''
    ],
    [
        '_Total', '0', '1', '0', '1', '0', '0', '0', '0', '0', '8', '8', '0', '0',
        '245', '245', '0', '0', '0', '0', '0', '0', '2', '2', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '9242', '9242', '43', '43', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '16167', '16167', '0', '0', '0', '0',
        '0', '0', '0', '0', '6106', '6106', '0', '0', '7', '7', '0', '0', '22', '22',
        '0', '0', '0', '0', '11868', '0', '0', '0'
    ],
    [
        'LM_W3SVC_34578_ROOT_Ucwa', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '5693', '5693', '43', '43', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '11511', '11511', '0', '0',
        '0', '0', '0', '0', '0', '0', '5802', '5802', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '11452', '0', '0', '0'
    ],
    [
        'LM_W3SVC_34577_ROOT_Reach', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '1', '1', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        'LM_W3SVC_34578_ROOT_Reach', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '1', '1', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        'LM_W3SVC_34577_ROOT_LocationInformation', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '264', '264', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '378', '378',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        'LM_W3SVC_34577_ROOT_RgsClients', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '187', '187', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '306', '306', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        'LM_W3SVC_34577_ROOT_Autodiscover', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '12', '12', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '62', '62', '0', '0', '0',
        '0', '0', '0', '0', '0', '13', '13', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '25', '0', '0', '0'
    ],
    [
        'LM_W3SVC_34577_ROOT_meet', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '4', '4', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        'LM_W3SVC_34577_ROOT_DataCollabWeb_wopi', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '7', '7', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '7', '7', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        'LM_W3SVC_34577_ROOT_RequestHandler', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '1', '1', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        'LM_W3SVC_34578_ROOT_Autodiscover', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '47', '47', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '226', '226', '0', '0',
        '0', '0', '0', '0', '0', '0', '63', '63', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '110', '0', '0', '0'
    ],
    [
        'LM_W3SVC_34578_ROOT_RgsClients', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '7', '7', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '11', '11', '0', '0', '0',
        '0', '0', '0', '0', '0', '5', '5', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '10', '0', '0', '0'
    ],
    [
        'LM_W3SVC_34578_ROOT_meet', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '27', '27', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '6', '6', '0',
        '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        'LM_W3SVC_34578_ROOT_lwa', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '55', '55', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '16', '16', '0',
        '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        'LM_W3SVC_34578_ROOT_GroupExpansion', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '208', '208', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '210', '210', '0',
        '0', '0', '0', '0', '0', '0', '0', '110', '110', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '220', '0', '0', '0'
    ],
    [
        'LM_W3SVC_34578_ROOT_WebTicket', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '5', '5', '0', '0', '101', '101', '0', '0', '0', '0', '0', '0', '2', '2',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '210', '210', '0',
        '0', '0', '0', '0', '0', '0', '0', '102', '102', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '51', '0', '0', '0'
    ],
    [
        'LM_W3SVC_34577_ROOT_WebTicket', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '3', '3', '0', '0', '144', '144', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '276', '276', '0',
        '0', '0', '0', '0', '0', '0', '0', '11', '11', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        'LM_W3SVC_34577_ROOT_CertProv', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '3', '3', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '6', '6', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        'LM_W3SVC_34577_ROOT_GroupExpansion', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '2683', '2683', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '2707', '2707', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        'LM_W3SVC_34577_ROOT_Abs_Handler', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '138', '138', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '168', '168', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ], ['[LS:SIP - Protocol]'],
    [
        'instance', 'SIP - Incoming Messages', 'SIP - Incoming Messages /Sec',
        'SIP - Incoming Dialog Creating Requests', 'SIP - Incoming Dialog Creating Requests /Sec',
        'SIP - Incoming Requests Dropped', 'SIP - Incoming Requests Dropped /Sec',
        'SIP - Incoming Responses Dropped', 'SIP - Incoming Responses Dropped /Sec',
        'SIP - REGISTER Requests that Failed or Timed Out',
        'SIP - REGISTER Requests that Failed or Timed Out /Sec', 'SIP - Messages In Server',
        'SIP - Compressed Server Connections', 'SIP - Compressed Client Connections',
        'SIP - Incoming Requests In Server', 'SIP - Incoming Responses In Server',
        'SIP - Local Requests In Server', 'SIP - Local Responses In Server',
        'SIP - Outgoing Messages', 'SIP - Outgoing Messages /Sec',
        'SIP - Average Incoming Message Processing Time', ' ',
        'SIP - Average Local Message Processing Time', ' ', 'SIP - Events In Processing',
        'SIP - Events Processed /Sec', 'SIP - Events Queued In State Machine',
        'SIP - Average Event Processing Time', ' ',
        'SIP - Average Number Of Active Worker Threads', 'SIP - UAS Transactions Outstanding',
        'SIP - UAS Transactions Timed Out', 'SIP - UAS Transactions Timed Out /Sec',
        'SIP - UAC Transactions Outstanding', 'SIP - UAC Transactions Timed Out',
        'SIP - UAC Transactions Timed Out /Sec', 'SIP - Proxy Transactions Outstanding',
        'SIP - Proxy Transactions Timed Out', 'SIP - Proxy Transactions Timed Out /Sec'
    ],
    [
        '""', '2512273', '2512311', '1475877', '1475902', '813', '813', '502', '502',
        '2203', '2203', '0', '17', '53', '0', '0', '0', '0', '2842314', '2842320',
        '229005714', '2534318', '223039244', '1331487', '0', '7849715', '0', '1315518577',
        '7845726', '1603540', '0', '230', '230', '0', '101', '101', '0', '1028', '1028'
    ], ['[LS:SIP - Responses]'],
    [
        'instance', 'SIP - Incoming 1xx (non-100) Responses',
        'SIP - Incoming 1xx (non-100) Responses /Sec', 'SIP - Incoming 2xx Responses',
        'SIP - Incoming 2xx Responses /Sec', 'SIP - Incoming 3xx Responses',
        'SIP - Incoming 3xx Responses /Sec', 'SIP - Incoming 400 Responses',
        'SIP - Incoming 400 Responses /Sec', 'SIP - Incoming 401 Responses',
        'SIP - Incoming 401 Responses /Sec', 'SIP - Incoming 403 Responses',
        'SIP - Incoming 403 Responses /Sec', 'SIP - Incoming 404 Responses',
        'SIP - Incoming 404 Responses /Sec', 'SIP - Incoming 407 Responses',
        'SIP - Incoming 407 Responses /Sec', 'SIP - Incoming 408 Responses',
        'SIP - Incoming 408 Responses /Sec', 'SIP - Incoming 482 Responses',
        'SIP - Incoming 482 Responses /Sec', 'SIP - Incoming 483 Responses',
        'SIP - Incoming 483 Responses /Sec', 'SIP - Incoming Other 4xx Responses',
        'SIP - Incoming Other 4xx Responses /Sec', 'SIP - Incoming 503 Responses',
        'SIP - Incoming 503 Responses /Sec', 'SIP - Incoming 504 Responses',
        'SIP - Incoming 504 Responses /Sec', 'SIP - Incoming Other 5xx Responses',
        'SIP - Incoming Other 5xx Responses /Sec', 'SIP - Incoming 6xx Responses',
        'SIP - Incoming 6xx Responses /Sec', 'SIP - Local 1xx Responses',
        'SIP - Local 1xx Responses /Sec', 'SIP - Local 2xx Responses',
        'SIP - Local 2xx Responses /Sec', 'SIP - Local 3xx Responses',
        'SIP - Local 3xx Responses /Sec', 'SIP - Local 400 Responses',
        'SIP - Local 400 Responses /Sec', 'SIP - Local 400 Responses Ratio',
        'SIP - Local 403 Responses', 'SIP - Local 403 Responses /Sec',
        'SIP - Local 403 Responses Ratio', 'SIP - Local 404 Responses',
        'SIP - Local 404 Responses /Sec', 'SIP - Local 404 Responses Ratio',
        'SIP - Local 408 Responses', 'SIP - Local 408 Responses /Sec',
        'SIP - Local 408 Responses Ratio', 'SIP - Local 482 Responses',
        'SIP - Local 482 Responses /Sec', 'SIP - Local 482 Responses Ratio',
        'SIP - Local 483 Responses', 'SIP - Local 483 Responses /Sec',
        'SIP - Local 483 Responses Ratio', 'SIP - Local Other 4xx Responses',
        'SIP - Local 4xx Responses /Sec', 'SIP - Local Other 4xx Responses Ratio',
        'SIP - Local 500 Responses', 'SIP - Local 500 Responses /Sec',
        'SIP - Local 500 Responses Ratio', 'SIP - Local 503 Responses',
        'SIP - Local 503 Responses /Sec', 'SIP - Local 503 Responses Ratio',
        'SIP - Local 504 Responses', 'SIP - Local 504 Responses /Sec',
        'SIP - Local 504 Responses Ratio', 'SIP - Local Other 5xx Responses',
        'SIP - Local 5xx Responses /Sec', 'SIP - Local Other 5xx Responses Ratio',
        'SIP - Local 6xx Responses', 'SIP - Local 6xx Responses /Sec',
        'SIP - Local 6xx Responses Ratio'
    ],
    [
        '""', '3209', '3209', '696923', '696923', '94', '94', '4575', '4575', '0', '0',
        '31142', '31142', '276268', '276268', '0', '0', '21', '21', '0', '0', '0', '0',
        '6263', '6263', '0', '0', '7533', '7533', '21', '21', '17', '17', '16203',
        '16203', '430709', '430715', '0', '0', '140', '140', '0', '217', '217', '0',
        '2141', '2141', '0', '2', '2', '0', '0', '0', '0', '0', '0', '0', '46375',
        '46375', '0', '0', '0', '0', '6', '6', '0', '437', '437', '0', '0', '0', '0',
        '0', '0', '0'
    ], ['[LS:SIP - Peers]'],
    [
        'instance', 'SIP - Connections Active', 'SIP - Inactive Connections Dropped',
        'SIP - Revoked Connections Dropped',
        'SIP - Above Limit Connections Dropped (Access Edge Server only)',
        'SIP - Outgoing Connects Failed', 'SIP - Outgoing TLS Negotiations Failed',
        'SIP - Sends Outstanding', 'SIP - Sends Timed-Out', 'SIP - Sends Timed-Out /Sec',
        'SIP - Average Outgoing Queue Delay', ' ',
        'SIP - Average Number Of Messages In Processing', 'SIP - Flow-controlled Connections',
        'SIP - Flow-controlled Connections Dropped', 'SIP - Average Flow-Control Delay', ' ',
        'SIP - Incoming Requests', 'SIP - Incoming Requests /Sec', 'SIP - Incoming Responses',
        'SIP - Incoming Responses /Sec', 'SIP - Outgoing Requests',
        'SIP - Outgoing Requests /Sec', 'SIP - Outgoing Responses',
        'SIP - Outgoing Responses /Sec',
        'SIP - Requests Rejected Due To User Limits Exceeded (Access Edge Server only)',
        'SIP - Messages To Federated Partners Throttled Due to Frequent Connectivity Failures',
        'SIP - Messages To Federated Partners Throttled Due to Frequent Connectivity Failures /Sec'
    ],
    [
        '_Total', '95', '29186', '0', '0', '237', '0', '0', '0', '0', '4103288425',
        '10344', '102449654', '0', '0', '0', '0', '1475950', '1475151', '1036352',
        '1036352', '1356931', '1356935', '1484234', '1484249', '0', '0', '0'
    ],
    [
        'Clients', '29', '61', '0', '0', '237', '0', '0', '0', '0', '3719588120',
        '3419', '66025479', '0', '0', '0', '0', '747275', '747273', '445107', '445107',
        '744094', '744098', '724529', '724529', '0', '0', '0'
    ],
    [
        'pbwvw-skype03', '18', '2432', '0', '0', '0', '0', '0', '0', '0', '83298406',
        '1937', '25567524', '0', '0', '0', '0', '333085', '332315', '110994', '110994',
        '114096', '114096', '333930', '333943', '0', '0', '0'
    ],
    [
        'edge', '14', '1514', '0', '0', '0', '0', '0', '0', '0', '175675572', '2983',
        '4440807', '0', '0', '0', '0', '65210', '65210', '379519', '379519', '379900',
        '379900', '65862', '65862', '0', '0', '0'
    ],
    [
        'pbwvw-skype01', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        'pbwvw-skype02', '0', '1', '0', '0', '0', '0', '0', '0', '0', '0', '3', '2381',
        '0', '0', '0', '0', '69', '69', '0', '0', '0', '0', '71', '71', '0', '0', '0'
    ],
    [
        'pbwvw-stapp01', '6', '2106', '0', '0', '0', '0', '0', '0', '0', '28281202',
        '461', '2759567', '0', '0', '0', '0', '21885', '21859', '1124', '1124', '3804',
        '3804', '22077', '22078', '0', '0', '0'
    ],
    [
        '0.0.0.0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        'pbwvw-skype04', '9', '1023', '0', '0', '0', '0', '0', '0', '0', '45999760',
        '905', '353869', '0', '0', '0', '0', '253916', '253915', '97641', '97641',
        '97624', '97624', '253840', '253841', '0', '0', '0'
    ],
    [
        'outlook', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '50025',
        '0', '0', '0', '0', '818', '818', '0', '0', '0', '0', '818', '818', '0', '0',
        '0'
    ],
    [
        'pbwvw-stapp02', '4', '12', '0', '0', '0', '0', '0', '0', '0', '43492372',
        '570', '2455625', '0', '0', '0', '0', '24186', '24186', '1500', '1500', '16970',
        '16970', '24186', '24186', '0', '0', '0'
    ],
    [
        'pbwvw-exchg02', '2', '3662', '0', '0', '0', '0', '0', '0', '0', '3327524',
        '32', '374704', '0', '0', '0', '0', '5048', '5048', '262', '262', '244', '244',
        '10079', '10079', '0', '0', '0'
    ],
    [
        'pbwvw-exchg01', '2', '3643', '0', '0', '0', '0', '0', '0', '0', '371775', '4',
        '101531', '0', '0', '0', '0', '4924', '4924', '24', '24', '24', '24', '9832',
        '9832', '0', '0', '0'
    ],
    [
        'pbwaw-exchg02', '3', '3550', '0', '0', '0', '0', '0', '0', '0', '703999', '6',
        '56435', '0', '0', '0', '0', '4876', '4876', '28', '28', '28', '28', '9740',
        '9740', '0', '0', '0'
    ],
    [
        'pbwbw-exchg01', '3', '3742', '0', '0', '0', '0', '0', '0', '0', '986128', '10',
        '36080', '0', '0', '0', '0', '4888', '4888', '79', '79', '74', '74', '9754',
        '9754', '0', '0', '0'
    ],
    [
        'pbwbw-exchg02', '2', '3618', '0', '0', '0', '0', '0', '0', '0', '1030952', '8',
        '154928', '0', '0', '0', '0', '4895', '4895', '48', '48', '47', '47', '9778',
        '9778', '0', '0', '0'
    ],
    [
        'pbwaw-exchg01', '3', '3822', '0', '0', '0', '0', '0', '0', '0', '532615', '6',
        '70699', '0', '0', '0', '0', '4875', '4875', '26', '26', '26', '26', '9738',
        '9738', '0', '0', '0'
    ], ['[LS:SIP - Load Management]'],
    [
        'instance', 'SIP - Average Holding Time For Incoming Messages', ' ',
        'SIP - Incoming Messages Held', 'SIP - Incoming Messages Held Above Low Watermark',
        'SIP - Incoming Messages Held Above High Watermark',
        'SIP - Incoming Messages Held Above Overload Watermark',
        'SIP - Incoming Messages Timed out', 'SIP - Low Watermark', 'SIP - High Watermark',
        'SIP - Address space usage', 'SIP - Page file usage'
    ],
    ['""', '1510747184', '2960375', '0', '0', '0', '0', '0', '250', '500', '0', '41'],
    ['[LS:DATAMCU - MCU Health And Performance]'],
    [
        'instance', 'DATAMCU - HTTP Stack load', 'DATAMCU - HTTP Stack state',
        'DATAMCU - Thread Pool Load', 'DATAMCU - Thread Pool Health State',
        'DATAMCU - Thread Pool Unhandled Exceptions', 'DATAMCU - MCU Health State',
        'DATAMCU - MCU Draining State', 'DATAMCU - MCU Health State Changed Count',
        'DATAMCU - MCU Health DNS resolution failure Count',
        'DATAMCU - MCU Health DNS resolution succeeded Count'
    ], ['""', '0', '0', '0', '0', '0', '0', '0', '0', '0', '2587'],
    ['[LS:AVMCU - MCU Health And Performance]'],
    [
        'instance', 'AVMCU - HTTP Stack load', 'AVMCU - HTTP Stack state',
        'AVMCU - Thread Pool Load', 'AVMCU - Thread Pool Health State',
        'AVMCU - Thread Pool Unhandled Exceptions', 'AVMCU - MCU Health State',
        'AVMCU - MCU Draining State', 'AVMCU - MCU Health State Changed Count',
        'AVMCU - MCU Health DNS resolution failure Count',
        'AVMCU - MCU Health DNS resolution succeeded Count'
    ], ['""', '0', '0', '0', '0', '0', '0', '0', '0', '0', '2587'],
    ['[LS:AsMcu - MCU Health And Performance]'],
    [
        'instance', 'ASMCU - HTTP Stack load', 'ASMCU - HTTP Stack state',
        'ASMCU - Thread Pool Load', 'ASMCU - Thread Pool Health State',
        'ASMCU - Thread Pool Unhandled Exceptions', 'ASMCU - MCU Health State',
        'ASMCU - MCU Draining State', 'ASMCU - MCU Health State Changed Count',
        'ASMCU - MCU Health DNS resolution failure Count',
        'ASMCU - MCU Health DNS resolution succeeded Count'
    ], ['""', '0', '0', '0', '0', '0', '0', '0', '0', '0', '2587'],
    ['[LS:ImMcu - MCU Health And Performance]'],
    [
        'instance', 'IMMCU - HTTP Stack load', 'IMMCU - HTTP Stack state',
        'IMMCU - Thread Pool Load', 'IMMCU - Thread Pool Health State',
        'IMMCU - Thread Pool Unhandled Exceptions', 'IMMCU - MCU Health State',
        'IMMCU - MCU Draining State', 'IMMCU - MCU Health State Changed Count',
        'IMMCU - MCU Health DNS resolution failure Count',
        'IMMCU - MCU Health DNS resolution succeeded Count'
    ], ['""', '0', '0', '0', '0', '0', '0', '0', '0', '0', '2587'],
    ['[LS:USrv - DBStore]'],
    [
        'instance', 'USrv - Queue Depth', ' ', 'USrv - Queue Latency (msec)', ' ',
        'USrv - Sproc Latency (msec)', ' ', 'USrv - % Database Time', ' ',
        'USrv - Threads Waiting for New Database Requests',
        'USrv - Threads Executing Database Operations',
        'USrv - Threads Calling Back with Database Results', 'USrv - Blocked Client Threads',
        ' ', 'USrv - Total Deadlocks', 'USrv - Total Dropped Requests',
        'USrv - Total Deadlock Failures', 'USrv - Total Transaction Count Mismatch Failures',
        'USrv - Total ODBC Timeout Failures', 'USrv - Total severe SQL errors',
        'USrv - Total fatal SQL errors', 'USrv - Throttled requests/sec',
        'USrv - Total throttled requests', 'USrv - Database connection status',
        'USrv - Sproc Calls/sec', 'USrv - Total sproc calls', 'USrv - Database failover count'
    ],
    [
        '""', '524', '1132983', '238138', '1135722', '4967352', '1135722', '3081699',
        '31859', '10', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '1', '1103251', '1103251', '0'
    ], ['[LS:MediationServer - Health Indices]'], ['instance', '- Load Call Failure Index'],
    ['""', '0'], ['[LS:MediationServer - Global Counters]'],
    [
        'instance', '- Current audio channels with PSM quality reporting',
        '- Total failed calls caused by unexpected interaction from the Proxy',
        '- Current number of ports opened on the gateway side',
        '- Total number of timer timeouts that are exceeding the predefined threshold'
    ], ['""', '1', '5', '1', '0'], ['[LS:MediationServer - Global Per Gateway Counters]'],
    ['instance', '- Total failed calls caused by unexpected interaction from a gateway'],
    ['_Total', '0'], ['pbwva-vgate01.intern.rossmann.de', '0'],
    ['pbwva-vgate01.intern.rossmann.de;trunk=pbwva-vgate01.intern.rossmann.de', '0'],
    ['[LS:MediationServer - Media Relay]'],
    ['instance', '- Candidates Missing', '- Media Connectivity Check Failure'],
    ['""', '0', '0'], ['[LS:A/V Auth - Requests]'],
    [
        'instance', '- Credentials Issued', '- Credentials Issued/sec',
        '- Bad Requests Received', '- Bad Requests Received/sec', '- Current requests serviced'
    ], ['""', '0', '0', '0', '0', '0'], ['[ASP.NET Apps v4.0.30319]'],
    [
        'instance', 'Anonymous Requests', 'Anonymous Requests/Sec', 'Cache Total Entries',
        'Cache Total Turnover Rate', 'Cache Total Hits', 'Cache Total Misses',
        'Cache Total Hit Ratio', 'Cache Total Hit Ratio Base', 'Cache API Entries',
        'Cache API Turnover Rate', 'Cache API Hits', 'Cache API Misses', 'Cache API Hit Ratio',
        'Cache API Hit Ratio Base', 'Output Cache Entries', 'Output Cache Turnover Rate',
        'Output Cache Hits', 'Output Cache Misses', 'Output Cache Hit Ratio',
        'Output Cache Hit Ratio Base', 'Compilations Total', 'Debugging Requests',
        'Errors During Preprocessing', 'Errors During Compilation', 'Errors During Execution',
        'Errors Unhandled During Execution', 'Errors Unhandled During Execution/Sec',
        'Errors Total', 'Errors Total/Sec', 'Pipeline Instance Count', 'Request Bytes In Total',
        'Request Bytes Out Total', 'Requests Executing', 'Requests Failed',
        'Requests Not Found', 'Requests Not Authorized', 'Requests In Application Queue',
        'Requests Timed Out', 'Requests Succeeded', 'Requests Total', 'Requests/Sec',
        'Sessions Active', 'Sessions Abandoned', 'Sessions Timed Out', 'Sessions Total',
        'Transactions Aborted', 'Transactions Committed', 'Transactions Pending',
        'Transactions Total', 'Transactions/Sec', 'Session State Server connections total',
        'Session SQL Server connections total', 'Events Raised', 'Events Raised/Sec',
        'Application Lifetime Events', 'Application Lifetime Events/Sec', 'Error Events Raised',
        'Error Events Raised/Sec', 'Request Error Events Raised',
        'Request Error Events Raised/Sec', 'Infrastructure Error Events Raised',
        'Infrastructure Error Events Raised/Sec', 'Request Events Raised',
        'Request Events Raised/Sec', 'Audit Success Events Raised',
        'Audit Failure Events Raised', 'Membership Authentication Success',
        'Membership Authentication Failure', 'Forms Authentication Success',
        'Forms Authentication Failure', 'Viewstate MAC Validation Failure',
        'Request Execution Time', 'Requests Disconnected', 'Requests Rejected',
        'Request Wait Time', 'Cache % Machine Memory Limit Used',
        'Cache % Machine Memory Limit Used Base', 'Cache % Process Memory Limit Used',
        'Cache % Process Memory Limit Used Base', 'Cache Total Trims', 'Cache API Trims',
        'Output Cache Trims', '% Managed Processor Time (estimated)',
        '% Managed Processor Time Base (estimated)', 'Managed Memory Used (estimated)',
        'Request Bytes In Total (WebSockets)', 'Request Bytes Out Total (WebSockets)',
        'Requests Executing (WebSockets)', 'Requests Failed (WebSockets)',
        'Requests Succeeded (WebSockets)', 'Requests Total (WebSockets)'
    ],
    [
        '__Total__', '4020', '4020', '223', '177475', '246152', '89212', '246152',
        '335364', '8', '12', '637', '19', '637', '656', '0', '0', '0', '0', '0', '0',
        '104', '0', '0', '0', '0', '0', '0', '0', '0', '49', '22591387', '59046000',
        '1', '17774', '2629', '12645', '0', '0', '11384', '29159', '29159', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '16591', '16591', '232', '232',
        '0', '0', '0', '0', '0', '0', '0', '0', '16359', '0', '0', '0', '0', '0',
        '0', '586100', '0', '0', '0', '875', '2475', '22933', '503303275', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        '_LM_W3SVC_34577_ROOT_LocationInformation', '378', '378', '8', '1008', '778', '519',
        '778', '1297', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '1', '1062329', '2619756', '0',
        '0', '0', '0', '0', '0', '378', '378', '378', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '542', '542', '1', '1', '0', '0', '0', '0', '0',
        '0', '0', '0', '541', '0', '0', '0', '0', '0', '0', '8', '0', '0', '0', '35',
        '99', '0', '20132131', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0'
    ],
    [
        '_LM_W3SVC_34578_ROOT_Autodiscover', '59', '59', '10', '788', '921', '409', '921',
        '1330', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '1', '0', '299231', '0', '57', '0', '57',
        '0', '0', '169', '226', '226', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '229', '229', '1', '1', '0', '0', '0', '0', '0', '0', '0', '0',
        '228', '0', '0', '0', '0', '0', '0', '3', '0', '0', '0', '35', '99', '1033',
        '20132131', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        '_LM_W3SVC_34578_ROOT_lwa', '4', '4', '7', '379', '350', '207', '350', '557', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '1', '0', '5712217', '0', '2', '2', '0', '0', '0',
        '53', '55', '55', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '5',
        '5', '1', '1', '0', '0', '0', '0', '0', '0', '0', '0', '4', '0', '0', '0',
        '0', '0', '0', '1', '0', '0', '0', '35', '99', '919', '20132131', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        '_LM_W3SVC_34577_ROOT_Reach', '0', '0', '8', '60', '147', '56', '147', '203', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '1', '0', '0', '0',
        '0', '0', '0', '0', '0', '1', '0', '0', '0', '1', '0', '1', '0', '0', '0',
        '1', '1', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '3', '3',
        '3', '3', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '174', '0', '0', '0', '35', '99', '983', '20132131', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        '_LM_W3SVC_34577_ROOT_cscp', '0', '0', '14', '198', '1510', '129', '1510', '1639',
        '8', '12', '637', '19', '637', '656', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '1', '41663', '99355', '0', '10', '1', '9',
        '0', '0', '284', '294', '294', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '1', '1', '1', '1', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '35', '99', '0', '20132131',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        '_LM_W3SVC_34577_ROOT_Autodiscover', '24', '24', '10', '336', '353', '183', '353',
        '536', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '2', '0', '95742', '0', '13', '0', '13',
        '0', '0', '49', '62', '62', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '74', '74', '1', '1', '0', '0', '0', '0', '0', '0', '0', '0', '73', '0',
        '0', '0', '0', '0', '0', '2', '0', '0', '0', '35', '99', '0', '20132131', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        '_LM_W3SVC_34577_ROOT_RequestHandler', '1', '1', '4', '28', '69', '26', '69', '95',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '1', '549', '115', '0', '0', '0', '0', '0',
        '0', '1', '1', '1', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '3', '3', '1', '1', '0', '0', '0', '0', '0', '0', '0', '0', '2', '0', '0',
        '0', '0', '0', '0', '161', '0', '0', '0', '35', '99', '0', '20132131', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        '_LM_W3SVC_34578_ROOT_Abs', '0', '0', '4', '22', '12538', '23', '12538', '12561',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '2', '0', '0', '0', '12462', '0', '12462', '0',
        '0', '0', '12462', '12462', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '1', '1', '1', '1', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '35', '99', '0', '20132131', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        '_LM_W3SVC_34578_ROOT_GroupExpansion', '100', '100', '5', '181', '473', '104',
        '473', '577', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '1', '980445', '671267', '0',
        '0', '0', '0', '0', '0', '210', '210', '210', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '233', '233', '1', '1', '0', '0', '0', '0', '0',
        '0', '0', '0', '232', '0', '0', '0', '0', '0', '0', '8', '0', '0', '0', '35',
        '99', '0', '20132131', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0'
    ],
    [
        '_LM_W3SVC_34577_ROOT_Abs', '0', '0', '40', '602', '488', '331', '488', '819',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '2', '0', '0', '0', '0', '0', '0', '0', '0',
        '138', '138', '138', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '1', '1', '1', '1', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '35', '99', '1052', '20132131', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        '_LM_W3SVC_34577_ROOT', '0', '0', '3', '211', '200', '117', '200', '317', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '1', '0', '0', '0', '0', '0', '0', '0', '0', '32',
        '32', '32', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '1', '1',
        '1', '1', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '35', '99', '0', '20132131', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        '_LM_W3SVC_34578_ROOT_Ucwa', '0', '0', '4', '170444', '220886', '85285', '220886',
        '306171', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '2', '4992207', '27042896', '1',
        '5185', '2626', '59', '0', '0', '6325', '11511', '11511', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '11452', '11452', '1', '1', '0', '0', '0',
        '0', '0', '0', '0', '0', '11451', '0', '0', '0', '0', '0', '0', '585289', '0',
        '0', '0', '35', '99', '10035', '20132131', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0'
    ],
    [
        '_LM_W3SVC_34578_ROOT_Reach', '0', '0', '8', '60', '147', '56', '147', '203', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '1', '0', '0', '0',
        '0', '0', '0', '0', '0', '1', '0', '0', '0', '1', '0', '1', '0', '0', '0',
        '1', '1', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '3', '3',
        '3', '3', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '163', '0', '0', '0', '35', '99', '981', '20132131', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        '_LM_W3SVC_34577_ROOT_WebTicket', '270', '270', '5', '717', '590', '372', '590',
        '962', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '1', '801128', '3286709', '0', '3', '0',
        '3', '0', '0', '273', '276', '276', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '381', '381', '1', '1', '0', '0', '0', '0', '0', '0', '0',
        '0', '380', '0', '0', '0', '0', '0', '0', '25', '0', '0', '0', '35', '99',
        '0', '20132131', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        '_LM_W3SVC_34577_ROOT_GroupExpansion', '2707', '2707', '6', '122', '3381', '75',
        '3381', '3456', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '9', '13354163', '14215371', '0',
        '0', '0', '0', '0', '0', '2707', '2707', '2707', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '2723', '2723', '1', '1', '0', '0', '0', '0', '0',
        '0', '0', '0', '2722', '0', '0', '0', '0', '0', '0', '5', '0', '0', '0',
        '35', '99', '3706', '20132131', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0'
    ],
    [
        '_LM_W3SVC_34577_ROOT_Ucwa', '0', '0', '4', '24', '49', '24', '49', '73', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '35', '99', '447', '20132131', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        '_LM_W3SVC_34577_ROOT_DataCollabWeb_wopi', '0', '0', '5', '37', '92', '31', '92',
        '123', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '1', '0', '484259', '0', '0', '0', '0',
        '0', '0', '7', '7', '7', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '8', '8', '1', '1', '0', '0', '0', '0', '0', '0', '0', '0', '7', '0',
        '0', '0', '0', '0', '0', '2', '0', '0', '0', '35', '99', '0', '20132131', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        '_LM_W3SVC_34578_ROOT', '0', '0', '3', '31', '125', '27', '125', '152', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '1', '0', '0', '0', '0', '0', '0', '0', '0', '61', '61',
        '61', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '1', '1', '1',
        '1', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '35', '99', '1038', '20132131', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        '_LM_W3SVC_34578_ROOT_meet', '5', '5', '7', '285', '586', '162', '586', '748',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '51', '0', '0',
        '0', '0', '0', '0', '0', '0', '1', '0', '172965', '0', '0', '0', '0', '0',
        '0', '27', '27', '27', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '108', '108', '103', '103', '0', '0', '0', '0', '0', '0', '0', '0', '5', '0',
        '0', '0', '0', '0', '0', '2', '0', '0', '0', '35', '99', '1853', '20132131',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        '_LM_W3SVC_34577_ROOT_RgsClients', '306', '306', '10', '770', '662', '402', '662',
        '1064', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '1', '752085', '2607922', '0', '0', '0',
        '0', '0', '0', '306', '306', '306', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '429', '429', '1', '1', '0', '0', '0', '0', '0', '0', '0',
        '0', '428', '0', '0', '0', '0', '0', '0', '20', '0', '0', '0', '35', '99',
        '0', '20132131', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        '_LM_W3SVC_34577_ROOT_meet', '4', '4', '6', '170', '470', '103', '470', '573',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '51', '0', '0',
        '0', '0', '0', '0', '0', '0', '1', '0', '3846', '0', '0', '0', '0', '0', '0',
        '4', '4', '4', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '107',
        '107', '103', '103', '0', '0', '0', '0', '0', '0', '0', '0', '4', '0', '0',
        '0', '0', '0', '0', '65', '0', '0', '0', '35', '99', '0', '20132131', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        '_LM_W3SVC_34577_ROOT_Abs_Handler', '0', '0', '35', '311', '597', '183', '597',
        '780', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '14', '0', '0', '0', '30', '0', '30', '0',
        '0', '138', '168', '168', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '1', '1', '1', '1', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '30', '0', '0', '0', '35', '99', '0', '20132131',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        '_LM_W3SVC_34578_ROOT_RgsClients', '6', '6', '7', '79', '137', '55', '137', '192',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '1', '27726', '87838', '0', '0', '0', '0', '0',
        '0', '11', '11', '11', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '17', '17', '1', '1', '0', '0', '0', '0', '0', '0', '0', '0', '16', '0', '0',
        '0', '0', '0', '0', '25', '0', '0', '0', '35', '99', '886', '20132131', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        '_LM_W3SVC_34577_ROOT_CertProv', '6', '6', '5', '49', '89', '38', '89', '127',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '1', '21702', '118505', '0', '0', '0', '0', '0',
        '0', '6', '6', '6', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '10', '10', '1', '1', '0', '0', '0', '0', '0', '0', '0', '0', '9', '0', '0',
        '0', '0', '0', '0', '106', '0', '0', '0', '35', '99', '0', '20132131', '0',
        '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ],
    [
        '_LM_W3SVC_34578_ROOT_WebTicket', '150', '150', '5', '563', '514', '295', '514',
        '809', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '0', '0', '0', '0', '1', '557390', '1528006', '0', '10', '0',
        '10', '0', '0', '205', '215', '215', '0', '0', '0', '0', '0', '0', '0', '0',
        '0', '0', '0', '258', '258', '1', '1', '0', '0', '0', '0', '0', '0', '0',
        '0', '257', '0', '0', '0', '0', '0', '0', '11', '0', '0', '0', '35', '99',
        '0', '20132131', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
    ]
]

discovery = {
    '': [(None, None)],
    'conferencing': [],
    'data_proxy': [],
    'edge': [],
    'edge_auth': [(None, None)],
    'mcu': [(None, None)],
    'mediation_server': [(None, None)],
    'mobile': [(None, None)],
    'sip_stack': [(None, None)],
    'xmpp_proxy': []
}

checks = {
    '': [(None, {
        'failed_locations_requests': {
            'upper': (1.0, 2.0)
        },
        'failed_file_requests': {
            'upper': (1.0, 2.0)
        },
        'join_failures': {
            'upper': (1, 2)
        },
        'asp_requests_rejected': {
            'upper': (1, 2)
        },
        'failed_validate_cert': {
            'upper': (1, 2)
        },
        'failed_search_requests': {
            'upper': (1.0, 2.0)
        },
        '5xx_responses': {
            'upper': (1.0, 2.0)
        },
        'timedout_ad_requests': {
            'upper': (0.01, 0.02)
        }
    }, [(0, 'Failed search requests/sec: 0.00', [('failed_search_requests', 0.0, 1.0, 2.0, None,
                                                 None)]),
        (0, 'Failed location requests/sec: 0.00', [('failed_location_requests', 0.0, 1.0, 2.0, None,
                                                   None)]),
        (0, 'Timeout AD requests/sec: 0.00', [('failed_ad_requests', 0.0, 0.01, 0.02, None, None)]),
        (0, 'HTTP 5xx/sec: 0.00', [('http_5xx', 0.0, 1.0, 2.0, None, None)]),
        (0, 'Requests rejected: 0', [('asp_requests_rejected', 0.0, 1, 2, None, None)])])],
    'edge_auth': [(None, {
        'bad_requests': {
            'upper': (20, 40)
        }
    }, [(0, 'Bad requests/sec: 0.00', [('avauth_failed_requests', 0.0, 20, 40, None, None)])])],
    'mcu': [(None, {}, [(0, 'DATAMCU: Normal', []), (0, 'AVMCU: Normal', []),
                        (0, 'ASMCU: Normal', []), (0, 'IMMCU: Normal', [])])],
    'mediation_server': [(None, {
        'failed_calls_because_of_proxy': {
            'upper': (10, 20)
        },
        'load_call_failure_index': {
            'upper': (10, 20)
        },
        'media_connectivity_failure': {
            'upper': (1, 2)
        },
        'failed_calls_because_of_gateway': {
            'upper': (10, 20)
        }
    }, [(0, 'Load call failure index: 0', [('mediation_load_call_failure_index', 0.0, 10, 20, None,
                                           None)]),
        (0, 'Failed calls because of proxy: 5', [('mediation_failed_calls_because_of_proxy', 5.0, 10,
                                                 20, None, None)]),
        (0, 'Failed calls because of gateway: 0', [('mediation_failed_calls_because_of_gateway', 0.0,
                                                   10, 20, None, None)]),
        (0, 'Media connectivity check failure: 0', [('mediation_media_connectivity_failure', 0.0, 1,
                                                    2, None, None)])])],
    'mobile': [(None, {
        'requests_processing': {
            'upper': (10000, 20000)
        }
    }, [(0, 'Android: 0 active', [('ucwa_active_sessions_android', 0.0, None, None, None, None)]),
        (0, 'iPad: 0 active', [('ucwa_active_sessions_ipad', 0.0, None, None, None, None)]),
        (0, 'iPhone: 0 active', [('ucwa_active_sessions_iphone', 0.0, None, None, None, None)]),
        (0, 'Requested: 1', [('web_requests_processing', 1.0, 10000, 20000, None, None)])])],
    'sip_stack': [(None, {
        'authentication_errors': {
            'upper': (1, 2)
        },
        'timedout_incoming_messages': {
            'upper': (2, 4)
        },
        'local_503_responses': {
            'upper': (0.01, 0.02)
        },
        'outgoing_queue_delay': {
            'upper': (2.0, 4.0)
        },
        'incoming_requests_dropped': {
            'upper': (1.0, 2.0)
        },
        'queue_latency': {
            'upper': (0.0001, 0.2)
        },
        'message_processing_time': {
            'upper': (1.0, 2.0)
        },
        'sproc_latency': {
            'upper': (0.1, 0.2)
        },
        'throttled_requests': {
            'upper': (0.2, 0.4)
        },
        'holding_time_incoming': {
            'upper': (6.0, 12.0)
        },
        'incoming_responses_dropped': {
            'upper': (1.0, 2.0)
        },
        'flow_controlled_connections': {
            'upper': (1, 2)
        },
        'timedout_sends': {
            'upper': (0.01, 0.02)
        }
    }, [(0, 'Avg incoming message processing time: 0.00', [('sip_message_processing_time', 0.0, 1.0,
                                                           2.0, None, None)]),
        (0, 'Incoming responses dropped/sec: 0.00', [('sip_incoming_responses_dropped', 0.0, 1.0,
                                                     2.0, None, None)]),
        (0, 'Incoming requests dropped/sec: 0.00', [('sip_incoming_requests_dropped', 0.0, 1.0, 2.0,
                                                    None, None)]),
        (1, 'Queue latency: 210 \xb5s (warn/crit at 100 \xb5s/200 ms)',
         [('usrv_queue_latency', 0.00020967983362125592, 0.0001, 0.2, None, None)]),
        (0, 'Sproc latency: 1.16 \xb5s', [('usrv_sproc_latency', 1.1562460162588214e-06, 0.1, 0.2, None,
                                       None)]),
        (0, 'Throttled requests/sec: 0.00', [('usrv_throttled_requests', 0.0, 0.2, 0.4, None,
                                             None)]),
        (0, 'Local 503 responses/sec: 0.00', [('sip_503_responses', 0.0, 0.01, 0.02, None, None)]),
        (0, 'Incoming messages timed out: 0', [('sip_incoming_messages_timed_out', 0.0, 2, 4, None,
                                               None)]),
        (0, 'Avg holding time for incoming messages: 0.00',
         [('sip_avg_holding_time_incoming_messages', 0.0, 6.0, 12.0, None, None)]),
        (0, 'Flow-controlled connections: 0', [('sip_flow_controlled_connections', 0.0, 1, 2, None,
                                               None)]),
        (0, 'Avg outgoing queue delay: 0.00', [('sip_avg_outgoing_queue_delay', 0.0, 2.0, 4.0, None,
                                               None)]),
        (0, 'Sends timed out/sec: 0.00', [('sip_sends_timed_out', 0.0, 0.01, 0.02, None, None)])])]
}
