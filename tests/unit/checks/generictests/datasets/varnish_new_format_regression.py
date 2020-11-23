#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2019 tribe29 GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

# yapf: disable
# type: ignore

checkname = 'varnish'

info = [['MGT.child_start', '1', '0.00', 'Child', 'process', 'started'],
        ['MGT.child_exit', '0', '0.00', 'Child', 'process', 'normal', 'exit'],
        ['MGT.child_stop', '0', '0.00', 'Child', 'process', 'unexpected', 'exit'],
        ['MGT.child_died', '0', '0.00', 'Child', 'process', 'died', '(signal)'],
        ['MGT.child_dump', '0', '0.00', 'Child', 'process', 'core', 'dumped'],
        ['MGT.child_panic', '0', '0.00', 'Child', 'process', 'panic'],
        ['MAIN.summs', '544816', '1.16', 'stat', 'summ', 'operations'],
        ['MAIN.sess_conn', '247796', '0.53', 'Sessions', 'accepted'],
        ['MAIN.sess_drop', '0', '0.00', 'Sessions', 'dropped'],
        ['MAIN.sess_fail', '0', '0.00', 'Session', 'accept', 'failures'],
        [
            'MAIN.client_req_400', '0', '0.00', 'Client', 'requests', 'received,', 'subject',
            'to', '400', 'errors'
        ],
        [
            'MAIN.client_req_417', '0', '0.00', 'Client', 'requests', 'received,', 'subject',
            'to', '417', 'errors'
        ], ['MAIN.client_req', '283290', '0.60', 'Good', 'client', 'requests', 'received'],
        ['MAIN.cache_hit', '277834', '0.59', 'Cache', 'hits'],
        ['MAIN.cache_hitpass', '0', '0.00', 'Cache', 'hits', 'for', 'pass.'],
        ['MAIN.cache_hitmiss', '0', '0.00', 'Cache', 'hits', 'for', 'miss.'],
        ['MAIN.cache_miss', '3142', '0.01', 'Cache', 'misses'],
        ['MAIN.backend_conn', '1065', '0.00', 'Backend', 'conn.', 'success'],
        ['MAIN.backend_unhealthy', '0', '0.00', 'Backend', 'conn.', 'not', 'attempted'],
        ['MAIN.backend_busy', '0', '0.00', 'Backend', 'conn.', 'too', 'many'],
        ['MAIN.backend_fail', '0', '0.00', 'Backend', 'conn.', 'failures'],
        ['MAIN.backend_reuse', '4405', '0.01', 'Backend', 'conn.', 'reuses'],
        ['MAIN.backend_recycle', '5470', '0.01', 'Backend', 'conn.', 'recycles'],
        ['MAIN.backend_retry', '0', '0.00', 'Backend', 'conn.', 'retry'],
        ['MAIN.fetch_head', '0', '0.00', 'Fetch', 'no', 'body', '(HEAD)'],
        ['MAIN.fetch_length', '5470', '0.01', 'Fetch', 'with', 'Length'],
        ['MAIN.fetch_chunked', '0', '0.00', 'Fetch', 'chunked'],
        ['MAIN.fetch_eof', '0', '0.00', 'Fetch', 'EOF'],
        ['MAIN.fetch_bad', '0', '0.00', 'Fetch', 'bad', 'T-E'],
        ['MAIN.fetch_none', '0', '0.00', 'Fetch', 'no', 'body'],
        ['MAIN.fetch_1xx', '0', '0.00', 'Fetch', 'no', 'body', '(1xx)'],
        ['MAIN.fetch_204', '0', '0.00', 'Fetch', 'no', 'body', '(204)'],
        ['MAIN.fetch_304', '0', '0.00', 'Fetch', 'no', 'body', '(304)'],
        ['MAIN.fetch_failed', '0', '0.00', 'Fetch', 'failed', '(all', 'causes)'],
        ['MAIN.fetch_no_thread', '0', '0.00', 'Fetch', 'failed', '(no', 'thread)'],
        ['MAIN.pools', '2', '.', 'Number', 'of', 'thread', 'pools'],
        ['MAIN.threads', '200', '.', 'Total', 'number', 'of', 'threads'],
        ['MAIN.threads_limited', '0', '0.00', 'Threads', 'hit', 'max'],
        ['MAIN.threads_created', '200', '0.00', 'Threads', 'created'],
        ['MAIN.threads_destroyed', '0', '0.00', 'Threads', 'destroyed'],
        ['MAIN.threads_failed', '0', '0.00', 'Thread', 'creation', 'failed'],
        ['MAIN.thread_queue_len', '0', '.', 'Length', 'of', 'session', 'queue'],
        [
            'MAIN.busy_sleep', '0', '0.00', 'Number', 'of', 'requests', 'sent', 'to',
            'sleep', 'on', 'busy', 'objhdr'
        ],
        [
            'MAIN.busy_wakeup', '0', '0.00', 'Number', 'of', 'requests', 'woken', 'after',
            'sleep', 'on', 'busy', 'objhdr'
        ],
        [
            'MAIN.busy_killed', '0', '0.00', 'Number', 'of', 'requests', 'killed', 'after',
            'sleep', 'on', 'busy', 'objhdr'
        ], ['MAIN.sess_queued', '0', '0.00', 'Sessions', 'queued', 'for', 'thread'],
        ['MAIN.sess_dropped', '0', '0.00', 'Sessions', 'dropped', 'for', 'thread'],
        ['MAIN.req_dropped', '0', '0.00', 'Requests', 'dropped'],
        ['MAIN.n_object', '267', '.', 'object', 'structs', 'made'],
        ['MAIN.n_vampireobject', '0', '.', 'unresurrected', 'objects'],
        ['MAIN.n_objectcore', '285', '.', 'objectcore', 'structs', 'made'],
        ['MAIN.n_objecthead', '285', '.', 'objecthead', 'structs', 'made'],
        ['MAIN.n_backend', '1', '.', 'Number', 'of', 'backends'],
        ['MAIN.n_expired', '2875', '.', 'Number', 'of', 'expired', 'objects'],
        ['MAIN.n_lru_nuked', '0', '.', 'Number', 'of', 'LRU', 'nuked', 'objects'],
        ['MAIN.n_lru_moved', '153105', '.', 'Number', 'of', 'LRU', 'moved', 'objects'],
        ['MAIN.losthdr', '0', '0.00', 'HTTP', 'header', 'overflows'],
        ['MAIN.s_sess', '247796', '0.53', 'Total', 'sessions', 'seen'],
        ['MAIN.s_pipe', '0', '0.00', 'Total', 'pipe', 'sessions', 'seen'],
        ['MAIN.s_pass', '2314', '0.00', 'Total', 'pass-ed', 'requests', 'seen'],
        ['MAIN.s_fetch', '5456', '0.01', 'Total', 'backend', 'fetches', 'initiated'],
        ['MAIN.s_synth', '0', '0.00', 'Total', 'synthethic', 'responses', 'made'],
        ['MAIN.s_req_hdrbytes', '35628567', '75.95', 'Request', 'header', 'bytes'],
        ['MAIN.s_req_bodybytes', '0', '0.00', 'Request', 'body', 'bytes'],
        ['MAIN.s_resp_hdrbytes', '107104795', '228.32', 'Response', 'header', 'bytes'],
        ['MAIN.s_resp_bodybytes', '1011093565', '2155.43', 'Response', 'body', 'bytes'],
        ['MAIN.s_pipe_hdrbytes', '0', '0.00', 'Pipe', 'request', 'header', 'bytes'],
        ['MAIN.s_pipe_in', '0', '0.00', 'Piped', 'bytes', 'from', 'client'],
        ['MAIN.s_pipe_out', '0', '0.00', 'Piped', 'bytes', 'to', 'client'],
        ['MAIN.sess_closed', '239285', '0.51', 'Session', 'Closed'],
        ['MAIN.sess_closed_err', '244950', '0.52', 'Session', 'Closed', 'with', 'error'],
        ['MAIN.sess_readahead', '1', '0.00', 'Session', 'Read', 'Ahead'],
        ['MAIN.sess_herd', '26380', '0.06', 'Session', 'herd'],
        ['MAIN.sc_rem_close', '1273', '0.00', 'Session', 'OK', 'REM_CLOSE'],
        ['MAIN.sc_req_close', '1572', '0.00', 'Session', 'OK', 'REQ_CLOSE'],
        ['MAIN.sc_req_http10', '237713', '0.51', 'Session', 'Err', 'REQ_HTTP10'],
        ['MAIN.sc_rx_bad', '0', '0.00', 'Session', 'Err', 'RX_BAD'],
        ['MAIN.sc_rx_body', '0', '0.00', 'Session', 'Err', 'RX_BODY'],
        ['MAIN.sc_rx_junk', '0', '0.00', 'Session', 'Err', 'RX_JUNK'],
        ['MAIN.sc_rx_overflow', '0', '0.00', 'Session', 'Err', 'RX_OVERFLOW'],
        ['MAIN.sc_rx_timeout', '7237', '0.02', 'Session', 'Err', 'RX_TIMEOUT'],
        ['MAIN.sc_tx_pipe', '0', '0.00', 'Session', 'OK', 'TX_PIPE'],
        ['MAIN.sc_tx_error', '0', '0.00', 'Session', 'Err', 'TX_ERROR'],
        ['MAIN.sc_tx_eof', '0', '0.00', 'Session', 'OK', 'TX_EOF'],
        ['MAIN.sc_resp_close', '0', '0.00', 'Session', 'OK', 'RESP_CLOSE'],
        ['MAIN.sc_overload', '0', '0.00', 'Session', 'Err', 'OVERLOAD'],
        ['MAIN.sc_pipe_overflow', '0', '0.00', 'Session', 'Err', 'PIPE_OVERFLOW'],
        ['MAIN.sc_range_short', '0', '0.00', 'Session', 'Err', 'RANGE_SHORT'],
        ['MAIN.sc_req_http20', '0', '0.00', 'Session', 'Err', 'REQ_HTTP20'],
        ['MAIN.sc_vcl_failure', '0', '0.00', 'Session', 'Err', 'VCL_FAILURE'],
        ['MAIN.shm_records', '12598501', '26.86', 'SHM', 'records'],
        ['MAIN.shm_writes', '1881802', '4.01', 'SHM', 'writes'],
        ['MAIN.shm_flushes', '0', '0.00', 'SHM', 'flushes', 'due', 'to', 'overflow'],
        ['MAIN.shm_cont', '281', '0.00', 'SHM', 'MTX', 'contention'],
        ['MAIN.shm_cycles', '4', '0.00', 'SHM', 'cycles', 'through', 'buffer'],
        ['MAIN.backend_req', '5470', '0.01', 'Backend', 'requests', 'made'],
        ['MAIN.n_vcl', '1', '.', 'Number', 'of', 'loaded', 'VCLs', 'in', 'total'],
        ['MAIN.n_vcl_avail', '1', '.', 'Number', 'of', 'VCLs', 'available'],
        ['MAIN.n_vcl_discard', '0', '.', 'Number', 'of', 'discarded', 'VCLs'],
        ['MAIN.vcl_fail', '0', '0.00', 'VCL', 'failures'],
        ['MAIN.bans', '1', '.', 'Count', 'of', 'bans'],
        ['MAIN.bans_completed', '1', '.', 'Number', 'of', 'bans', 'marked', u"'completed'"],
        ['MAIN.bans_obj', '0', '.', 'Number', 'of', 'bans', 'using', 'obj.*'],
        ['MAIN.bans_req', '0', '.', 'Number', 'of', 'bans', 'using', 'req.*'],
        ['MAIN.bans_added', '1', '0.00', 'Bans', 'added'],
        ['MAIN.bans_deleted', '0', '0.00', 'Bans', 'deleted'],
        [
            'MAIN.bans_tested', '0', '0.00', 'Bans', 'tested', 'against', 'objects',
            '(lookup)'
        ],
        [
            'MAIN.bans_obj_killed', '0', '0.00', 'Objects', 'killed', 'by', 'bans',
            '(lookup)'
        ],
        [
            'MAIN.bans_lurker_tested', '0', '0.00', 'Bans', 'tested', 'against', 'objects',
            '(lurker)'
        ],
        [
            'MAIN.bans_tests_tested', '0', '0.00', 'Ban', 'tests', 'tested', 'against',
            'objects', '(lookup)'
        ],
        [
            'MAIN.bans_lurker_tests_tested', '0', '0.00', 'Ban', 'tests', 'tested',
            'against', 'objects', '(lurker)'
        ],
        [
            'MAIN.bans_lurker_obj_killed', '0', '0.00', 'Objects', 'killed', 'by', 'bans',
            '(lurker)'
        ],
        [
            'MAIN.bans_lurker_obj_killed_cutoff', '0', '0.00', 'Objects', 'killed', 'by',
            'bans', 'for', 'cutoff', '(lurker)'
        ], ['MAIN.bans_dups', '0', '0.00', 'Bans', 'superseded', 'by', 'other', 'bans'],
        [
            'MAIN.bans_lurker_contention', '0', '0.00', 'Lurker', 'gave', 'way', 'for',
            'lookup'
        ],
        [
            'MAIN.bans_persisted_bytes', '16', '.', 'Bytes', 'used', 'by', 'the',
            'persisted', 'ban', 'lists'
        ],
        [
            'MAIN.bans_persisted_fragmentation', '0', '.', 'Extra', 'bytes', 'in',
            'persisted', 'ban', 'lists', 'due', 'to', 'fragmentation'
        ], ['MAIN.n_purges', '0', '.', 'Number', 'of', 'purge', 'operations', 'executed'],
        ['MAIN.n_obj_purged', '0', '.', 'Number', 'of', 'purged', 'objects'],
        [
            'MAIN.exp_mailed', '3170', '0.01', 'Number', 'of', 'objects', 'mailed', 'to',
            'expiry', 'thread'
        ],
        [
            'MAIN.exp_received', '3170', '0.01', 'Number', 'of', 'objects', 'received',
            'by', 'expiry', 'thread'
        ], ['MAIN.hcb_nolock', '280976', '0.60', 'HCB', 'Lookups', 'without', 'lock'],
        ['MAIN.hcb_lock', '3142', '0.01', 'HCB', 'Lookups', 'with', 'lock'],
        ['MAIN.hcb_insert', '3142', '0.01', 'HCB', 'Inserts'],
        ['MAIN.esi_errors', '0', '0.00', 'ESI', 'parse', 'errors', '(unlock)'],
        ['MAIN.esi_warnings', '0', '0.00', 'ESI', 'parse', 'warnings', '(unlock)'],
        ['MAIN.vmods', '0', '.', 'Loaded', 'VMODs'],
        ['MAIN.n_gzip', '0', '0.00', 'Gzip', 'operations'],
        ['MAIN.n_gunzip', '0', '0.00', 'Gunzip', 'operations'],
        ['MAIN.n_test_gunzip', '0', '0.00', 'Test', 'gunzip', 'operations'],
        ['LCK.backend.creat', '3', '0.00', 'Created', 'locks'],
        ['LCK.backend.destroy', '0', '0.00', 'Destroyed', 'locks'],
        ['LCK.backend.locks', '10943', '0.02', 'Lock', 'Operations'],
        ['LCK.backend_tcp.creat', '1', '0.00', 'Created', 'locks'],
        ['LCK.backend_tcp.destroy', '0', '0.00', 'Destroyed', 'locks'],
        ['LCK.backend_tcp.locks', '20814', '0.04', 'Lock', 'Operations'],
        ['LCK.ban.creat', '1', '0.00', 'Created', 'locks'],
        ['LCK.ban.destroy', '0', '0.00', 'Destroyed', 'locks'],
        ['LCK.ban.locks', '36728', '0.08', 'Lock', 'Operations'],
        ['LCK.busyobj.creat', '5488', '0.01', 'Created', 'locks'],
        ['LCK.busyobj.destroy', '5470', '0.01', 'Destroyed', 'locks'],
        ['LCK.busyobj.locks', '44656', '0.10', 'Lock', 'Operations'],
        ['LCK.cli.creat', '1', '0.00', 'Created', 'locks'],
        ['LCK.cli.destroy', '0', '0.00', 'Destroyed', 'locks'],
        ['LCK.cli.locks', '156283', '0.33', 'Lock', 'Operations'],
        ['LCK.exp.creat', '1', '0.00', 'Created', 'locks'],
        ['LCK.exp.destroy', '0', '0.00', 'Destroyed', 'locks'],
        ['LCK.exp.locks', '21269', '0.05', 'Lock', 'Operations'],
        ['LCK.hcb.creat', '1', '0.00', 'Created', 'locks'],
        ['LCK.hcb.destroy', '0', '0.00', 'Destroyed', 'locks'],
        ['LCK.hcb.locks', '8623', '0.02', 'Lock', 'Operations'],
        ['LCK.lru.creat', '2', '0.00', 'Created', 'locks'],
        ['LCK.lru.destroy', '0', '0.00', 'Destroyed', 'locks'],
        ['LCK.lru.locks', '159150', '0.34', 'Lock', 'Operations'],
        ['LCK.mempool.creat', '5', '0.00', 'Created', 'locks'],
        ['LCK.mempool.destroy', '0', '0.00', 'Destroyed', 'locks'],
        ['LCK.mempool.locks', '3132022', '6.68', 'Lock', 'Operations'],
        ['LCK.objhdr.creat', '3161', '0.01', 'Created', 'locks'],
        ['LCK.objhdr.destroy', '2875', '0.01', 'Destroyed', 'locks'],
        ['LCK.objhdr.locks', '1177910', '2.51', 'Lock', 'Operations'],
        ['LCK.pipestat.creat', '1', '0.00', 'Created', 'locks'],
        ['LCK.pipestat.destroy', '0', '0.00', 'Destroyed', 'locks'],
        ['LCK.pipestat.locks', '0', '0.00', 'Lock', 'Operations'],
        ['LCK.sess.creat', '247795', '0.53', 'Created', 'locks'],
        ['LCK.sess.destroy', '247796', '0.53', 'Destroyed', 'locks'],
        ['LCK.sess.locks', '258736', '0.55', 'Lock', 'Operations'],
        ['LCK.vbe.creat', '1', '0.00', 'Created', 'locks'],
        ['LCK.vbe.destroy', '0', '0.00', 'Destroyed', 'locks'],
        ['LCK.vbe.locks', '156276', '0.33', 'Lock', 'Operations'],
        ['LCK.vcapace.creat', '1', '0.00', 'Created', 'locks'],
        ['LCK.vcapace.destroy', '0', '0.00', 'Destroyed', 'locks'],
        ['LCK.vcapace.locks', '0', '0.00', 'Lock', 'Operations'],
        ['LCK.vcl.creat', '1', '0.00', 'Created', 'locks'],
        ['LCK.vcl.destroy', '0', '0.00', 'Destroyed', 'locks'],
        ['LCK.vcl.locks', '14377', '0.03', 'Lock', 'Operations'],
        ['LCK.vxid.creat', '1', '0.00', 'Created', 'locks'],
        ['LCK.vxid.destroy', '0', '0.00', 'Destroyed', 'locks'],
        ['LCK.vxid.locks', '30', '0.00', 'Lock', 'Operations'],
        ['LCK.waiter.creat', '2', '0.00', 'Created', 'locks'],
        ['LCK.waiter.destroy', '0', '0.00', 'Destroyed', 'locks'],
        ['LCK.waiter.locks', '119241', '0.25', 'Lock', 'Operations'],
        ['LCK.wq.creat', '3', '0.00', 'Created', 'locks'],
        ['LCK.wq.destroy', '0', '0.00', 'Destroyed', 'locks'],
        ['LCK.wq.locks', '1289567', '2.75', 'Lock', 'Operations'],
        ['LCK.wstat.creat', '1', '0.00', 'Created', 'locks'],
        ['LCK.wstat.destroy', '0', '0.00', 'Destroyed', 'locks'],
        ['LCK.wstat.locks', '290491', '0.62', 'Lock', 'Operations'],
        ['MEMPOOL.busyobj.live', '0', '.', 'In', 'use'],
        ['MEMPOOL.busyobj.pool', '10', '.', 'In', 'Pool'],
        ['MEMPOOL.busyobj.sz_wanted', '65536', '.', 'Size', 'requested'],
        ['MEMPOOL.busyobj.sz_actual', '65504', '.', 'Size', 'allocated'],
        ['MEMPOOL.busyobj.allocs', '5470', '0.01', 'Allocations'],
        ['MEMPOOL.busyobj.frees', '5470', '0.01', 'Frees'],
        ['MEMPOOL.busyobj.recycle', '5470', '0.01', 'Recycled', 'from', 'pool'],
        ['MEMPOOL.busyobj.timeout', '632', '0.00', 'Timed', 'out', 'from', 'pool'],
        ['MEMPOOL.busyobj.toosmall', '0', '0.00', 'Too', 'small', 'to', 'recycle'],
        ['MEMPOOL.busyobj.surplus', '0', '0.00', 'Too', 'many', 'for', 'pool'],
        ['MEMPOOL.busyobj.randry', '0', '0.00', 'Pool', 'ran', 'dry'],
        ['MEMPOOL.req0.live', '0', '.', 'In', 'use'],
        ['MEMPOOL.req0.pool', '10', '.', 'In', 'Pool'],
        ['MEMPOOL.req0.sz_wanted', '65536', '.', 'Size', 'requested'],
        ['MEMPOOL.req0.sz_actual', '65504', '.', 'Size', 'allocated'],
        ['MEMPOOL.req0.allocs', '133404', '0.28', 'Allocations'],
        ['MEMPOOL.req0.frees', '133404', '0.28', 'Frees'],
        ['MEMPOOL.req0.recycle', '133404', '0.28', 'Recycled', 'from', 'pool'],
        ['MEMPOOL.req0.timeout', '1710', '0.00', 'Timed', 'out', 'from', 'pool'],
        ['MEMPOOL.req0.toosmall', '0', '0.00', 'Too', 'small', 'to', 'recycle'],
        ['MEMPOOL.req0.surplus', '0', '0.00', 'Too', 'many', 'for', 'pool'],
        ['MEMPOOL.req0.randry', '0', '0.00', 'Pool', 'ran', 'dry'],
        ['MEMPOOL.sess0.live', '0', '.', 'In', 'use'],
        ['MEMPOOL.sess0.pool', '10', '.', 'In', 'Pool'],
        ['MEMPOOL.sess0.sz_wanted', '512', '.', 'Size', 'requested'],
        ['MEMPOOL.sess0.sz_actual', '480', '.', 'Size', 'allocated'],
        ['MEMPOOL.sess0.allocs', '123864', '0.26', 'Allocations'],
        ['MEMPOOL.sess0.frees', '123864', '0.26', 'Frees'],
        ['MEMPOOL.sess0.recycle', '123864', '0.26', 'Recycled', 'from', 'pool'],
        ['MEMPOOL.sess0.timeout', '3928', '0.01', 'Timed', 'out', 'from', 'pool'],
        ['MEMPOOL.sess0.toosmall', '0', '0.00', 'Too', 'small', 'to', 'recycle'],
        ['MEMPOOL.sess0.surplus', '0', '0.00', 'Too', 'many', 'for', 'pool'],
        ['MEMPOOL.sess0.randry', '0', '0.00', 'Pool', 'ran', 'dry'],
        ['LCK.sma.creat', '2', '0.00', 'Created', 'locks'],
        ['LCK.sma.destroy', '0', '0.00', 'Destroyed', 'locks'],
        ['LCK.sma.locks', '21346', '0.05', 'Lock', 'Operations'],
        ['SMA.s0.c_req', '6312', '0.01', 'Allocator', 'requests'],
        ['SMA.s0.c_fail', '0', '0.00', 'Allocator', 'failures'],
        ['SMA.s0.c_bytes', '58190951', '124.05', 'Bytes', 'allocated'],
        ['SMA.s0.c_freed', '52496614', '111.91', 'Bytes', 'freed'],
        ['SMA.s0.g_alloc', '534', '.', 'Allocations', 'outstanding'],
        ['SMA.s0.g_bytes', '5694337', '.', 'Bytes', 'outstanding'],
        ['SMA.s0.g_space', '4289272959', '.', 'Bytes', 'available'],
        ['SMA.Transient.c_req', '4628', '0.01', 'Allocator', 'requests'],
        ['SMA.Transient.c_fail', '0', '0.00', 'Allocator', 'failures'],
        ['SMA.Transient.c_bytes', '56144858', '119.69', 'Bytes', 'allocated'],
        ['SMA.Transient.c_freed', '56144858', '119.69', 'Bytes', 'freed'],
        ['SMA.Transient.g_alloc', '0', '.', 'Allocations', 'outstanding'],
        ['SMA.Transient.g_bytes', '0', '.', 'Bytes', 'outstanding'],
        ['SMA.Transient.g_space', '0', '.', 'Bytes', 'available'],
        ['MEMPOOL.req1.live', '0', '.', 'In', 'use'],
        ['MEMPOOL.req1.pool', '10', '.', 'In', 'Pool'],
        ['MEMPOOL.req1.sz_wanted', '65536', '.', 'Size', 'requested'],
        ['MEMPOOL.req1.sz_actual', '65504', '.', 'Size', 'allocated'],
        ['MEMPOOL.req1.allocs', '133534', '0.28', 'Allocations'],
        ['MEMPOOL.req1.frees', '133534', '0.28', 'Frees'],
        ['MEMPOOL.req1.recycle', '133534', '0.28', 'Recycled', 'from', 'pool'],
        ['MEMPOOL.req1.timeout', '1721', '0.00', 'Timed', 'out', 'from', 'pool'],
        ['MEMPOOL.req1.toosmall', '0', '0.00', 'Too', 'small', 'to', 'recycle'],
        ['MEMPOOL.req1.surplus', '0', '0.00', 'Too', 'many', 'for', 'pool'],
        ['MEMPOOL.req1.randry', '0', '0.00', 'Pool', 'ran', 'dry'],
        ['MEMPOOL.sess1.live', '0', '.', 'In', 'use'],
        ['MEMPOOL.sess1.pool', '10', '.', 'In', 'Pool'],
        ['MEMPOOL.sess1.sz_wanted', '512', '.', 'Size', 'requested'],
        ['MEMPOOL.sess1.sz_actual', '480', '.', 'Size', 'allocated'],
        ['MEMPOOL.sess1.allocs', '123932', '0.26', 'Allocations'],
        ['MEMPOOL.sess1.frees', '123932', '0.26', 'Frees'],
        ['MEMPOOL.sess1.recycle', '123932', '0.26', 'Recycled', 'from', 'pool'],
        ['MEMPOOL.sess1.timeout', '3997', '0.01', 'Timed', 'out', 'from', 'pool'],
        ['MEMPOOL.sess1.toosmall', '0', '0.00', 'Too', 'small', 'to', 'recycle'],
        ['MEMPOOL.sess1.surplus', '0', '0.00', 'Too', 'many', 'for', 'pool'],
        ['MEMPOOL.sess1.randry', '0', '0.00', 'Pool', 'ran', 'dry'],
        ['VBE.boot.default.happy', '0', '.', 'Happy', 'health', 'probes'],
        ['VBE.boot.default.bereq_hdrbytes', '3723175', '7.94', 'Request', 'header', 'bytes'],
        ['VBE.boot.default.bereq_bodybytes', '0', '0.00', 'Request', 'body', 'bytes'],
        [
            'VBE.boot.default.beresp_hdrbytes', '1446437', '3.08', 'Response', 'header',
            'bytes'
        ],
        [
            'VBE.boot.default.beresp_bodybytes', '112184497', '239.15', 'Response', 'body',
            'bytes'
        ],
        [
            'VBE.boot.default.pipe_hdrbytes', '0', '0.00', 'Pipe', 'request', 'header',
            'bytes'
        ], ['VBE.boot.default.pipe_out', '0', '0.00', 'Piped', 'bytes', 'to', 'backend'],
        ['VBE.boot.default.pipe_in', '0', '0.00', 'Piped', 'bytes', 'from', 'backend'],
        ['VBE.boot.default.conn', '0', '.', 'Concurrent', 'connections', 'to', 'backend'],
        ['VBE.boot.default.req', '5470', '0.01', 'Backend', 'requests', 'sent']]

discovery = {
    '': [],
    'backend': [(None, {})],
    'backend_success_ratio': [(None, {})],
    'cache': [(None, {})],
    'cache_hit_ratio': [(None, {})],
    'client': [(None, {})],
    'esi': [(None, {})],
    'fetch': [],
    'objects': [(None, {})],
    'worker': [],
    'worker_thread_ratio': []
}

checks = {
    'backend': [(None, {}, [(0, '0.0 conn. too many/s',
                             [('varnish_backend_busy_rate', 0.0, None, None, None, None)]),
                            (0, '0.0 conn. not attempted/s',
                             [('varnish_backend_unhealthy_rate', 0.0, None, None, None, None)]),
                            (0, '0.0 requests made/s',
                             [('varnish_backend_req_rate', 0.0, None, None, None, None)]),
                            (0, '0.0 conn. recycles/s',
                             [('varnish_backend_recycle_rate', 0.0, None, None, None, None)]),
                            (0, '0.0 conn. retry/s',
                             [('varnish_backend_retry_rate', 0.0, None, None, None, None)]),
                            (0, '0.0 conn. failures/s',
                             [('varnish_backend_fail_rate', 0.0, None, None, None, None)]),
                            (0, '0.0 conn. success/s',
                             [('varnish_backend_conn_rate', 0.0, None, None, None, None)]),
                            (0, '0.0 conn. reuses/s',
                             [('varnish_backend_reuse_rate', 0.0, None, None, None, None)])])],
    'backend_success_ratio': [(None, {
        'levels_lower': (70.0, 60.0)
    }, [(0, '100%', [('varnish_backend_success_ratio', 100.0, None,
                                                       None, None, None)])])],
    'cache': [(None, {}, [(0, '0.0 misses/s',
                           [('varnish_cache_miss_rate', 0.0, None, None, None, None)]),
                          (0, '0.0 hits/s',
                           [('varnish_cache_hit_rate', 0.0, None, None, None, None)]),
                          (0, '0.0 hits for pass./s',
                           [('varnish_cache_hitpass_rate', 0.0, None, None, None, None)])])],
    'cache_hit_ratio': [(None, {
        'levels_lower': (70.0, 60.0)
    }, [(0, '98.88%', [('cache_hit_ratio', 98.88175502534024, None, None, None,
                                        None)])])],
    'client': [(None, {}, [(0, '0.0 Good client requests received/s',
                            [('varnish_client_req_rate', 0.0, None, None, None, None)])])],
    'esi': [(None, {
        'errors': (1.0, 2.0)
    }, [(0, '0.0 parse errors (unlock)/s', [('varnish_esi_errors_rate',
                                                                       0.0, 1.0, 2.0, None, None)]),
        (0, '0.0 parse warnings (unlock)/s',
         [('varnish_esi_warnings_rate', 0.0, None, None, None, None)])])],
    'objects': [(None, {},
                 [(0, '0.0 Number of expired objects/s',
                   [('varnish_objects_expired_rate', 0.0, None, None, None, None)]),
                  (0, '0.0 Number of LRU nuked objects/s',
                   [('varnish_objects_lru_nuked_rate', 0.0, None, None, None, None)]),
                  (0, '0.0 Number of LRU moved objects/s',
                   [('varnish_objects_lru_moved_rate', 0.0, None, None, None, None)])])]
}
