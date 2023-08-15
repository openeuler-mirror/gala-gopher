/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: luzhihao
 * Create: 2022-07-28
 * Description: tcp event
 ******************************************************************************/
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "args.h"
#include "event.h"
#include "tcp_event.h"

#define OO_NAME "tcp_link"

static void build_event_label(struct tcp_tracker_s *tracker, struct event_info_s *evt)
{
    (void)snprintf(evt->ip, EVT_IP_LEN, "CIP(%s), SIP(%s:%u)",
                   tracker->src_ip,
                   tracker->dst_ip,
                   tracker->id.port);
}

static void build_entity_id(struct tcp_tracker_s *tracker, char *buf, int buf_len)
{
    (void)snprintf(buf, buf_len, "%u_%s_%s_%s_%u_%u",
                    tracker->id.tgid,
                    (tracker->id.role == 0) ? "server" : "client",
                    tracker->src_ip,
                    tracker->dst_ip,
                    tracker->id.port,
                    tracker->id.family);
}

#define __ENTITY_ID_LEN 128

void report_tcp_win_evt(struct probe_params *args, struct tcp_tracker_s *tracker)
{
    char entityId[__ENTITY_ID_LEN];
    struct event_info_s evt = {0};

    if (args->logs == 0) {
        return;
    }

    entityId[0] = 0;
    evt.entityName = OO_NAME;
    evt.entityId = entityId;
    evt.pid = (int)tracker->id.tgid;
    build_event_label(tracker, &evt);

    if ((char)tracker->zero_win_rx_ratio > args->res_percent_upper) {
        build_entity_id(tracker, entityId, __ENTITY_ID_LEN);
        evt.metrics = "zero_win_rx_ratio";
        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "TCP zero receive windows ratio %.2f.", tracker->zero_win_rx_ratio);
    }

    if ((char)tracker->zero_win_tx_ratio > args->res_percent_upper) {
        if (entityId[0] == 0) {
            build_entity_id(tracker, entityId, __ENTITY_ID_LEN);
        }
        evt.metrics = "zero_win_tx_ratio";
        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "TCP zero send windows ratio %.2f.", tracker->zero_win_tx_ratio);
    }
}

void report_tcp_abn_evt(struct probe_params *args, struct tcp_tracker_s *tracker)
{
    char entityId[__ENTITY_ID_LEN];
    struct event_info_s evt = {0};

    if (args->logs == 0) {
        return;
    }

    entityId[0] = 0;
    evt.entityName = OO_NAME;
    evt.entityId = entityId;
    evt.pid = (int)tracker->id.tgid;
    build_event_label(tracker, &evt);

    if (tracker->stats[TCP_OOM] != 0) {
        build_entity_id(tracker, entityId, __ENTITY_ID_LEN);
        evt.metrics = "tcp_oom";

        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "TCP out of memory(%llu).",
                    tracker->stats[TCP_OOM]);
    }

    if ((args->drops_count_thr != 0) && (tracker->stats[BACKLOG_DROPS] > args->drops_count_thr)) {
        if (entityId[0] == 0) {
            build_entity_id(tracker, entityId, __ENTITY_ID_LEN);
        }
        evt.metrics = "backlog_drops";

        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "TCP backlog queue drops(%llu).",
                    tracker->stats[BACKLOG_DROPS]);
    }

    if ((args->drops_count_thr != 0) && (tracker->stats[FILTER_DROPS] > args->drops_count_thr)) {
        if (entityId[0] == 0) {
            build_entity_id(tracker, entityId, __ENTITY_ID_LEN);
        }
        evt.metrics = "filter_drops";

        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "TCP filter drops(%llu).",
                    tracker->stats[FILTER_DROPS]);
    }

    if ((args->drops_count_thr != 0) && (tracker->stats[SK_DROPS] > args->drops_count_thr)) {
        if (entityId[0] == 0) {
            build_entity_id(tracker, entityId, __ENTITY_ID_LEN);
        }
        evt.metrics = "sk_drops";

        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "Number of lost packets in the TCP protocol stack(%llu).",
                    tracker->stats[SK_DROPS]);
    }

    if ((args->drops_count_thr != 0) && (tracker->stats[LOST_OUT] > args->drops_count_thr)) {
        if (entityId[0] == 0) {
            build_entity_id(tracker, entityId, __ENTITY_ID_LEN);
        }
        evt.metrics = "lost_out";

        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "Number of lost segments estimated by TCP congestion(%llu).",
                    tracker->stats[LOST_OUT]);
    }

    if ((args->drops_count_thr != 0) && (tracker->stats[SACKED_OUT] > args->drops_count_thr)) {
        if (entityId[0] == 0) {
            build_entity_id(tracker, entityId, __ENTITY_ID_LEN);
        }
        evt.metrics = "sacked_out";

        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "Number of out-of-order TCP packets (SACK) or number of repeated TCP ACKs (NO SACK)(%llu).",
                    tracker->stats[SACKED_OUT]);
    }

}

void report_tcp_syn_rtt_evt(struct probe_params *args, struct tcp_tracker_s *tracker)
{
    char entityId[__ENTITY_ID_LEN];
    unsigned int latency_thr_us;
    struct event_info_s evt = {0};

    if (args->logs == 0) {
        return;
    }

    entityId[0] = 0;
    evt.entityName = OO_NAME;
    evt.entityId = entityId;
    evt.pid = (int)tracker->id.tgid;
    build_event_label(tracker, &evt);

    latency_thr_us = args->latency_thr << 3; // milliseconds to microseconds
    if ((latency_thr_us != 0) && (tracker->stats[SYN_SRTT_MAX] > latency_thr_us)) {
        build_entity_id(tracker, entityId, __ENTITY_ID_LEN);
        evt.metrics = "syn_srtt_max";

        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "TCP connection establish timed out(%llu us).",
                    tracker->stats[SYN_SRTT_MAX]);
    }
}

