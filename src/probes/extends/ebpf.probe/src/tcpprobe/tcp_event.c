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

static void build_event_label(struct tcp_link_s *link, struct event_info_s *evt)
{
    unsigned char src_ip_str[INET6_ADDRSTRLEN];
    unsigned char dst_ip_str[INET6_ADDRSTRLEN];

    ip_str(link->family, (unsigned char *)&(link->c_ip), src_ip_str, INET6_ADDRSTRLEN);
    ip_str(link->family, (unsigned char *)&(link->s_ip), dst_ip_str, INET6_ADDRSTRLEN);

    (void)snprintf(evt->ip, EVT_IP_LEN, "CIP(%s:%u), SIP(%s:%u)",
                   src_ip_str,
                   link->c_port,
                   dst_ip_str,
                   link->s_port);
}

static void build_entity_id(struct tcp_link_s *link, char *buf, int buf_len)
{
    unsigned char src_ip_str[INET6_ADDRSTRLEN];
    unsigned char dst_ip_str[INET6_ADDRSTRLEN];

    ip_str(link->family, (unsigned char *)&(link->c_ip), src_ip_str, INET6_ADDRSTRLEN);
    ip_str(link->family, (unsigned char *)&(link->s_ip), dst_ip_str, INET6_ADDRSTRLEN);

    (void)snprintf(buf, buf_len, "%u_%u_%s_%s_%u_%u_%u",
                    link->tgid,
                    link->role,
                    src_ip_str,
                    dst_ip_str,
                    link->c_port,
                    link->s_port,
                    link->family);
}

#define __ENTITY_ID_LEN 128

void report_tcp_win_evt(struct probe_params *args, struct tcp_metrics_s *metrics)
{
    struct tcp_windows *win_stats;
    char entityId[__ENTITY_ID_LEN];
    struct event_info_s evt = {0};

    if (args->logs == 0) {
        return;
    }

    entityId[0] = 0;
    evt.entityName = OO_NAME;
    evt.entityId = entityId;
    evt.pid = (int)metrics->link.tgid;
    build_event_label(&(metrics->link), &evt);

    win_stats = &(metrics->win_stats);
    if (win_stats->tcpi_rcv_wnd == 0) {
        build_entity_id(&metrics->link, entityId, __ENTITY_ID_LEN);
        evt.metrics = "rcv_wnd";
        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "TCP zero receive windows.");
    }

    if (win_stats->tcpi_snd_wnd == 0) {
        if (entityId[0] == 0) {
            build_entity_id(&metrics->link, entityId, __ENTITY_ID_LEN);
        }
        evt.metrics = "snd_wnd";
        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "TCP zero send windows.");
    }

    if (win_stats->tcpi_avl_snd_wnd == 0 && win_stats->tcpi_snd_wnd != 0) {
        if (entityId[0] == 0) {
            build_entity_id(&metrics->link, entityId, __ENTITY_ID_LEN);
        }
        evt.metrics = "avl_snd_wnd";
        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "TCP zero available send windows.");
    }
}

void report_tcp_abn_evt(struct probe_params *args, struct tcp_metrics_s *metrics)
{
    struct tcp_abn *abn_stats;
    char entityId[__ENTITY_ID_LEN];
    struct event_info_s evt = {0};

    if (args->logs == 0) {
        return;
    }

    entityId[0] = 0;
    evt.entityName = OO_NAME;
    evt.entityId = entityId;
    evt.pid = (int)metrics->link.tgid;
    build_event_label(&(metrics->link), &evt);

    abn_stats = &(metrics->abn_stats);
    if (abn_stats->tcp_oom != 0) {
        build_entity_id(&metrics->link, entityId, __ENTITY_ID_LEN);
        evt.metrics = "tcp_oom";

        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "TCP out of memory(%u).",
                    abn_stats->tcp_oom);
    }

    if ((args->drops_count_thr != 0) && (abn_stats->backlog_drops > args->drops_count_thr)) {
        if (entityId[0] == 0) {
            build_entity_id(&metrics->link, entityId, __ENTITY_ID_LEN);
        }
        evt.metrics = "backlog_drops";

        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "TCP backlog queue drops(%u).",
                    abn_stats->backlog_drops);
    }

    if ((args->drops_count_thr != 0) && (abn_stats->filter_drops > args->drops_count_thr)) {
        if (entityId[0] == 0) {
            build_entity_id(&metrics->link, entityId, __ENTITY_ID_LEN);
        }
        evt.metrics = "filter_drops";

        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "TCP filter drops(%u).",
                    abn_stats->filter_drops);
    }

    u32 sk_drops_delta = (abn_stats->sk_drops >= abn_stats->last_time_sk_drops) ?
        (abn_stats->sk_drops - abn_stats->last_time_sk_drops) : abn_stats->sk_drops;

    if ((args->drops_count_thr != 0) && (sk_drops_delta > args->drops_count_thr)) {
        if (entityId[0] == 0) {
            build_entity_id(&metrics->link, entityId, __ENTITY_ID_LEN);
        }
        evt.metrics = "sk_drops";

        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "Number of lost packets in the TCP protocol stack(%u).",
                    sk_drops_delta);
    }

    u32 lost_out_delta = (abn_stats->lost_out >= abn_stats->last_time_lost_out) ?
        (abn_stats->lost_out - abn_stats->last_time_lost_out) : abn_stats->lost_out;
    if ((args->drops_count_thr != 0) && (lost_out_delta > args->drops_count_thr)) {
        if (entityId[0] == 0) {
            build_entity_id(&metrics->link, entityId, __ENTITY_ID_LEN);
        }
        evt.metrics = "lost_out";

        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "Number of lost segments estimated by TCP congestion(%u).",
                    lost_out_delta);
    }


    u32 sacked_out_delta = (abn_stats->sacked_out >= abn_stats->last_time_sacked_out) ?
        (abn_stats->sacked_out - abn_stats->last_time_sacked_out) : abn_stats->sacked_out;

    if ((args->drops_count_thr != 0) && (sacked_out_delta > args->drops_count_thr)) {
        if (entityId[0] == 0) {
            build_entity_id(&metrics->link, entityId, __ENTITY_ID_LEN);
        }
        evt.metrics = "sacked_out";

        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "Number of out-of-order TCP packets (SACK) or number of repeated TCP ACKs (NO SACK)(%u).",
                    sacked_out_delta);
    }

}

void report_tcp_syn_rtt_evt(struct probe_params *args, struct tcp_metrics_s *metrics)
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
    evt.pid = (int)metrics->link.tgid;
    build_event_label(&(metrics->link), &evt);

    latency_thr_us = args->latency_thr << 3; // milliseconds to microseconds
    if ((latency_thr_us != 0) && (metrics->srtt_stats.syn_srtt > latency_thr_us)) {
        build_entity_id(&metrics->link, entityId, __ENTITY_ID_LEN);
        evt.metrics = "syn_srtt";

        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "TCP connection establish timed out(%u us).",
                    metrics->srtt_stats.syn_srtt);
    }
}

