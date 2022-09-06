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

void report_tcp_abn_evt(struct probe_params *args, struct tcp_metrics_s *metrics)
{
    struct tcp_abn *abn_stats;
    char entityId[__ENTITY_ID_LEN];

    if (args->logs == 0) {
        return;
    }

    entityId[0] = 0;

    abn_stats = &(metrics->abn_stats);
    if (abn_stats->tcp_oom != 0) {
        build_entity_id(&metrics->link, entityId, __ENTITY_ID_LEN);
        report_logs(OO_NAME,
                    entityId,
                    "tcp_oom",
                    EVT_SEC_WARN,
                    "TCP out of memory(%u).",
                    abn_stats->tcp_oom);
    }

    if ((args->drops_count_thr != 0) && (abn_stats->backlog_drops > args->drops_count_thr)) {
        if (entityId[0] != 0) {
            build_entity_id(&metrics->link, entityId, __ENTITY_ID_LEN);
        }
        report_logs(OO_NAME,
                    entityId,
                    "backlog_drops",
                    EVT_SEC_WARN,
                    "TCP backlog queue drops(%u).",
                    abn_stats->backlog_drops);
    }

    if ((args->drops_count_thr != 0) && (abn_stats->filter_drops > args->drops_count_thr)) {
        if (entityId[0] != 0) {
            build_entity_id(&metrics->link, entityId, __ENTITY_ID_LEN);
        }
        report_logs(OO_NAME,
                    entityId,
                    "filter_drops",
                    EVT_SEC_WARN,
                    "TCP filter drops(%u).",
                    abn_stats->filter_drops);
    }
}

void report_tcp_syn_rtt_evt(struct probe_params *args, struct tcp_metrics_s *metrics)
{
    char entityId[__ENTITY_ID_LEN];
    unsigned int latency_thr_us;

    if (args->logs == 0) {
        return;
    }

    entityId[0] = 0;

    latency_thr_us = args->latency_thr << 3; // milliseconds to microseconds
    if ((latency_thr_us != 0) && (metrics->srtt_stats.syn_srtt > latency_thr_us)) {
        build_entity_id(&metrics->link, entityId, __ENTITY_ID_LEN);
        report_logs(OO_NAME,
                    entityId,
                    "syn_srtt",
                    EVT_SEC_WARN,
                    "TCP connection establish timed out(%u us).",
                    metrics->srtt_stats.syn_srtt);
    }
}

