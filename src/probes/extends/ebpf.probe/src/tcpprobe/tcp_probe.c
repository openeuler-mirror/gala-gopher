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
 * Description: tcp load bpf probe
 ******************************************************************************/
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/resource.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "args.h"
#include "tcpprobe.h"
#include "tcp_event.h"
#include "tcp_tx_rx.skel.h"
#include "tcp_windows.skel.h"
#include "tcp_sockbuf.skel.h"
#include "tcp_rtt.skel.h"
#include "tcp_rate.skel.h"
#include "tcp_abn.skel.h"
#include "tcp_link.skel.h"

#define TCP_TBL_ABN     "tcp_abn"
#define TCP_TBL_SYNRTT  "tcp_srtt"
#define TCP_TBL_RTT     "tcp_rtt"
#define TCP_TBL_WIN     "tcp_windows"
#define TCP_TBL_RATE    "tcp_rate"
#define TCP_TBL_SOCKBUF "tcp_sockbuf"
#define TCP_TBL_TXRX    "tcp_tx_rx"

static struct probe_params *g_args = NULL;

static void output_tcp_abn(void *ctx, int cpu, void *data, __u32 size)
{
    u32 sk_drops_delta;
    u32 lost_out_delta;
    u32 sacked_out_delta;
    struct tcp_link_s *link;
    unsigned char src_ip_str[INET6_ADDRSTRLEN];
    unsigned char dst_ip_str[INET6_ADDRSTRLEN];

    struct tcp_metrics_s *metrics  = (struct tcp_metrics_s *)data;

    link = &(metrics->link);
    ip_str(link->family, (unsigned char *)&(link->c_ip), src_ip_str, INET6_ADDRSTRLEN);
    ip_str(link->family, (unsigned char *)&(link->s_ip), dst_ip_str, INET6_ADDRSTRLEN);

    sk_drops_delta = (metrics->abn_stats.sk_drops >= metrics->abn_stats.last_time_sk_drops) ?
        (metrics->abn_stats.sk_drops - metrics->abn_stats.last_time_sk_drops) : metrics->abn_stats.sk_drops;

    lost_out_delta = (metrics->abn_stats.lost_out >= metrics->abn_stats.last_time_lost_out) ?
        (metrics->abn_stats.lost_out - metrics->abn_stats.last_time_lost_out) : metrics->abn_stats.lost_out;

    sacked_out_delta = (metrics->abn_stats.sacked_out >= metrics->abn_stats.last_time_sacked_out) ?
        (metrics->abn_stats.sacked_out - metrics->abn_stats.last_time_sacked_out) : metrics->abn_stats.sacked_out;

    (void)fprintf(stdout,
        "|%s|%u|%u|%s|%s|%u|%u|%u"
        "|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%d|%d|\n",
        TCP_TBL_ABN,
        link->tgid,
        link->role,
        src_ip_str,
        dst_ip_str,
        link->c_port,
        link->s_port,
        link->family,

        metrics->abn_stats.total_retrans,
        metrics->abn_stats.backlog_drops,
        sk_drops_delta,
        lost_out_delta,
        sacked_out_delta,
        metrics->abn_stats.filter_drops,
        metrics->abn_stats.tmout,
        metrics->abn_stats.sndbuf_limit,
        metrics->abn_stats.rmem_scheduls,
        metrics->abn_stats.tcp_oom,
        metrics->abn_stats.send_rsts,
        metrics->abn_stats.receive_rsts,
        metrics->abn_stats.sk_err,
        metrics->abn_stats.sk_err_soft);
    (void)fflush(stdout);
}

static void output_tcp_syn_rtt(void *ctx, int cpu, void *data, __u32 size)
{
    struct tcp_link_s *link;
    unsigned char src_ip_str[INET6_ADDRSTRLEN];
    unsigned char dst_ip_str[INET6_ADDRSTRLEN];

    struct tcp_metrics_s *metrics  = (struct tcp_metrics_s *)data;

    link = &(metrics->link);
    ip_str(link->family, (unsigned char *)&(link->c_ip), src_ip_str, INET6_ADDRSTRLEN);
    ip_str(link->family, (unsigned char *)&(link->s_ip), dst_ip_str, INET6_ADDRSTRLEN);

    (void)fprintf(stdout,
        "|%s|%u|%u|%s|%s|%u|%u|%u"
        "|%u|\n",
        TCP_TBL_SYNRTT,
        link->tgid,
        link->role,
        src_ip_str,
        dst_ip_str,
        link->c_port,
        link->s_port,
        link->family,

        metrics->srtt_stats.syn_srtt);
    (void)fflush(stdout);
}

static void output_tcp_rtt(void *ctx, int cpu, void *data, __u32 size)
{
    struct tcp_link_s *link;
    unsigned char src_ip_str[INET6_ADDRSTRLEN];
    unsigned char dst_ip_str[INET6_ADDRSTRLEN];

    struct tcp_metrics_s *metrics  = (struct tcp_metrics_s *)data;

    link = &(metrics->link);
    ip_str(link->family, (unsigned char *)&(link->c_ip), src_ip_str, INET6_ADDRSTRLEN);
    ip_str(link->family, (unsigned char *)&(link->s_ip), dst_ip_str, INET6_ADDRSTRLEN);

    (void)fprintf(stdout,
        "|%s|%u|%u|%s|%s|%u|%u|%u"
        "|%u|%u|\n",
        TCP_TBL_RTT,
        link->tgid,
        link->role,
        src_ip_str,
        dst_ip_str,
        link->c_port,
        link->s_port,
        link->family,

        metrics->rtt_stats.tcpi_srtt,
        metrics->rtt_stats.tcpi_rcv_rtt);
    (void)fflush(stdout);
}

static void output_tcp_txrx(void *ctx, int cpu, void *data, __u32 size)
{
    u32 segs_out_delta, segs_in_delta;
    struct tcp_link_s *link;
    unsigned char src_ip_str[INET6_ADDRSTRLEN];
    unsigned char dst_ip_str[INET6_ADDRSTRLEN];

    struct tcp_metrics_s *metrics  = (struct tcp_metrics_s *)data;

    link = &(metrics->link);
    ip_str(link->family, (unsigned char *)&(link->c_ip), src_ip_str, INET6_ADDRSTRLEN);
    ip_str(link->family, (unsigned char *)&(link->s_ip), dst_ip_str, INET6_ADDRSTRLEN);

    segs_in_delta = (metrics->tx_rx_stats.segs_in >= metrics->tx_rx_stats.last_time_segs_in) ?
        (metrics->tx_rx_stats.segs_in - metrics->tx_rx_stats.last_time_segs_in) : metrics->tx_rx_stats.segs_in;
    segs_out_delta = (metrics->tx_rx_stats.segs_out >= metrics->tx_rx_stats.last_time_segs_out) ?
        (metrics->tx_rx_stats.segs_out - metrics->tx_rx_stats.last_time_segs_out) : metrics->tx_rx_stats.segs_out;

    (void)fprintf(stdout,
        "|%s|%u|%u|%s|%s|%u|%u|%u"
        "|%llu|%llu|%u|%u|\n",
        TCP_TBL_TXRX,
        link->tgid,
        link->role,
        src_ip_str,
        dst_ip_str,
        link->c_port,
        link->s_port,
        link->family,

        metrics->tx_rx_stats.rx,
        metrics->tx_rx_stats.tx,
        segs_in_delta,
        segs_out_delta);
    (void)fflush(stdout);
}

static void output_tcp_win(void *ctx, int cpu, void *data, __u32 size)
{
    struct tcp_link_s *link;
    unsigned char src_ip_str[INET6_ADDRSTRLEN];
    unsigned char dst_ip_str[INET6_ADDRSTRLEN];

    struct tcp_metrics_s *metrics  = (struct tcp_metrics_s *)data;

    link = &(metrics->link);
    ip_str(link->family, (unsigned char *)&(link->c_ip), src_ip_str, INET6_ADDRSTRLEN);
    ip_str(link->family, (unsigned char *)&(link->s_ip), dst_ip_str, INET6_ADDRSTRLEN);

    (void)fprintf(stdout,
        "|%s|%u|%u|%s|%s|%u|%u|%u"
        "|%u|%u|%u|%u|%u|%u|\n",
        TCP_TBL_WIN,
        link->tgid,
        link->role,
        src_ip_str,
        dst_ip_str,
        link->c_port,
        link->s_port,
        link->family,

        metrics->win_stats.tcpi_snd_cwnd,
        metrics->win_stats.tcpi_notsent_bytes,
        metrics->win_stats.tcpi_notack_bytes,
        metrics->win_stats.tcpi_reordering,
        metrics->win_stats.tcpi_snd_wnd,
        metrics->win_stats.tcpi_rcv_wnd);
    (void)fflush(stdout);
}

static void output_tcp_rate(void *ctx, int cpu, void *data, __u32 size)
{
    struct tcp_link_s *link;
    unsigned char src_ip_str[INET6_ADDRSTRLEN];
    unsigned char dst_ip_str[INET6_ADDRSTRLEN];

    struct tcp_metrics_s *metrics  = (struct tcp_metrics_s *)data;

    link = &(metrics->link);
    ip_str(link->family, (unsigned char *)&(link->c_ip), src_ip_str, INET6_ADDRSTRLEN);
    ip_str(link->family, (unsigned char *)&(link->s_ip), dst_ip_str, INET6_ADDRSTRLEN);

    (void)fprintf(stdout,
        "|%s|%u|%u|%s|%s|%u|%u|%u"
        "|%u|%u|%u|%u|%u|%u|%llu|%u|%u|%u|%u|%u|\n",
        TCP_TBL_RATE,
        link->tgid,
        link->role,
        src_ip_str,
        dst_ip_str,
        link->c_port,
        link->s_port,
        link->family,

        metrics->rate_stats.tcpi_rto,
        metrics->rate_stats.tcpi_ato,
        metrics->rate_stats.tcpi_snd_ssthresh,
        metrics->rate_stats.tcpi_rcv_ssthresh,
        metrics->rate_stats.tcpi_advmss,
        metrics->rate_stats.tcpi_rcv_space,
        metrics->rate_stats.tcpi_delivery_rate,
        metrics->rate_stats.tcpi_busy_time,
        metrics->rate_stats.tcpi_rwnd_limited,
        metrics->rate_stats.tcpi_sndbuf_limited,
        metrics->rate_stats.tcpi_pacing_rate,
        metrics->rate_stats.tcpi_max_pacing_rate);
    (void)fflush(stdout);
}

static void output_tcp_sockbuf(void *ctx, int cpu, void *data, __u32 size)
{
    struct tcp_link_s *link;
    unsigned char src_ip_str[INET6_ADDRSTRLEN];
    unsigned char dst_ip_str[INET6_ADDRSTRLEN];

    struct tcp_metrics_s *metrics  = (struct tcp_metrics_s *)data;

    link = &(metrics->link);
    ip_str(link->family, (unsigned char *)&(link->c_ip), src_ip_str, INET6_ADDRSTRLEN);
    ip_str(link->family, (unsigned char *)&(link->s_ip), dst_ip_str, INET6_ADDRSTRLEN);

    (void)fprintf(stdout,
        "|%s|%u|%u|%s|%s|%u|%u|%u"
        "|%u|%u|%u|%u|%u|%u|%u|%d|%d|\n",
        TCP_TBL_SOCKBUF,
        link->tgid,
        link->role,
        src_ip_str,
        dst_ip_str,
        link->c_port,
        link->s_port,
        link->family,

        metrics->sockbuf_stats.tcpi_sk_err_que_size,
        metrics->sockbuf_stats.tcpi_sk_rcv_que_size,
        metrics->sockbuf_stats.tcpi_sk_wri_que_size,
        metrics->sockbuf_stats.tcpi_sk_backlog_size,
        metrics->sockbuf_stats.tcpi_sk_omem_size,
        metrics->sockbuf_stats.tcpi_sk_forward_size,
        metrics->sockbuf_stats.tcpi_sk_wmem_size,
        metrics->sockbuf_stats.sk_rcvbuf,
        metrics->sockbuf_stats.sk_sndbuf);
    (void)fflush(stdout);
}
#if 0
static void output_tcp_metrics(void *ctx, int cpu, void *data, u32 size)
{
    struct tcp_metrics_s *metrics  = (struct tcp_metrics_s *)data;
    u32 flags = metrics->report_flags & TCP_PROBE_ALL;
    switch (flags) {
        case TCP_PROBE_ABN:
        {
            output_tcp_abn(ctx, cpu, data, size);
            break;
        }
        case TCP_PROBE_WINDOWS:
        {
            output_tcp_win(ctx, cpu, data, size);
            break;
        }
        case TCP_PROBE_RTT:
        {
            output_tcp_rtt(ctx, cpu, data, size);
            break;
        }
        case TCP_PROBE_TXRX:
        {
            output_tcp_txrx(ctx, cpu, data, size);
            break;
        }
        case TCP_PROBE_SOCKBUF:
        {
            output_tcp_sockbuf(ctx, cpu, data, size);
            break;
        }
        case TCP_PROBE_RATE:
        {
            output_tcp_rate(ctx, cpu, data, size);
            break;
        }
        case TCP_PROBE_SRTT:
        {
            output_tcp_syn_rtt(ctx, cpu, data, size);
            break;
        }
        default:
        {
            ERROR("[TCPPROBE] Invalid output.\n");
            break;
        }
    }
    (void)fflush(stdout);
}
#endif
static char is_load_probe(struct probe_params *args, u32 probe)
{
    return args->load_probe & probe;
}

static void load_args(int args_fd, struct probe_params* params)
{
    u32 key = 0;
    struct tcp_args_s args = {0};

    args.cport_flag = (u32)params->cport_flag;
    args.period = NS(params->period);
    args.filter_by_task = (u32)params->filter_task_probe;
    args.filter_by_tgid = (u32)params->filter_pid;

    (void)bpf_map_update_elem(args_fd, &key, &args, BPF_ANY);
}

static int tcp_load_probe_sockbuf(struct bpf_prog_s *prog, char is_load)
{
    int fd;
    struct perf_buffer *pb = NULL;

    __LOAD_PROBE(tcp_sockbuf, err, is_load);
    if (is_load) {
        prog->skels[prog->num].skel = tcp_sockbuf_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)tcp_sockbuf_bpf__destroy;

        fd = GET_MAP_FD(tcp_sockbuf, tcp_output);
        pb = create_pref_buffer(fd, output_tcp_sockbuf);
        if (pb == NULL) {
            ERROR("[TCPPROBE] Crate 'tcp_sockbuf' perf buffer failed.\n");
            goto err;
        }
        prog->pbs[prog->num] = pb;
        prog->num++;
    }

    return 0;
err:
    UNLOAD(tcp_sockbuf);
    return -1;
}

static int tcp_load_probe_rtt(struct bpf_prog_s *prog, char is_load)
{
    int fd;
    struct perf_buffer *pb = NULL;

    __LOAD_PROBE(tcp_rtt, err, is_load);
    if (is_load) {
        prog->skels[prog->num].skel = tcp_rtt_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)tcp_rtt_bpf__destroy;

        fd = GET_MAP_FD(tcp_rtt, tcp_output);
        pb = create_pref_buffer(fd, output_tcp_rtt);
        if (pb == NULL) {
            ERROR("[TCPPROBE] Crate 'tcp_rtt' perf buffer failed.\n");
            goto err;
        }
        prog->pbs[prog->num] = pb;
        prog->num++;
    }

    return 0;
err:
    UNLOAD(tcp_rtt);
    return -1;
}

static int tcp_load_probe_win(struct bpf_prog_s *prog, char is_load)
{
    int fd;
    struct perf_buffer *pb = NULL;

    __LOAD_PROBE(tcp_windows, err, is_load);
    if (is_load) {
        prog->skels[prog->num].skel = tcp_windows_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)tcp_windows_bpf__destroy;

        fd = GET_MAP_FD(tcp_windows, tcp_output);
        pb = create_pref_buffer(fd, output_tcp_win);
        if (pb == NULL) {
            ERROR("[TCPPROBE] Crate 'tcp_windows' perf buffer failed.\n");
            goto err;
        }
        prog->pbs[prog->num] = pb;
        prog->num++;
    }

    return 0;
err:
    UNLOAD(tcp_windows);
    return -1;
}

static int tcp_load_probe_rate(struct bpf_prog_s *prog, char is_load)
{
    int fd;
    struct perf_buffer *pb = NULL;

    __LOAD_PROBE(tcp_rate, err, is_load);
    if (is_load) {
        prog->skels[prog->num].skel = tcp_rate_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)tcp_rate_bpf__destroy;

        fd = GET_MAP_FD(tcp_rate, tcp_output);
        pb = create_pref_buffer(fd, output_tcp_rate);
        if (pb == NULL) {
            ERROR("[TCPPROBE] Crate 'tcp_rate' perf buffer failed.\n");
            goto err;
        }
        prog->pbs[prog->num] = pb;
        prog->num++;
    }

    return 0;
err:
    UNLOAD(tcp_rate);
    return -1;
}

static int tcp_load_probe_abn(struct bpf_prog_s *prog, char is_load)
{
    int fd;
    struct perf_buffer *pb = NULL;

    __LOAD_PROBE(tcp_abn, err, is_load);
    if (is_load) {
        prog->skels[prog->num].skel = tcp_abn_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)tcp_abn_bpf__destroy;

        fd = GET_MAP_FD(tcp_abn, tcp_output);
        pb = create_pref_buffer(fd, output_tcp_abn);
        if (pb == NULL) {
            ERROR("[TCPPROBE] Crate 'tcp_abn' perf buffer failed.\n");
            goto err;
        }
        prog->pbs[prog->num] = pb;
        prog->num++;
    }

    return 0;
err:
    UNLOAD(tcp_abn);
    return -1;
}

static int tcp_load_probe_txrx(struct bpf_prog_s *prog, char is_load)
{
    int fd;
    struct perf_buffer *pb = NULL;

    __LOAD_PROBE(tcp_tx_rx, err, is_load);
    if (is_load) {
        prog->skels[prog->num].skel = tcp_tx_rx_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)tcp_tx_rx_bpf__destroy;

        fd = GET_MAP_FD(tcp_tx_rx, tcp_output);
        pb = create_pref_buffer(fd, output_tcp_txrx);
        if (pb == NULL) {
            ERROR("[TCPPROBE] Crate 'tcp_tx_rx' perf buffer failed.\n");
            goto err;
        }
        prog->pbs[prog->num] = pb;
        prog->num++;
    }

    return 0;
err:
    UNLOAD(tcp_tx_rx);
    return -1;
}

static int tcp_load_probe_link(struct probe_params *args, struct bpf_prog_s *prog)
{
    int fd;
    struct perf_buffer *pb = NULL;

    __LOAD_PROBE(tcp_link, err, 1);
    prog->skels[prog->num].skel = tcp_link_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)tcp_link_bpf__destroy;

    fd = GET_MAP_FD(tcp_link, tcp_output);
    pb = create_pref_buffer(fd, output_tcp_syn_rtt);
    if (pb == NULL) {
        ERROR("[TCPPROBE] Crate 'tcp_link' perf buffer failed.\n");
        goto err;
    }
    prog->pbs[prog->num] = pb;
    prog->num++;

    load_args(GET_MAP_FD(tcp_link, args_map), args);

    return 0;
err:
    UNLOAD(tcp_link);
    return -1;
}

struct bpf_prog_s* tcp_load_probe(struct probe_params *args)
{
    struct bpf_prog_s *prog;
    char is_load_txrx, is_load_abn, is_load_win, is_load_rate, is_load_rtt, is_load_sockbuf;

    is_load_txrx = is_load_probe(args, TCP_PROBE_TXRX);
    is_load_abn = is_load_probe(args, TCP_PROBE_ABN);
    is_load_rate = is_load_probe(args, TCP_PROBE_RATE);
    is_load_win = is_load_probe(args, TCP_PROBE_WINDOWS);
    is_load_rtt = is_load_probe(args, TCP_PROBE_RTT);
    is_load_sockbuf = is_load_probe(args, TCP_PROBE_SOCKBUF);

    g_args = args;

    prog = alloc_bpf_prog();
    if (prog == NULL) {
        return NULL;
    }

    if (tcp_load_probe_link(args, prog)) {
        goto err;
    }

    if (tcp_load_probe_txrx(prog, is_load_txrx)) {
        goto err;
    }

    if (tcp_load_probe_abn(prog, is_load_abn)) {
        goto err;
    }

    if (tcp_load_probe_rate(prog, is_load_rate)) {
        goto err;
    }

    if (tcp_load_probe_win(prog, is_load_win)) {
        goto err;
    }

    if (tcp_load_probe_rtt(prog, is_load_rtt)) {
        goto err;
    }

    if (tcp_load_probe_sockbuf(prog, is_load_sockbuf)) {
        goto err;
    }

    return prog;

err:

    unload_bpf_prog(&prog);
    return NULL;
}

