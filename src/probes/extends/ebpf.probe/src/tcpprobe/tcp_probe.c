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
#include <time.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "ipc.h"
#include "tcpprobe.h"
#include "tcp_tracker.h"
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

#define HISTO_BUCKET_DECLARE(variable) \
    float variable##_p50 = 0.0, variable##_p90 = 0.0, variable##_p99 = 0.0

#define HISTO_BUCKET_CALC(buckets, size, variable) \
do { \
    (void)histo_bucket_value((buckets), size, HISTO_P50, &(variable##_p50)); \
    (void)histo_bucket_value((buckets), size, HISTO_P90, &(variable##_p90)); \
    (void)histo_bucket_value((buckets), size, HISTO_P99, &(variable##_p99)); \
} while (0)

static void output_tcp_abn(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker)
{
    float retrans_ratio = 0.0;
    report_tcp_abn_evt(&(tcp_mng->ipc_body.probe_param), tracker);

    if (tracker->stats[RETRANS] > 0) {
        retrans_ratio = (float)((float)tracker->stats[RETRANS] / (float)tracker->stats[SEGS_SENT]);
    }

    (void)fprintf(stdout,
        "|%s|%u|%s|%s|%s|%u|%u"
        "|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%.2f|\n",
        TCP_TBL_ABN,
        tracker->id.tgid,
        (tracker->id.role == 0) ? "server" : "client",
        tracker->src_ip,
        tracker->dst_ip,
        tracker->id.port,
        tracker->id.family,

        tracker->stats[RETRANS],
        tracker->stats[BACKLOG_DROPS],
        tracker->stats[SK_DROPS],
        tracker->stats[LOST_OUT],
        tracker->stats[SACKED_OUT],
        tracker->stats[FILTER_DROPS],
        tracker->stats[TIME_OUT],
        tracker->stats[SNDBUF_LIMIT],
        tracker->stats[RMEM_SCHEDULES],
        tracker->stats[TCP_OOM],
        tracker->stats[SEND_RSTS],
        tracker->stats[RECEIVE_RSTS],
        retrans_ratio);
    (void)fflush(stdout);
}

static void output_tcp_syn_rtt(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker)
{
    HISTO_BUCKET_DECLARE(syn_rtt);

    report_tcp_syn_rtt_evt(&(tcp_mng->ipc_body.probe_param), tracker);

    HISTO_BUCKET_CALC(tracker->syn_srtt_buckets, __MAX_RTT_SIZE, syn_rtt);

    (void)fprintf(stdout,
        "|%s|%u|%s|%s|%s|%u|%u"
        "|%.2f|%.2f|%.2f|%llu|\n",
        TCP_TBL_SYNRTT,
        tracker->id.tgid,
        (tracker->id.role == 0) ? "server" : "client",
        tracker->src_ip,
        tracker->dst_ip,
        tracker->id.port,
        tracker->id.family,

        syn_rtt_p50,
        syn_rtt_p90,
        syn_rtt_p99,
        tracker->stats[SYN_SRTT]);
    (void)fflush(stdout);
}

static void output_tcp_rtt(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker)
{
    HISTO_BUCKET_DECLARE(srtt);
    HISTO_BUCKET_DECLARE(rcv_rtt);

    HISTO_BUCKET_CALC(tracker->srtt_buckets, __MAX_RTT_SIZE, srtt);
    HISTO_BUCKET_CALC(tracker->rcv_rtt_buckets, __MAX_RTT_SIZE, rcv_rtt);

    (void)fprintf(stdout,
        "|%s|%u|%s|%s|%s|%u|%u"
        "|%.2f|%.2f|%.2f|%.2f|%.2f|%.2f|\n",
        TCP_TBL_RTT,
        tracker->id.tgid,
        (tracker->id.role == 0) ? "server" : "client",
        tracker->src_ip,
        tracker->dst_ip,
        tracker->id.port,
        tracker->id.family,

        srtt_p50,
        srtt_p90,
        srtt_p99,
        rcv_rtt_p50,
        rcv_rtt_p90,
        rcv_rtt_p99);
    (void)fflush(stdout);
}

static void output_tcp_txrx(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker)
{
    (void)fprintf(stdout,
        "|%s|%u|%s|%s|%s|%u|%u"
        "|%llu|%llu|%llu|%llu|\n",
        TCP_TBL_TXRX,
        tracker->id.tgid,
        (tracker->id.role == 0) ? "server" : "client",
        tracker->src_ip,
        tracker->dst_ip,
        tracker->id.port,
        tracker->id.family,

        tracker->stats[BYTES_RECV],
        tracker->stats[BYTES_SENT],
        tracker->stats[SEGS_RECV],
        tracker->stats[SEGS_SENT]);
    (void)fflush(stdout);
}

static void output_tcp_win(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker)
{
    HISTO_BUCKET_DECLARE(snd_cwnd);
    HISTO_BUCKET_DECLARE(notsent_bytes);
    HISTO_BUCKET_DECLARE(notack_bytes);
    HISTO_BUCKET_DECLARE(reordering);
    HISTO_BUCKET_DECLARE(snd_wnd);
    HISTO_BUCKET_DECLARE(rcv_wnd);
    HISTO_BUCKET_DECLARE(avl_snd_wnd);

    HISTO_BUCKET_CALC(tracker->snd_cwnd_buckets, __MAX_WIND_SIZE, snd_cwnd);
    HISTO_BUCKET_CALC(tracker->not_sent_buckets, __MAX_WIND_SIZE, notsent_bytes);
    HISTO_BUCKET_CALC(tracker->not_acked_buckets, __MAX_WIND_SIZE, notack_bytes);
    HISTO_BUCKET_CALC(tracker->reordering_buckets, __MAX_WIND_SIZE, reordering);
    HISTO_BUCKET_CALC(tracker->snd_wnd_buckets, __MAX_WIND_SIZE, snd_wnd);
    HISTO_BUCKET_CALC(tracker->rcv_wnd_buckets, __MAX_WIND_SIZE, rcv_wnd);
    HISTO_BUCKET_CALC(tracker->avl_snd_wnd_buckets, __MAX_WIND_SIZE, avl_snd_wnd);

    if (tracker->stats[ZERO_WIN_RX] > 0) {
        tracker->zero_win_rx_ratio = (float)((float)tracker->stats[ZERO_WIN_RX] / (float)tracker->stats[BYTES_RECV]);
    }

    if (tracker->stats[ZERO_WIN_TX] > 0) {
        tracker->zero_win_tx_ratio = (float)((float)tracker->stats[ZERO_WIN_TX] / (float)tracker->stats[BYTES_SENT]);
    }

    report_tcp_win_evt(&(tcp_mng->ipc_body.probe_param), tracker);

    (void)fprintf(stdout,
        "|%s|%u|%s|%s|%s|%u|%u"
        "|%.0f|%.0f|%.0f|%.0f|%.0f|%.0f|"
        "|%.0f|%.0f|%.0f|%.0f|%.0f|%.0f|"
        "|%.0f|%.0f|%.0f|%.0f|%.0f|%.0f|"
        "|%.0f|%.0f|%.0f|"
        "|%.2f|%.2f|\n",
        TCP_TBL_WIN,
        tracker->id.tgid,
        (tracker->id.role == 0) ? "server" : "client",
        tracker->src_ip,
        tracker->dst_ip,
        tracker->id.port,
        tracker->id.family,

        snd_cwnd_p50, snd_cwnd_p90, snd_cwnd_p99, notsent_bytes_p50, notsent_bytes_p90, notsent_bytes_p99,
        notack_bytes_p50, notack_bytes_p90, notack_bytes_p99, reordering_p50, reordering_p90, reordering_p99,
        snd_wnd_p50, snd_wnd_p90, snd_wnd_p99, rcv_wnd_p50, rcv_wnd_p90, rcv_wnd_p99,
        avl_snd_wnd_p50, avl_snd_wnd_p90, avl_snd_wnd_p99,
        tracker->zero_win_rx_ratio, tracker->zero_win_tx_ratio);
    (void)fflush(stdout);
}

static void output_tcp_rate(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker)
{
    HISTO_BUCKET_DECLARE(rto);
    HISTO_BUCKET_DECLARE(ato);

    HISTO_BUCKET_CALC(tracker->rto_buckets, __MAX_RTO_SIZE, rto);
    HISTO_BUCKET_CALC(tracker->ato_buckets, __MAX_RTO_SIZE, ato);

    (void)fprintf(stdout,
        "|%s|%u|%s|%s|%s|%u|%u"
        "|%.0f|%.0f|%.0f|%.0f|%.0f|%.0f|\n",
        TCP_TBL_RATE,
        tracker->id.tgid,
        (tracker->id.role == 0) ? "server" : "client",
        tracker->src_ip,
        tracker->dst_ip,
        tracker->id.port,
        tracker->id.family,

        rto_p50, rto_p90, rto_p99, ato_p50, ato_p90, ato_p99);
    (void)fflush(stdout);
}

static void output_tcp_sockbuf(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker)
{
    HISTO_BUCKET_DECLARE(rcv_buf);
    HISTO_BUCKET_DECLARE(snd_buf);

    HISTO_BUCKET_CALC(tracker->rcv_buf_buckets, __MAX_SOCKBUF_SIZE, rcv_buf);
    HISTO_BUCKET_CALC(tracker->snd_buf_buckets, __MAX_SOCKBUF_SIZE, snd_buf);

    (void)fprintf(stdout,
        "|%s|%u|%s|%s|%s|%u|%u"
        "|%.0f|%.0f|%.0f|%.0f|%.0f|%.0f|\n",
        TCP_TBL_SOCKBUF,
        tracker->id.tgid,
        (tracker->id.role == 0) ? "server" : "client",
        tracker->src_ip,
        tracker->dst_ip,
        tracker->id.port,
        tracker->id.family,

        rcv_buf_p50, rcv_buf_p90, rcv_buf_p99, snd_buf_p50, snd_buf_p90, snd_buf_p99);
    (void)fflush(stdout);
}

static void reset_tcp_tracker_stats(struct tcp_tracker_s *tracker)
{
    histo_bucket_reset(tracker->snd_wnd_buckets, __MAX_WIND_SIZE);
    histo_bucket_reset(tracker->rcv_wnd_buckets, __MAX_WIND_SIZE);
    histo_bucket_reset(tracker->avl_snd_wnd_buckets, __MAX_WIND_SIZE);
    histo_bucket_reset(tracker->snd_cwnd_buckets, __MAX_WIND_SIZE);
    histo_bucket_reset(tracker->not_sent_buckets, __MAX_WIND_SIZE);
    histo_bucket_reset(tracker->not_acked_buckets, __MAX_WIND_SIZE);
    histo_bucket_reset(tracker->reordering_buckets, __MAX_WIND_SIZE);

    histo_bucket_reset(tracker->srtt_buckets, __MAX_RTT_SIZE);
    histo_bucket_reset(tracker->rcv_rtt_buckets, __MAX_RTT_SIZE);
    histo_bucket_reset(tracker->syn_srtt_buckets, __MAX_RTT_SIZE);

    histo_bucket_reset(tracker->rto_buckets, __MAX_RTO_SIZE);
    histo_bucket_reset(tracker->ato_buckets, __MAX_RTO_SIZE);

    histo_bucket_reset(tracker->snd_buf_buckets, __MAX_SOCKBUF_SIZE);
    histo_bucket_reset(tracker->rcv_buf_buckets, __MAX_SOCKBUF_SIZE);

    memset(&(tracker->stats), 0, sizeof(u64) * __MAX_STATS);
    tracker->zero_win_rx_ratio = 0.0;
    tracker->zero_win_tx_ratio = 0.0;
    return;
}

static void output_tcp_metrics(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker)
{
    char need_reset = 0;
    u32 flags = tracker->report_flags & TCP_PROBE_ALL;

    if (flags & TCP_PROBE_ABN) {
        need_reset = 1;
        output_tcp_abn(tcp_mng, tracker);
    }

    if (flags & TCP_PROBE_SRTT) {
        need_reset = 1;
        output_tcp_syn_rtt(tcp_mng, tracker);
    }

    if (flags & TCP_PROBE_WINDOWS) {
        need_reset = 1;
        output_tcp_win(tcp_mng, tracker);
    }

    if (flags & TCP_PROBE_RTT) {
        need_reset = 1;
        output_tcp_rtt(tcp_mng, tracker);
    }

    if (flags & TCP_PROBE_TXRX) {
        need_reset = 1;
        output_tcp_txrx(tcp_mng, tracker);
    }

    if (flags & TCP_PROBE_SOCKBUF) {
        need_reset = 1;
        output_tcp_sockbuf(tcp_mng, tracker);
    }

    if (flags & TCP_PROBE_RATE) {
        need_reset = 1;
        output_tcp_rate(tcp_mng, tracker);
    }
    tracker->report_flags = 0;
    if (need_reset) {
        reset_tcp_tracker_stats(tracker);
    }
    return;
}

#if 1

static void proc_tcp_txrx(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker, const struct tcp_tx_rx *data)
{
    u32 segs_out_delta, segs_in_delta;

    tracker->stats[BYTES_SENT] += data->tx;
    tracker->stats[BYTES_RECV] += data->rx;

    segs_in_delta = (data->segs_in >= data->last_time_segs_in) ?
        (data->segs_in - data->last_time_segs_in) : data->segs_in;
    segs_out_delta = (data->segs_out >= data->last_time_segs_out) ?
        (data->segs_out - data->last_time_segs_out) : data->segs_out;
    tracker->stats[SEGS_SENT] += segs_out_delta;
    tracker->stats[SEGS_RECV] += segs_in_delta;
    tracker->report_flags |= TCP_PROBE_TXRX;
    return;
}

static void proc_tcp_abnormal(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker, const struct tcp_abn *data)
{
    u32 sk_drops_delta, lost_out_delta, sacked_out_delta;

    sk_drops_delta = (data->sk_drops >= data->last_time_sk_drops) ?
        (data->sk_drops - data->last_time_sk_drops) : data->sk_drops;

    lost_out_delta = (data->lost_out >= data->last_time_lost_out) ?
        (data->lost_out - data->last_time_lost_out) : data->lost_out;

    sacked_out_delta = (data->sacked_out >= data->last_time_sacked_out) ?
        (data->sacked_out - data->last_time_sacked_out) : data->sacked_out;

    tracker->stats[RETRANS] += data->total_retrans;
    tracker->stats[BACKLOG_DROPS] += data->backlog_drops;
    tracker->stats[FILTER_DROPS] += data->filter_drops;
    tracker->stats[SK_DROPS] += sk_drops_delta;
    tracker->stats[LOST_OUT] += lost_out_delta;
    tracker->stats[SACKED_OUT] += sacked_out_delta;
    tracker->stats[TIME_OUT] += data->tmout;
    tracker->stats[SNDBUF_LIMIT] += data->sndbuf_limit;
    tracker->stats[RMEM_SCHEDULES] += data->rmem_scheduls;
    tracker->stats[TCP_OOM] += data->tcp_oom;
    tracker->stats[SEND_RSTS] += data->send_rsts;
    tracker->stats[RECEIVE_RSTS] += data->receive_rsts;
    tracker->report_flags |= TCP_PROBE_ABN;
    return;
}

static void proc_tcp_windows(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker, const struct tcp_windows *data)
{
    (void)histo_bucket_add_value(tracker->snd_wnd_buckets, __MAX_WIND_SIZE, data->tcpi_snd_wnd);
    (void)histo_bucket_add_value(tracker->rcv_wnd_buckets, __MAX_WIND_SIZE, data->tcpi_rcv_wnd);
    (void)histo_bucket_add_value(tracker->avl_snd_wnd_buckets, __MAX_WIND_SIZE, data->tcpi_avl_snd_wnd);
    (void)histo_bucket_add_value(tracker->snd_cwnd_buckets, __MAX_WIND_SIZE, data->tcpi_snd_cwnd);

    (void)histo_bucket_add_value(tracker->not_sent_buckets, __MAX_WIND_SIZE, data->tcpi_notsent_bytes);
    (void)histo_bucket_add_value(tracker->not_acked_buckets, __MAX_WIND_SIZE, data->tcpi_notack_bytes);
    (void)histo_bucket_add_value(tracker->reordering_buckets, __MAX_WIND_SIZE, data->tcpi_reordering);

    if (data->tcpi_snd_wnd == 0) {
        tracker->stats[ZERO_WIN_TX]++;
    }

    if (data->tcpi_rcv_wnd == 0) {
        tracker->stats[ZERO_WIN_RX]++;
    }
    tracker->report_flags |= TCP_PROBE_WINDOWS;
    return;
}

static void proc_tcp_rtt(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker, const struct tcp_rtt *data)
{
    (void)histo_bucket_add_value(tracker->srtt_buckets, __MAX_RTT_SIZE, data->tcpi_srtt);
    (void)histo_bucket_add_value(tracker->rcv_rtt_buckets, __MAX_RTT_SIZE, data->tcpi_rcv_rtt);
    tracker->report_flags |= TCP_PROBE_RTT;
    return;
}

static void proc_tcp_srtt(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker, const struct tcp_srtt *data)
{
    (void)histo_bucket_add_value(tracker->syn_srtt_buckets, __MAX_RTT_SIZE, data->syn_srtt);
    tracker->stats[SYN_SRTT] = max(tracker->stats[SYN_SRTT], data->syn_srtt);
    tracker->report_flags |= TCP_PROBE_SRTT;
    return;
}

static void proc_tcp_rate(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker, const struct tcp_rate *data)
{
    (void)histo_bucket_add_value(tracker->rto_buckets, __MAX_RTO_SIZE, data->tcpi_rto);
    (void)histo_bucket_add_value(tracker->ato_buckets, __MAX_RTO_SIZE, data->tcpi_ato);
    tracker->report_flags |= TCP_PROBE_RATE;
    return;
}

static void proc_tcp_sockbuf(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker, const struct tcp_sockbuf *data)
{
    (void)histo_bucket_add_value(tracker->rcv_buf_buckets, __MAX_SOCKBUF_SIZE, data->sk_rcvbuf);
    (void)histo_bucket_add_value(tracker->snd_buf_buckets, __MAX_SOCKBUF_SIZE, data->sk_sndbuf);
    tracker->report_flags |= TCP_PROBE_SOCKBUF;
    return;
}

static char is_tracker_inactive(struct tcp_tracker_s *tracker)
{
#define __INACTIVE_TIME_SECS     (5 * 60)       // 5min
    time_t current = (time_t)time(NULL);
    time_t secs;

    if (current > tracker->last_rcv_data) {
        secs = current - tracker->last_rcv_data;
        if (secs >= __INACTIVE_TIME_SECS) {
            return 1;
        }
    }

    return 0;
}

static char is_track_tmout(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker)
{
    time_t current = (time_t)time(NULL);
    time_t secs;

    if (current > tracker->last_report) {
        secs = current - tracker->last_report;
        if (secs >= tcp_mng->ipc_body.probe_param.period) {
            tracker->last_report = current;
            return 1;
        }
    }

    if (current < tracker->last_report) {
        tracker->last_report = current;
    }

    return 0;
}

static void proc_tcp_metrics_evt(void *ctx, int cpu, void *data, __u32 size)
{
    struct tcp_tracker_s* tracker = NULL;
    struct tcp_metrics_s *metrics  = (struct tcp_metrics_s *)data;
    struct tcp_mng_s *tcp_mng = ctx;
    u32 metrics_flags = metrics->report_flags & TCP_PROBE_ALL;

    tracker = get_tcp_tracker(tcp_mng, (const void *)(&(metrics->link)));
    if (tracker == NULL) {
        return;
    }

    tracker->last_rcv_data = (time_t)time(NULL);

    if (metrics_flags & TCP_PROBE_SRTT) {
        proc_tcp_srtt(tcp_mng, tracker, (const struct tcp_srtt *)(&(metrics->srtt_stats)));
    }

    if (metrics_flags & TCP_PROBE_ABN) {
        proc_tcp_abnormal(tcp_mng, tracker, (const struct tcp_abn *)(&(metrics->abn_stats)));
    }

    if (metrics_flags & TCP_PROBE_WINDOWS) {
        proc_tcp_windows(tcp_mng, tracker, (const struct tcp_windows *)(&(metrics->win_stats)));
    }

    if (metrics_flags & TCP_PROBE_RTT) {
        proc_tcp_rtt(tcp_mng, tracker, (const struct tcp_rtt *)(&(metrics->rtt_stats)));
    }

    if (metrics_flags & TCP_PROBE_TXRX) {
        proc_tcp_txrx(tcp_mng, tracker, (const struct tcp_tx_rx *)(&(metrics->tx_rx_stats)));
    }

    if (metrics_flags & TCP_PROBE_SOCKBUF) {
        proc_tcp_sockbuf(tcp_mng, tracker, (const struct tcp_sockbuf *)(&(metrics->sockbuf_stats)));
    }

    if (metrics_flags & TCP_PROBE_RATE) {
        proc_tcp_rate(tcp_mng, tracker, (const struct tcp_rate *)(&(metrics->rate_stats)));
    }

    if (is_track_tmout(tcp_mng, tracker)) {
        output_tcp_metrics(tcp_mng, tracker);
    }

    return;
}

#endif

static int tcp_load_probe_sockbuf(struct tcp_mng_s *tcp_mng, struct bpf_prog_s *prog, char is_load)
{
    int fd;
    struct perf_buffer *pb = NULL;

    __LOAD_PROBE(tcp_sockbuf, err, is_load);
    if (is_load) {
        prog->skels[prog->num].skel = tcp_sockbuf_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)tcp_sockbuf_bpf__destroy;

        fd = GET_MAP_FD(tcp_sockbuf, tcp_output);
        pb = create_pref_buffer3(fd, proc_tcp_metrics_evt, NULL, tcp_mng);
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

static int tcp_load_probe_rtt(struct tcp_mng_s *tcp_mng, struct bpf_prog_s *prog, char is_load)
{
    int fd;
    struct perf_buffer *pb = NULL;

    __LOAD_PROBE(tcp_rtt, err, is_load);
    if (is_load) {
        prog->skels[prog->num].skel = tcp_rtt_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)tcp_rtt_bpf__destroy;

        fd = GET_MAP_FD(tcp_rtt, tcp_output);
        pb = create_pref_buffer3(fd, proc_tcp_metrics_evt, NULL, tcp_mng);
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

static int tcp_load_probe_win(struct tcp_mng_s *tcp_mng, struct bpf_prog_s *prog, char is_load)
{
    int fd;
    struct perf_buffer *pb = NULL;

    __LOAD_PROBE(tcp_windows, err, is_load);
    if (is_load) {
        prog->skels[prog->num].skel = tcp_windows_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)tcp_windows_bpf__destroy;

        fd = GET_MAP_FD(tcp_windows, tcp_output);
        pb = create_pref_buffer3(fd, proc_tcp_metrics_evt, NULL, tcp_mng);
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

static int tcp_load_probe_rate(struct tcp_mng_s *tcp_mng, struct bpf_prog_s *prog, char is_load)
{
    int fd;
    struct perf_buffer *pb = NULL;

    __LOAD_PROBE(tcp_rate, err, is_load);
    if (is_load) {
        prog->skels[prog->num].skel = tcp_rate_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)tcp_rate_bpf__destroy;

        fd = GET_MAP_FD(tcp_rate, tcp_output);
        pb = create_pref_buffer3(fd, proc_tcp_metrics_evt, NULL, tcp_mng);
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

static int tcp_load_probe_abn(struct tcp_mng_s *tcp_mng, struct bpf_prog_s *prog, char is_load)
{
    int fd;
    struct perf_buffer *pb = NULL;

    __LOAD_PROBE(tcp_abn, err, is_load);
    if (is_load) {
        prog->skels[prog->num].skel = tcp_abn_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)tcp_abn_bpf__destroy;

        fd = GET_MAP_FD(tcp_abn, tcp_output);
        pb = create_pref_buffer3(fd, proc_tcp_metrics_evt, NULL, tcp_mng);
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

static int tcp_load_probe_txrx(struct tcp_mng_s *tcp_mng, struct bpf_prog_s *prog, char is_load)
{
    int fd;
    struct perf_buffer *pb = NULL;

    __LOAD_PROBE(tcp_tx_rx, err, is_load);
    if (is_load) {
        prog->skels[prog->num].skel = tcp_tx_rx_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)tcp_tx_rx_bpf__destroy;

        fd = GET_MAP_FD(tcp_tx_rx, tcp_output);
        pb = create_pref_buffer3(fd, proc_tcp_metrics_evt, NULL, tcp_mng);
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

static void load_args(int args_fd, struct probe_params* params)
{
    u32 key = 0;
    struct tcp_args_s args = {0};

    args.cport_flag = (u32)params->cport_flag;
    args.period = NS(params->period);

    (void)bpf_map_update_elem(args_fd, &key, &args, BPF_ANY);
}

static int tcp_load_probe_link(struct tcp_mng_s *tcp_mng, struct probe_params *args, struct bpf_prog_s *prog)
{
    int fd;
    struct perf_buffer *pb = NULL;

    __LOAD_PROBE(tcp_link, err, 1);
    prog->skels[prog->num].skel = tcp_link_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)tcp_link_bpf__destroy;

    fd = GET_MAP_FD(tcp_link, tcp_output);
    pb = create_pref_buffer3(fd, proc_tcp_metrics_evt, NULL, tcp_mng);
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

int tcp_load_probe(struct tcp_mng_s *tcp_mng, struct ipc_body_s *ipc_body, struct bpf_prog_s **new_prog)
{
    char is_load = 0;
    struct bpf_prog_s *prog;
    char is_load_txrx, is_load_abn, is_load_win, is_load_rate, is_load_rtt, is_load_sockbuf;

    is_load_txrx = ipc_body->probe_range_flags & PROBE_RANGE_TCP_STATS;
    is_load_abn = ipc_body->probe_range_flags & PROBE_RANGE_TCP_ABNORMAL;
    is_load_rate = ipc_body->probe_range_flags & PROBE_RANGE_TCP_RATE;
    is_load_win = ipc_body->probe_range_flags & PROBE_RANGE_TCP_WINDOWS;
    is_load_rtt = ipc_body->probe_range_flags & PROBE_RANGE_TCP_RTT;
    is_load_sockbuf = ipc_body->probe_range_flags & PROBE_RANGE_TCP_SOCKBUF;

    is_load = is_load_txrx | is_load_abn | is_load_rate | is_load_win | is_load_rtt | is_load_sockbuf;
    if (!is_load) {
        return 0;
    }

    prog = alloc_bpf_prog();
    if (prog == NULL) {
        return -1;
    }

    if (tcp_load_probe_link(tcp_mng, &(ipc_body->probe_param), prog)) {
        goto err;
    }

    if (tcp_load_probe_txrx(tcp_mng, prog, is_load_txrx)) {
        goto err;
    }

    if (tcp_load_probe_abn(tcp_mng, prog, is_load_abn)) {
        goto err;
    }

    if (tcp_load_probe_rate(tcp_mng, prog, is_load_rate)) {
        goto err;
    }

    if (tcp_load_probe_win(tcp_mng, prog, is_load_win)) {
        goto err;
    }

    if (tcp_load_probe_rtt(tcp_mng, prog, is_load_rtt)) {
        goto err;
    }

    if (tcp_load_probe_sockbuf(tcp_mng, prog, is_load_sockbuf)) {
        goto err;
    }

    INFO("[TCPPROBE]: Successfully load ebpf prog.\n");
    *new_prog = prog;
    return 0;

err:
    unload_bpf_prog(&prog);
    return -1;
}

void scan_tcp_trackers(struct tcp_mng_s *tcp_mng)
{
    struct tcp_tracker_s *tracker, *tmp;

    H_ITER(tcp_mng->trackers, tracker, tmp) {
        if (is_tracker_inactive(tracker)) {
            H_DEL(tcp_mng->trackers, tracker);
            destroy_tcp_tracker(tracker);
            tcp_mng->tcp_tracker_count--;
        } else {
            if (is_track_tmout(tcp_mng, tracker)) {
                output_tcp_metrics(tcp_mng, tracker);
            }
        }
    }
}

