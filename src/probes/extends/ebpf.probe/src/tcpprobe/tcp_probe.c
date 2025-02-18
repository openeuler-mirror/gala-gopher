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
#include "feat_probe.h"
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
#include "tcp_delay.skel.h"

#define TCP_TBL_METRIC  "tcp_metric"
#define TCP_TBL_DELAY   "proc_flow_perf"

static int is_load_probe(struct tcp_mng_s *tcp_mng, u32 probe_load_flag)
{
    if (tcp_mng->ipc_body.probe_range_flags & probe_load_flag) {
        return 1;
    }
    return 0;
}

static void output_tcp_abn(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker,
                           char *buffer, size_t size)
{
    float retrans_ratio = 0.0;
    report_tcp_abn_evt(&(tcp_mng->ipc_body.probe_param), tracker);

    if (tracker->stats[RETRANS] > 0) {
        retrans_ratio = tracker->stats[SEGS_SENT] == 0 ? 0.00f : (float) ((float) tracker->stats[RETRANS] /
                                                                          (float) tracker->stats[SEGS_SENT]);
    }

    (void)snprintf(buffer, size,
        "|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%.2f",

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
}

static void output_tcp_syn_rtt(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker,
                               char *buffer, size_t size)
{
    char *syn_srtt_historm = tcp_mng->historms[TCP_HISTORM_RTT_SYN_SRTT];

    syn_srtt_historm[0] = 0;

    if (serialize_histo(tcp_mng->histo_attr->syn_srtt_buckets, &tracker->syn_srtt_buckets, __MAX_RTT_SIZE, syn_srtt_historm, MAX_HISTO_SERIALIZE_SIZE)) {
        return;
    }

    report_tcp_syn_rtt_evt(&(tcp_mng->ipc_body.probe_param), tracker);

    (void)snprintf(buffer, size,
        "|%s|%llu",
        syn_srtt_historm,
        tracker->stats[SYN_SRTT_MAX]);
}

static void output_tcp_rtt(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker,
                           char *buffer, size_t size)
{
    char *srtt_historm = tcp_mng->historms[TCP_HISTORM_RTT_SRTT];
    char *rcv_rtt_historm = tcp_mng->historms[TCP_HISTORM_RTT_RCV_RTT];

    srtt_historm[0] = 0;
    rcv_rtt_historm[0] = 0;

    if (serialize_histo(tcp_mng->histo_attr->srtt_buckets, &tracker->srtt_buckets, __MAX_RTT_SIZE, srtt_historm, MAX_HISTO_SERIALIZE_SIZE)) {
        return;
    }
    if (serialize_histo(tcp_mng->histo_attr->rcv_rtt_buckets, &tracker->rcv_rtt_buckets, __MAX_RTT_SIZE, rcv_rtt_historm, MAX_HISTO_SERIALIZE_SIZE)) {
        return;
    }

    (void)snprintf(buffer, size,
        "|%s|%s",
        srtt_historm,
        rcv_rtt_historm);
}

static void output_tcp_txrx(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker,
                            char *buffer, size_t size)
{
    (void)snprintf(buffer, size,
        "|%llu|%llu|%llu|%llu",
        tracker->stats[BYTES_RECV],
        tracker->stats[BYTES_SENT],
        tracker->stats[SEGS_RECV],
        tracker->stats[SEGS_SENT]);
}

static void output_tcp_win(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker,
                           char *buffer, size_t size)
{
    char *snd_cwnd_historm = tcp_mng->historms[TCP_HISTORM_WIND_SND_CWND];
    char *not_sent_historm = tcp_mng->historms[TCP_HISTORM_WIND_NOT_SENT];
    char *not_acked_historm = tcp_mng->historms[TCP_HISTORM_WIND_ACKED];
    char *reordering_historm = tcp_mng->historms[TCP_HISTORM_WIND_REORDERING];
    char *snd_wind_historm = tcp_mng->historms[TCP_HISTORM_WIND_SND];
    char *rcv_wind_historm = tcp_mng->historms[TCP_HISTORM_WIND_RCV];
    char *avl_snd_wind_historm = tcp_mng->historms[TCP_HISTORM_WIND_AVL_SND];
    struct histo_attr_single *range_attr = tcp_mng->histo_attr;

    snd_cwnd_historm[0] = 0;
    not_sent_historm[0] = 0;
    not_acked_historm[0] = 0;
    reordering_historm[0] = 0;
    snd_wind_historm[0] = 0;
    rcv_wind_historm[0] = 0;
    avl_snd_wind_historm[0] = 0;

    if (serialize_histo(range_attr->snd_cwnd_buckets, &tracker->snd_cwnd_buckets, __MAX_WIND_SIZE, snd_cwnd_historm, MAX_HISTO_SERIALIZE_SIZE)) {
        return;
    }
    if (serialize_histo(range_attr->not_sent_buckets, &tracker->not_sent_buckets, __MAX_WIND_SIZE, not_sent_historm, MAX_HISTO_SERIALIZE_SIZE)) {
        return;
    }
    if (serialize_histo(range_attr->not_acked_buckets, &tracker->not_acked_buckets, __MAX_WIND_SIZE, not_acked_historm, MAX_HISTO_SERIALIZE_SIZE)) {
        return;
    }
    if (serialize_histo(range_attr->reordering_buckets, &tracker->reordering_buckets, __MAX_WIND_SIZE, reordering_historm, MAX_HISTO_SERIALIZE_SIZE)) {
        return;
    }
    if (serialize_histo(range_attr->snd_wnd_buckets, &tracker->snd_wnd_buckets, __MAX_WIND_SIZE, snd_wind_historm, MAX_HISTO_SERIALIZE_SIZE)) {
        return;
    }
    if (serialize_histo(range_attr->rcv_wnd_buckets, &tracker->rcv_wnd_buckets, __MAX_WIND_SIZE, rcv_wind_historm, MAX_HISTO_SERIALIZE_SIZE)) {
        return;
    }
    if (serialize_histo(range_attr->avl_snd_wnd_buckets, &tracker->avl_snd_wnd_buckets, __MAX_WIND_SIZE, avl_snd_wind_historm, MAX_HISTO_SERIALIZE_SIZE)) {
        return;
    }

    if (tracker->stats[ZERO_WIN_RX] > 0) {
        tracker->zero_win_rx_ratio = tracker->stats[BYTES_RECV] == 0 ? 0.00f :
                                     (float) ((float) tracker->stats[ZERO_WIN_RX] / (float) tracker->stats[BYTES_RECV]);
    }

    if (tracker->stats[ZERO_WIN_TX] > 0) {
        tracker->zero_win_tx_ratio = tracker->stats[BYTES_SENT] == 0 ? 0.00f :
                                     (float) ((float) tracker->stats[ZERO_WIN_TX] / (float) tracker->stats[BYTES_SENT]);
    }

    report_tcp_win_evt(&(tcp_mng->ipc_body.probe_param), tracker);

    (void)snprintf(buffer, size,
        "|%s|%s|%s|%s|%s|%s|%s"
        "|%llu|%llu"
        "|%.2f|%.2f",
        snd_cwnd_historm,
        not_sent_historm,
        not_acked_historm,
        reordering_historm,
        snd_wind_historm,
        rcv_wind_historm,
        avl_snd_wind_historm,

        tracker->stats[ZERO_WIN_RX],
        tracker->stats[ZERO_WIN_TX],

        tracker->zero_win_rx_ratio, tracker->zero_win_tx_ratio);
}

static void output_tcp_rate(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker,
                            char *buffer, size_t size)
{
    char *rto_historm = tcp_mng->historms[TCP_HISTORM_RTO];
    char *ato_historm = tcp_mng->historms[TCP_HISTORM_ATO];

    rto_historm[0] = 0;
    ato_historm[0] = 0;

    if (serialize_histo(tcp_mng->histo_attr->rto_buckets, &tracker->rto_buckets, __MAX_RTO_SIZE, rto_historm, MAX_HISTO_SERIALIZE_SIZE)) {
        return;
    }
    if (serialize_histo(tcp_mng->histo_attr->ato_buckets, &tracker->ato_buckets, __MAX_RTO_SIZE, ato_historm, MAX_HISTO_SERIALIZE_SIZE)) {
        return;
    }

    (void)snprintf(buffer, size,
        "|%s|%s",
        rto_historm, ato_historm);
}

static void output_tcp_sockbuf(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker,
                               char *buffer, size_t size)
{
    char *rcv_buf_historm = tcp_mng->historms[TCP_HISTORM_SOCKBUF_RCV];
    char *snd_buf_historm = tcp_mng->historms[TCP_HISTORM_SOCKBUF_SND];

    rcv_buf_historm[0] = 0;
    snd_buf_historm[0] = 0;

    if (serialize_histo(tcp_mng->histo_attr->rcv_buf_buckets, &tracker->rcv_buf_buckets, __MAX_SOCKBUF_SIZE, rcv_buf_historm, MAX_HISTO_SERIALIZE_SIZE)) {
        return;
    }
    if (serialize_histo(tcp_mng->histo_attr->snd_buf_buckets, &tracker->snd_buf_buckets, __MAX_SOCKBUF_SIZE, snd_buf_historm, MAX_HISTO_SERIALIZE_SIZE)) {
        return;
    }

    (void)snprintf(buffer, size,
        "|%s|%s",
        rcv_buf_historm, snd_buf_historm);
}

static void output_tcp_flow_delay(struct tcp_mng_s *tcp_mng, struct tcp_flow_tracker_s *tracker)
{
    char *send_delay_buf = tcp_mng->historms[TCP_HISTORM_DELAY_TX];
    char *recv_delay_buf = tcp_mng->historms[TCP_HISTORM_DELAY_RX];

    send_delay_buf[0] = 0;
    recv_delay_buf[0] = 0;
    if (serialize_histo(tcp_mng->histo_attr->send_delay_buckets, &tracker->send_delay_buckets, __MAX_DELAY_SIZE, send_delay_buf, MAX_HISTO_SERIALIZE_SIZE)) {
        return;
    }
    if (serialize_histo(tcp_mng->histo_attr->recv_delay_buckets, &tracker->recv_delay_buckets, __MAX_DELAY_SIZE, recv_delay_buf, MAX_HISTO_SERIALIZE_SIZE)) {
        return;
    }

    (void)fprintf(stdout,
        "|%s|%u|%s|%s|%u"
        "|%s|%s|\n",
        TCP_TBL_DELAY,
        tracker->id.tgid,
        (tracker->id.role == 0) ? "server" : "client",
        tracker->id.remote_ip,
        tracker->id.port,

        recv_delay_buf, send_delay_buf);
    (void)fflush(stdout);
}

static void reset_tcp_abn_stats(struct tcp_tracker_s *tracker)
{
    enum tcp_stats_t tcp_abn_stats_arr[] = {RETRANS, BACKLOG_DROPS, SK_DROPS,
                                            LOST_OUT, SACKED_OUT, FILTER_DROPS,
                                            TIME_OUT, SNDBUF_LIMIT, RMEM_SCHEDULES,
                                            TCP_OOM, SEND_RSTS, RECEIVE_RSTS};

    for (int i = 0; i < sizeof(tcp_abn_stats_arr) / sizeof(tcp_abn_stats_arr[0]); i++) {
        tracker->stats[tcp_abn_stats_arr[i]] = 0;
    }
}

static void reset_tcp_syn_rtt_stats(struct tcp_tracker_s *tracker)
{
    histo_bucket_reset(&tracker->syn_srtt_buckets, __MAX_RTT_SIZE);
    tracker->stats[SYN_SRTT_MAX] = 0;
}

static void reset_tcp_win_stats(struct tcp_tracker_s *tracker)
{
    histo_bucket_reset(&tracker->snd_wnd_buckets, __MAX_WIND_SIZE);
    histo_bucket_reset(&tracker->rcv_wnd_buckets, __MAX_WIND_SIZE);
    histo_bucket_reset(&tracker->avl_snd_wnd_buckets, __MAX_WIND_SIZE);
    histo_bucket_reset(&tracker->snd_cwnd_buckets, __MAX_WIND_SIZE);
    histo_bucket_reset(&tracker->not_sent_buckets, __MAX_WIND_SIZE);
    histo_bucket_reset(&tracker->not_acked_buckets, __MAX_WIND_SIZE);
    histo_bucket_reset(&tracker->reordering_buckets, __MAX_WIND_SIZE);

    tracker->stats[ZERO_WIN_RX] = 0;
    tracker->stats[ZERO_WIN_TX] = 0;
    tracker->zero_win_rx_ratio = 0.0f;
    tracker->zero_win_tx_ratio = 0.0f;
}

static void reset_tcp_rtt_stats(struct tcp_tracker_s *tracker)
{
    histo_bucket_reset(&tracker->srtt_buckets, __MAX_RTT_SIZE);
    histo_bucket_reset(&tracker->rcv_rtt_buckets, __MAX_RTT_SIZE);
}

static void reset_tcp_txrx_stats(struct tcp_tracker_s *tracker)
{
    tracker->stats[BYTES_RECV] = 0;
    tracker->stats[BYTES_SENT] = 0;
    tracker->stats[SEGS_RECV] = 0;
    tracker->stats[SEGS_SENT] = 0;
}

static void reset_tcp_sockbuf_stats(struct tcp_tracker_s *tracker)
{
    histo_bucket_reset(&tracker->snd_buf_buckets, __MAX_SOCKBUF_SIZE);
    histo_bucket_reset(&tracker->rcv_buf_buckets, __MAX_SOCKBUF_SIZE);
}

static void reset_tcp_rate_stats(struct tcp_tracker_s *tracker)
{
    histo_bucket_reset(&tracker->rto_buckets, __MAX_RTO_SIZE);
    histo_bucket_reset(&tracker->ato_buckets, __MAX_RTO_SIZE);
}

static void reset_tcp_flow_tracker_stats(struct tcp_flow_tracker_s *tracker)
{
    histo_bucket_reset(&tracker->send_delay_buckets, __MAX_DELAY_SIZE);
    histo_bucket_reset(&tracker->recv_delay_buckets, __MAX_DELAY_SIZE);
    return;
}

/*
 * 1. Max length of u64 is 20
 * 2. The longest histogram str is like this, it's length will not exceed 24 + 16 * bucket_size
 * |8 xxxxxxxx xxxxxx (* bucket size) %llu
 *
 * tx_rx: |%llu|%llu|%llu|%llu, most 4 * 21
 * win: |histo|histo|histo|histo|histo|histo|histo|%llu|%llu|%.2f|%.2f, most 7 * 104 + 2 * 21 + 2 * 7
 * abn: |%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%.2f, most 12 * 21 + 7
 * rtt: |histo|histo, most 2 * 104
 * rate: |histo|histo, most 2 * 104
 * sockbuf: |histo|histo, most 2 * 152
 * synrtt: |histo|%llu, most 104 + 21
 * So 1024 is big enough for all types of metric
*/
#define  METRIC_DATA_STR_LEN  1024
static int output_tcp_metrics(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker)
{
    int outputted = 0;
    u32 report_flags = tracker->report_flags & TCP_PROBE_ALL;
    u32 load_flags = tcp_mng->ipc_body.probe_range_flags;
    char txrx_buf[METRIC_DATA_STR_LEN] = "||||";
    char rtt_buf[METRIC_DATA_STR_LEN] = "||";
    char win_buf[METRIC_DATA_STR_LEN] = "|||||||||||";
    char rate_buf[METRIC_DATA_STR_LEN] = "||";
    char syn_rtt_buf[METRIC_DATA_STR_LEN] = "||";
    char sockbuf_buf[METRIC_DATA_STR_LEN] = "||";
    char abn_buf[METRIC_DATA_STR_LEN] = "|||||||||||||";

    if ((report_flags & TCP_PROBE_ABN) && (load_flags & PROBE_RANGE_TCP_ABNORMAL)) {
        outputted = 1;
        output_tcp_abn(tcp_mng, tracker, abn_buf, sizeof(abn_buf));
        reset_tcp_abn_stats(tracker);
    }

    if ((report_flags & TCP_PROBE_SRTT) && (load_flags & PROBE_RANGE_TCP_SRTT)) {
        outputted = 1;
        output_tcp_syn_rtt(tcp_mng, tracker, syn_rtt_buf, sizeof(syn_rtt_buf));
        reset_tcp_syn_rtt_stats(tracker);
    }

    if ((report_flags & TCP_PROBE_WINDOWS) && (load_flags & PROBE_RANGE_TCP_WINDOWS)) {
        outputted = 1;
        output_tcp_win(tcp_mng, tracker, win_buf, sizeof(win_buf));
        reset_tcp_win_stats(tracker);
    }

    if ((report_flags & TCP_PROBE_RTT) && (load_flags & PROBE_RANGE_TCP_RTT)) {
        outputted = 1;
        output_tcp_rtt(tcp_mng, tracker, rtt_buf, sizeof(rtt_buf));
        reset_tcp_rtt_stats(tracker);
    }

    if ((report_flags & TCP_PROBE_TXRX) && (load_flags & PROBE_RANGE_TCP_STATS)) {
        outputted = 1;
        output_tcp_txrx(tcp_mng, tracker, txrx_buf, sizeof(txrx_buf));
        reset_tcp_txrx_stats(tracker);
    }

    if ((report_flags & TCP_PROBE_SOCKBUF) && (load_flags & PROBE_RANGE_TCP_SOCKBUF)) {
        outputted = 1;
        output_tcp_sockbuf(tcp_mng, tracker, sockbuf_buf, sizeof(sockbuf_buf));
        reset_tcp_sockbuf_stats(tracker);
    }

    if ((report_flags & TCP_PROBE_RATE) && (load_flags & PROBE_RANGE_TCP_RATE)) {
        outputted = 1;
        output_tcp_rate(tcp_mng, tracker, rate_buf, sizeof(rate_buf));
        reset_tcp_rate_stats(tracker);
    }

    if (outputted) {
        (void)fprintf(stdout,
            "|%s|%u|%s|%s|%s|%s|%u|%u|%u"
            "%s%s%s%s%s%s%s|\n",
            TCP_TBL_METRIC,
            tracker->id.tgid,
            (tracker->id.role == 0) ? "server" : "client",
            tracker->src_ip,
            tracker->toa_src_ip ? : "",
            tracker->dst_ip,
            tracker->id.cport,
            tracker->id.port,
            tracker->id.family,

            txrx_buf, rtt_buf, win_buf, rate_buf, syn_rtt_buf, sockbuf_buf, abn_buf);
        (void)fflush(stdout);
    }
    tracker->report_flags = 0;
    return outputted;
}

static int output_tcp_flow_metrics(struct tcp_mng_s *tcp_mng, struct tcp_flow_tracker_s *tracker)
{
    int need_reset = 0;
    u32 flags = tracker->report_flags & TCP_PROBE_ALL;

    if ((flags & TCP_PROBE_DELAY) && is_load_probe(tcp_mng, PROBE_RANGE_TCP_DELAY)) {
        need_reset = 1;
        output_tcp_flow_delay(tcp_mng, tracker);
    }

    tracker->report_flags = 0;
    if (need_reset) {
        reset_tcp_flow_tracker_stats(tracker);
    }
    return need_reset;
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
    u32 sk_drops_delta, lost_out_delta;

    sk_drops_delta = (data->sk_drops >= data->last_time_sk_drops) ?
        (data->sk_drops - data->last_time_sk_drops) : data->sk_drops;

    lost_out_delta = (data->lost_out >= data->last_time_lost_out) ?
        (data->lost_out - data->last_time_lost_out) : data->lost_out;

    tracker->stats[RETRANS] += data->total_retrans;
    tracker->stats[BACKLOG_DROPS] += data->backlog_drops;
    tracker->stats[FILTER_DROPS] += data->filter_drops;
    tracker->stats[SK_DROPS] += sk_drops_delta;
    tracker->stats[LOST_OUT] += lost_out_delta;
    if (data->sacked_out > tracker->stats[SACKED_OUT]) {
        tracker->stats[SACKED_OUT] = data->sacked_out;
    }
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
    struct histo_attr_single *rg_attr = tcp_mng->histo_attr;
    (void)histo_bucket_add_value(rg_attr->snd_wnd_buckets, &tracker->snd_wnd_buckets, __MAX_WIND_SIZE, data->tcpi_snd_wnd);
    (void)histo_bucket_add_value(rg_attr->rcv_wnd_buckets, &tracker->rcv_wnd_buckets, __MAX_WIND_SIZE, data->tcpi_rcv_wnd);
    (void)histo_bucket_add_value(rg_attr->avl_snd_wnd_buckets, &tracker->avl_snd_wnd_buckets, __MAX_WIND_SIZE, data->tcpi_avl_snd_wnd);
    (void)histo_bucket_add_value(rg_attr->snd_cwnd_buckets, &tracker->snd_cwnd_buckets, __MAX_WIND_SIZE, data->tcpi_snd_cwnd);


    (void)histo_bucket_add_value(rg_attr->not_sent_buckets, &tracker->not_sent_buckets, __MAX_WIND_SIZE, data->tcpi_notsent_bytes);
    (void)histo_bucket_add_value(rg_attr->not_acked_buckets, &tracker->not_acked_buckets, __MAX_WIND_SIZE, data->tcpi_notack_bytes);
    (void)histo_bucket_add_value(rg_attr->reordering_buckets, &tracker->reordering_buckets, __MAX_WIND_SIZE, data->tcpi_reordering);

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
    (void)histo_bucket_add_value(tcp_mng->histo_attr->srtt_buckets, &tracker->srtt_buckets, __MAX_RTT_SIZE, data->tcpi_srtt);
    (void)histo_bucket_add_value(tcp_mng->histo_attr->rcv_rtt_buckets, &tracker->rcv_rtt_buckets, __MAX_RTT_SIZE, data->tcpi_rcv_rtt);
    tracker->report_flags |= TCP_PROBE_RTT;
    return;
}

static void proc_tcp_srtt(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker, const struct tcp_srtt *data)
{
    (void)histo_bucket_add_value(tcp_mng->histo_attr->syn_srtt_buckets, &tracker->syn_srtt_buckets, __MAX_RTT_SIZE, data->syn_srtt);
    tracker->stats[SYN_SRTT_MAX] = max(tracker->stats[SYN_SRTT_MAX], data->syn_srtt);
    tracker->report_flags |= TCP_PROBE_SRTT;
    return;
}

static void proc_tcp_rate(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker, const struct tcp_rate *data)
{
    (void)histo_bucket_add_value(tcp_mng->histo_attr->rto_buckets, &tracker->rto_buckets, __MAX_RTO_SIZE, data->tcpi_rto);
    (void)histo_bucket_add_value(tcp_mng->histo_attr->ato_buckets, &tracker->ato_buckets, __MAX_RTO_SIZE, data->tcpi_ato);
    tracker->report_flags |= TCP_PROBE_RATE;
    return;
}

static void proc_tcp_sockbuf(struct tcp_mng_s *tcp_mng, struct tcp_tracker_s *tracker, const struct tcp_sockbuf *data)
{
    (void)histo_bucket_add_value(tcp_mng->histo_attr->rcv_buf_buckets, &tracker->rcv_buf_buckets, __MAX_SOCKBUF_SIZE, data->sk_rcvbuf);
    (void)histo_bucket_add_value(tcp_mng->histo_attr->snd_buf_buckets, &tracker->snd_buf_buckets, __MAX_SOCKBUF_SIZE, data->sk_sndbuf);
    tracker->report_flags |= TCP_PROBE_SOCKBUF;
    return;
}

static void proc_tcp_flow_delay(struct tcp_mng_s *tcp_mng, struct tcp_flow_tracker_s *tracker,
    const struct tcp_delay *data)
{
    if (data->recv_state == DELAY_SAMP_FINISH) {
        (void)histo_bucket_add_value(tcp_mng->histo_attr->recv_delay_buckets, &tracker->recv_delay_buckets, __MAX_DELAY_SIZE, data->net_recv_delay);
    }
    if (data->send_state == DELAY_SAMP_FINISH) {
        (void)histo_bucket_add_value(tcp_mng->histo_attr->send_delay_buckets, &tracker->send_delay_buckets, __MAX_DELAY_SIZE, data->net_send_delay);
    }
    tracker->report_flags |= TCP_PROBE_DELAY;
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

static char is_flow_tracker_inactive(struct tcp_flow_tracker_s *tracker)
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

static char is_flow_track_tmout(struct tcp_mng_s *tcp_mng, struct tcp_flow_tracker_s *tracker)
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

// 从toa_socks中获取toa map元素，仅根据五元组，不依据tgid。如果没有则创建并添加到tcp_mng->toa_socks中
static void get_toa_sock(struct tcp_mng_s *tcp_mng, const struct tcp_metrics_s *metrics)
{
    struct toa_sock_id_s toa_sock_id = {0};
    const struct tcp_link_s *tcp_link = &(metrics->link);

    __init_toa_sock_id(&toa_sock_id, tcp_link);

    struct toa_socket_s *toa_sock = lkup_toa_sock(tcp_mng, (const struct toa_sock_id_s *)&toa_sock_id);
    if (toa_sock) {
        toa_sock->opt_family = metrics->link.opt_family;
        if (metrics->link.opt_family == AF_INET) {
            toa_sock->opt_c_ip = metrics->link.opt_c_ip;
        } else {
            memcpy(toa_sock->opt_c_ip6, tcp_link->opt_c_ip6, IP6_LEN);
        }
        return;
    }

    struct toa_socket_s *new_toa_sock = create_toa_sock(&toa_sock_id);
    if (new_toa_sock == NULL) {
        return;
    }
    new_toa_sock->opt_family = metrics->link.opt_family;
    if (metrics->link.opt_family == AF_INET) {
        new_toa_sock->opt_c_ip = metrics->link.opt_c_ip;
    } else {
        memcpy(new_toa_sock->opt_c_ip6, tcp_link->opt_c_ip6, IP6_LEN);
    }
    H_ADD(tcp_mng->toa_socks, id, sizeof(struct toa_sock_id_s), new_toa_sock);
    return;
}

static void process_tcp_tracker_metrics(struct tcp_mng_s *tcp_mng, struct tcp_metrics_s *metrics)
{
    struct tcp_tracker_s* tracker = NULL;
    u32 metrics_flags = metrics->report_flags & TCP_PROBE_ALL;

    // 优先处理toa的metrics
    struct toa_sock_id_s toa_sock_id = {0};
    struct toa_socket_s *toa_sock = NULL;
    if (metrics_flags & TCP_PROBE_TOA) {
        get_toa_sock(tcp_mng, (const struct tcp_metrics_s *)metrics);
        return;
    }

    __init_toa_sock_id(&toa_sock_id, &(metrics->link));
    toa_sock = lkup_toa_sock(tcp_mng, &toa_sock_id);
    tracker = get_tcp_tracker(tcp_mng, (const void *)(&(metrics->link)), toa_sock);
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

    if (metrics_flags & TCP_PROBE_TCP_CLOSE) {
        if (toa_sock) {
            H_DEL(tcp_mng->toa_socks, toa_sock);
            free(toa_sock);
        }
    }

    return;
}

static void process_tcp_flow_tracker_metrics(struct tcp_mng_s *tcp_mng, struct tcp_metrics_s *metrics)
{
    struct tcp_flow_tracker_s* tracker = NULL;
    u32 metrics_flags = metrics->report_flags & TCP_PROBE_ALL;

    tracker = get_tcp_flow_tracker(tcp_mng, (const void *)(&(metrics->link)));
    if (tracker == NULL) {
        return;
    }

    tracker->last_rcv_data = (time_t)time(NULL);

    if (metrics_flags & TCP_PROBE_DELAY) {
        proc_tcp_flow_delay(tcp_mng, tracker, (const struct tcp_delay *)(&(metrics->delay_stats)));
    }
    return;
}

static int proc_tcp_metrics_evt(void *ctx, void *data, u32 size)
{
    char *p = data;
    size_t remain_size = (size_t)size, step_size = sizeof(struct tcp_metrics_s), offset = 0;
    struct tcp_metrics_s *metrics;
    struct tcp_mng_s *tcp_mng = ctx;

    do {
        if (remain_size < step_size) {
            break;
        }
        p = (char *)data + offset;
        metrics  = (struct tcp_metrics_s *)p;

        process_tcp_tracker_metrics(tcp_mng, metrics);
        process_tcp_flow_tracker_metrics(tcp_mng, metrics);

        offset += step_size;
        remain_size -= step_size;
    } while (1);

    return 0;
}

#endif

static int tcp_load_probe_sockbuf(struct tcp_mng_s *tcp_mng, struct bpf_prog_s *prog, char is_load)
{
    int err;
    struct bpf_buffer *buffer = NULL;

    __OPEN_PROBE_WITH_OUTPUT(tcp_sockbuf, err, is_load, buffer);

    if (is_load) {
        __SELECT_RCV_ESTABLISHED_HOOKPOINT(tcp_sockbuf);
    }

    __LOAD_PROBE(tcp_sockbuf, err, is_load);

    if (is_load) {
        prog->skels[prog->num].skel = tcp_sockbuf_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)tcp_sockbuf_bpf__destroy;
        prog->custom_btf_paths[prog->num] = tcp_sockbuf_open_opts.btf_custom_path;

        if (prog->num == 0) {  // All sub-probes share a output buffer
            err = bpf_buffer__open(buffer, proc_tcp_metrics_evt, NULL, tcp_mng);
            if (err) {
                ERROR("[TCPPROBE] Open 'tcp_sockbuf' bpf_buffer failed.\n");
                goto err;
            }
        }
        prog->buffers[prog->num] = buffer;
        prog->num++;
    }

    return 0;
err:
    bpf_buffer__free(buffer);
    __UNLOAD_PROBE(tcp_sockbuf);
    return -1;
}

static int tcp_load_probe_rtt(struct tcp_mng_s *tcp_mng, struct bpf_prog_s *prog, char is_load)
{
    int err;
    struct bpf_buffer *buffer = NULL;

    __OPEN_PROBE_WITH_OUTPUT(tcp_rtt, err, is_load, buffer);

    if (is_load) {
        __SELECT_RCV_ESTABLISHED_HOOKPOINT(tcp_rtt);
    }

    __LOAD_PROBE(tcp_rtt, err, is_load);

    if (is_load) {
        prog->skels[prog->num].skel = tcp_rtt_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)tcp_rtt_bpf__destroy;
        prog->custom_btf_paths[prog->num] = tcp_rtt_open_opts.btf_custom_path;

        if (prog->num == 0) {  // All sub-probes share a output buffer
            err = bpf_buffer__open(buffer, proc_tcp_metrics_evt, NULL, tcp_mng);
            if (err) {
                ERROR("[TCPPROBE] Open 'tcp_rtt' bpf_buffer failed.\n");
                goto err;
            }
        }
        prog->buffers[prog->num] = buffer;
        prog->num++;
    }

    return 0;
err:
    bpf_buffer__free(buffer);
    __UNLOAD_PROBE(tcp_rtt);
    return -1;
}

static int tcp_load_probe_win(struct tcp_mng_s *tcp_mng, struct bpf_prog_s *prog, char is_load)
{
    int err;
    struct bpf_buffer *buffer = NULL;

    __OPEN_PROBE_WITH_OUTPUT(tcp_windows, err, is_load, buffer);

    if (is_load) {
        __SELECT_SPACE_ADJUST_HOOKPOINT(tcp_windows);
    }

    __LOAD_PROBE(tcp_windows, err, is_load);

    if (is_load) {
        prog->skels[prog->num].skel = tcp_windows_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)tcp_windows_bpf__destroy;
        prog->custom_btf_paths[prog->num] = tcp_windows_open_opts.btf_custom_path;

        if (prog->num == 0) {  // All sub-probes share a output buffer
            err = bpf_buffer__open(buffer, proc_tcp_metrics_evt, NULL, tcp_mng);
            if (err) {
                ERROR("[TCPPROBE] Open 'tcp_windows' bpf_buffer failed.\n");
                goto err;
            }
        }
        prog->buffers[prog->num] = buffer;
        prog->num++;
    }

    return 0;
err:
    bpf_buffer__free(buffer);
    __UNLOAD_PROBE(tcp_windows);
    return -1;
}

static int tcp_load_probe_rate(struct tcp_mng_s *tcp_mng, struct bpf_prog_s *prog, char is_load)
{
    int err;
    struct bpf_buffer *buffer = NULL;

    __OPEN_PROBE_WITH_OUTPUT(tcp_rate, err, is_load, buffer);

    if (is_load) {
        __SELECT_SPACE_ADJUST_HOOKPOINT(tcp_rate);
    }

    __LOAD_PROBE(tcp_rate, err, is_load);

    if (is_load) {
        prog->skels[prog->num].skel = tcp_rate_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)tcp_rate_bpf__destroy;
        prog->custom_btf_paths[prog->num] = tcp_rate_open_opts.btf_custom_path;

        if (prog->num == 0) {  // All sub-probes share a output buffer
            err = bpf_buffer__open(buffer, proc_tcp_metrics_evt, NULL, tcp_mng);
            if (err) {
                ERROR("[TCPPROBE] Open 'tcp_rate' bpf_buffer failed.\n");
                goto err;
            }
        }
        prog->buffers[prog->num] = buffer;
        prog->num++;
    }

    return 0;
err:
    bpf_buffer__free(buffer);
    __UNLOAD_PROBE(tcp_rate);
    return -1;
}

static int tcp_load_probe_abn(struct tcp_mng_s *tcp_mng, struct bpf_prog_s *prog, char is_load)
{
    int err;
    struct bpf_buffer *buffer = NULL;

    __OPEN_PROBE_WITH_OUTPUT(tcp_abn, err, is_load, buffer);

    if (is_load) {
        __SELECT_RCV_ESTABLISHED_HOOKPOINT(tcp_abn);
        __SELECT_RESET_HOOKPOINTS(tcp_abn);

        PROG_ENABLE_ONLY_IF(tcp_abn, bpf_tcp_write_err, probe_kernel_version() < KERNEL_VERSION(5, 10, 0));
    }

    __LOAD_PROBE(tcp_abn, err, is_load);

    if (is_load) {
        prog->skels[prog->num].skel = tcp_abn_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)tcp_abn_bpf__destroy;
        prog->custom_btf_paths[prog->num] = tcp_abn_open_opts.btf_custom_path;

        if (prog->num == 0) {   // All sub-probes share a output buffer
            err = bpf_buffer__open(buffer, proc_tcp_metrics_evt, NULL, tcp_mng);
            if (err) {
                ERROR("[TCPPROBE] Open 'tcp_abn' bpf_buffer failed.\n");
                goto err;
            }
        }
        prog->buffers[prog->num] = buffer;
        prog->num++;
    }

    return 0;
err:
    bpf_buffer__free(buffer);
    __UNLOAD_PROBE(tcp_abn);
    return -1;
}

static int tcp_load_probe_txrx(struct tcp_mng_s *tcp_mng, struct bpf_prog_s *prog, char is_load)
{
    int err;
    struct bpf_buffer *buffer = NULL;

    __OPEN_LOAD_PROBE_WITH_OUTPUT(tcp_tx_rx, err, is_load, buffer);
    if (is_load) {
        prog->skels[prog->num].skel = tcp_tx_rx_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)tcp_tx_rx_bpf__destroy;
        prog->custom_btf_paths[prog->num] = tcp_tx_rx_open_opts.btf_custom_path;
        if (prog->num == 0) {  // All sub-probes share a output buffer
            err = bpf_buffer__open(buffer, proc_tcp_metrics_evt, NULL, tcp_mng);
            if (err) {
                ERROR("[TCPPROBE] Open 'tcp_txrx' bpf_buffer failed.\n");
                goto err;
            }
        }
        prog->buffers[prog->num] = buffer;
        prog->num++;
    }

    return 0;
err:
    bpf_buffer__free(buffer);
    __UNLOAD_PROBE(tcp_tx_rx);
    return -1;
}

static int tcp_load_probe_delay(struct tcp_mng_s *tcp_mng, struct bpf_prog_s *prog, char is_load)
{
    int err;
    struct bpf_buffer *buffer = NULL;

    __OPEN_PROBE_WITH_OUTPUT(tcp_delay, err, is_load, buffer);

    if (is_load) {
        bool is_const = probe_kernel_version() > KERNEL_VERSION(5, 12, 0);
        PROG_ENABLE_ONLY_IF(tcp_delay, bpf_constprop_tcp_clean_rtx_queue, is_const);
        PROG_ENABLE_ONLY_IF(tcp_delay, bpf_tcp_clean_rtx_queue, !is_const);
        PROG_ENABLE_ONLY_IF(tcp_delay, bpf_tcp_recvmsg, probe_tstamp());
    }

    __LOAD_PROBE(tcp_delay, err, is_load);

    if (is_load) {
        prog->skels[prog->num].skel = tcp_delay_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)tcp_delay_bpf__destroy;
        prog->custom_btf_paths[prog->num] = tcp_delay_open_opts.btf_custom_path;

        if (prog->num == 0) {   // All sub-probes share a output buffer
            err = bpf_buffer__open(buffer, proc_tcp_metrics_evt, NULL, tcp_mng);
            if (err) {
                ERROR("[TCPPROBE] Open 'tcp_delay' bpf_buffer failed.\n");
                goto err;
            }
        }
        prog->buffers[prog->num] = buffer;
        prog->num++;
    }

    return 0;
err:
    bpf_buffer__free(buffer);
    __UNLOAD_PROBE(tcp_delay);
    return -1;
}

static int tcp_load_probe_link(struct tcp_mng_s *tcp_mng, struct probe_params *args, struct bpf_prog_s *prog)
{
    int err;
    struct bpf_buffer *buffer = NULL;

    __OPEN_PROBE_WITH_OUTPUT(tcp_link, err, 1, buffer);
    __SELECT_DESTROY_SOCK_HOOKPOINT(tcp_link);
    __LOAD_PROBE(tcp_link, err, 1);

    prog->skels[prog->num].skel = tcp_link_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)tcp_link_bpf__destroy;
    prog->custom_btf_paths[prog->num] = tcp_link_open_opts.btf_custom_path;

    if (prog->num == 0) {   // All sub-probes share a output buffer
        err = bpf_buffer__open(buffer, proc_tcp_metrics_evt, NULL, tcp_mng);
        if (err) {
            ERROR("[TCPPROBE] Open 'tcp_link' bpf_buffer failed.\n");
            goto err;
        }
    }
    prog->buffers[prog->num] = buffer;
    prog->num++;

    return 0;
err:
    bpf_buffer__free(buffer);
    __UNLOAD_PROBE(tcp_link);
    return -1;
}

int tcp_load_probe(struct tcp_mng_s *tcp_mng, struct ipc_body_s *ipc_body, struct bpf_prog_s **new_prog)
{
    char is_load = 0;
    struct bpf_prog_s *prog;
    char is_load_txrx, is_load_abn, is_load_win, is_load_rate, is_load_rtt, is_load_sockbuf, is_load_delay, is_load_srtt;

    is_load_txrx = ipc_body->probe_range_flags & PROBE_RANGE_TCP_STATS;
    is_load_abn = ipc_body->probe_range_flags & PROBE_RANGE_TCP_ABNORMAL;
    is_load_rate = ipc_body->probe_range_flags & PROBE_RANGE_TCP_RATE;
    is_load_win = ipc_body->probe_range_flags & PROBE_RANGE_TCP_WINDOWS;
    is_load_rtt = ipc_body->probe_range_flags & PROBE_RANGE_TCP_RTT;
    is_load_sockbuf = ipc_body->probe_range_flags & PROBE_RANGE_TCP_SOCKBUF;
    is_load_delay = ipc_body->probe_range_flags & PROBE_RANGE_TCP_DELAY;
    is_load_srtt = ipc_body->probe_range_flags & PROBE_RANGE_TCP_SRTT;

    is_load = is_load_txrx | is_load_abn | is_load_rate | is_load_win | is_load_rtt | is_load_sockbuf | is_load_delay | is_load_srtt;
    if (!is_load) {
        return 0;
    }

    prog = alloc_bpf_prog();
    if (prog == NULL) {
        return -1;
    }

#if defined(__x86_64__) || defined(__riscv)
    if (tcp_load_probe_link(tcp_mng, &(ipc_body->probe_param), prog)) {
        goto err;
    }
#endif

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

    if (tcp_load_probe_delay(tcp_mng, prog, is_load_delay)) {
        goto err;
    }
#ifdef __aarch64__
    if (tcp_load_probe_link(tcp_mng, &(ipc_body->probe_param), prog)) {
        goto err;
    }
#endif

    INFO("[TCPPROBE]: Successfully load ebpf prog.\n");
    *new_prog = prog;
    return 0;

err:
    unload_bpf_prog(&prog);
    return -1;
}

void aging_tcp_trackers(struct tcp_mng_s *tcp_mng)
{
    struct tcp_tracker_s *tracker, *tmp;

    H_ITER(tcp_mng->trackers, tracker, tmp) {
        if (is_tracker_inactive(tracker)) {
            H_DEL(tcp_mng->trackers, tracker);
            destroy_tcp_tracker(tracker);
            tcp_mng->tcp_tracker_count--;
        }
    }
}

void aging_tcp_flow_trackers(struct tcp_mng_s *tcp_mng)
{
    struct tcp_flow_tracker_s *tracker, *tmp;

    H_ITER(tcp_mng->flow_trackers, tracker, tmp) {
        if (is_flow_tracker_inactive(tracker)) {
            H_DEL(tcp_mng->flow_trackers, tracker);
            destroy_tcp_flow_tracker(tracker);
            tcp_mng->tcp_flow_tracker_count--;
        }
    }
}

#define __STEP (200)
void scan_tcp_trackers(struct tcp_mng_s *tcp_mng)
{
    int count = 0;
    struct tcp_tracker_s *tracker, *tmp;

    H_ITER(tcp_mng->trackers, tracker, tmp) {
        if ((count < __STEP) && is_track_tmout(tcp_mng, tracker)) {
            count += output_tcp_metrics(tcp_mng, tracker);
        }
    }
}

void scan_tcp_flow_trackers(struct tcp_mng_s *tcp_mng)
{
    int count = 0;
    struct tcp_flow_tracker_s *tracker, *tmp;

    H_ITER(tcp_mng->flow_trackers, tracker, tmp) {
        if ((count < __STEP) && is_flow_track_tmout(tcp_mng, tracker)) {
            count += output_tcp_flow_metrics(tcp_mng, tracker);
        }
    }
}
