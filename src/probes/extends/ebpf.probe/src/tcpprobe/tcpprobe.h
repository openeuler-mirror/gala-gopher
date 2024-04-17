/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: sky
 * Create: 2021-05-22
 * Description: tcp_probe include file
 ******************************************************************************/
#ifndef __TCPPROBE__H
#define __TCPPROBE__H

#include "bpf.h"

#define LINK_ROLE_SERVER 0
#define LINK_ROLE_CLIENT 1
#define LINK_ROLE_MAX 2

#define TCP_LINK_OUTPUT_PATH    "/sys/fs/bpf/gala-gopher/__tcplink_output"
#define TCP_LINK_ARGS_PATH      "/sys/fs/bpf/gala-gopher/__tcplink_args"
#define TCP_LINK_SOCKS_PATH     "/sys/fs/bpf/gala-gopher/__tcplink_socks"
#define TCP_LINK_TCP_PATH       "/sys/fs/bpf/gala-gopher/__tcplink_tcp"
#define TCP_LINK_FD_PATH        "/sys/fs/bpf/gala-gopher/__tcplink_tcp_fd"

#define TCP_PROBE_ABN       (u32)(1)
#define TCP_PROBE_WINDOWS   (u32)(1 << 1)
#define TCP_PROBE_RTT       (u32)(1 << 2)
#define TCP_PROBE_TXRX      (u32)(1 << 3)
#define TCP_PROBE_SOCKBUF   (u32)(1 << 4)
#define TCP_PROBE_RATE      (u32)(1 << 5)
#define TCP_PROBE_SRTT      (u32)(1 << 6)
#define TCP_PROBE_DELAY     (u32)(1 << 7)
#define TCP_PROBE_ALL       (u32)(TCP_PROBE_ABN | TCP_PROBE_WINDOWS \
                | TCP_PROBE_RTT | TCP_PROBE_TXRX \
                | TCP_PROBE_SOCKBUF | TCP_PROBE_RATE | TCP_PROBE_SRTT | TCP_PROBE_DELAY)

#define TCP_FD_PER_PROC_MAX (10)

#define TC_PROG "tcp_bpf/tc_tstamp.bpf.o"
#define BPF_F_INDEX_MASK    0xffffffffULL
#define BPF_F_CURRENT_CPU   BPF_F_INDEX_MASK

struct tcp_fd_info {
    int fds[TCP_FD_PER_PROC_MAX];
    __u8 fd_role[TCP_FD_PER_PROC_MAX];
    unsigned int cnt;
};

struct tcp_srtt {
    __u32 syn_srtt;         // FROM tcp_sock.srtt_us when old_state = RCV_SYNC & new_state = EATAB
};

struct tcp_abn {
    __u32 total_retrans;    // FROM tcp_retransmit_skb event
    __u32 backlog_drops;    // FROM tcp_add_backlog event
    __u32 last_time_sk_drops;
    __u32 sk_drops;         // FROM sock.sk_drops.counter
    __u32 last_time_lost_out;
    __u32 lost_out;         // FROM tcp_sock.lost_out
    __u32 last_time_sacked_out;
    __u32 sacked_out;       // FROM tcp_sock.sacked_out
    __u32 filter_drops;     // FROM tcp_filter event
    __u32 tmout;            // FROM tcp_write_err event
    __u32 sndbuf_limit;     // FROM sock_exceed_buf_limit event
    __u32 rmem_scheduls;    // FROM tcp_try_rmem_schedule event
    __u32 tcp_oom;          // FROM tcp_check_oom event
    __u32 send_rsts;        // FROM tcp_send_reset event
    __u32 receive_rsts;     // FROM tcp_receive_reset event
};

struct tcp_tx_rx {
    __u64 rx;               // FROM tcp_cleanup_rbuf
    __u64 tx;               // FROM tcp_sendmsg
    __u32 last_time_segs_out;
    __u32 segs_out;         // total number of segments sent
    __u32 last_time_segs_in;
    __u32 segs_in;          // total number of segments in
};

struct tcp_sockbuf {
#if 0
    __u32   tcpi_sk_err_que_size;   // FROM sock.sk_error_queue.qlen
    __u32   tcpi_sk_rcv_que_size;   // FROM sock.sk_receive_queue.qlen
    __u32   tcpi_sk_wri_que_size;   // FROM sock.sk_write_queue.qlen
    __u32   tcpi_sk_backlog_size;   // FROM sock.sk_backlog.len

    __u32   tcpi_sk_omem_size;      // FROM sock.sk_omem_alloc
    __u32   tcpi_sk_forward_size;   // FROM sock.sk_forward_alloc
    __u32   tcpi_sk_wmem_size;      // FROM sock.sk_wmem_alloc
#endif
    int   sk_rcvbuf;                    // FROM sock.sk_rcvbuf
    int   sk_sndbuf;                // FROM sock.sk_sndbuf
};

struct tcp_rate {
    __u32   tcpi_rto;           // Retransmission timeOut(us)
    __u32   tcpi_ato;           // Estimated value of delayed ACK(us)
#if 0
    __u32   tcpi_snd_ssthresh;  // Slow start threshold for congestion control.
    __u32   tcpi_rcv_ssthresh;  // Current receive window size.
    __u32   tcpi_advmss;        // Local MSS upper limit.

    __u64   tcpi_delivery_rate; // Current transmit rate (multiple different from the actual value).
    __u32   tcpi_rcv_space;     // Current receive buffer size.

    __u32   tcpi_busy_time;      // Time (jiffies) busy sending data.
    __u32   tcpi_rwnd_limited;   // Time (jiffies) limited by receive window.
    __u32   tcpi_sndbuf_limited; // Time (jiffies) limited by send buffer.

    __u32   tcpi_pacing_rate;    // bytes per second
    __u32   tcpi_max_pacing_rate;   // bytes per second
#endif
};

struct tcp_windows {
    __u32   tcpi_notsent_bytes; // Number of bytes not sent currently.
    __u32   tcpi_notack_bytes;  // Number of bytes not ack currently.
    __u32   tcpi_snd_wnd;       // FROM tcp_sock.snd_wnd
    __u32   tcpi_rcv_wnd;       // FROM tcp_sock.rcv_wnd
    __u32   tcpi_avl_snd_wnd;   // TCP Available Send Window

    __u32   tcpi_reordering;    // Segments to be reordered.
    __u32   tcpi_snd_cwnd;      // Congestion Control Window Size.
};

struct tcp_rtt {
    __u32   tcpi_srtt;          // FROM tcp_sock.srtt_us in tcp_recvmsg
    __u32   tcpi_rcv_rtt;       // Receive end RTT (unidirectional measurement).
};

// #define NET_DELAY_BUCKET_SIZE   6

enum tcp_delay_samp_state {
    DELAY_SAMP_INIT = 0,
    DELAY_SAMP_START_READY,
    DELAY_SAMP_FINISH
};

struct tcp_delay {
    __u64 net_send_delay;
    __u64 net_recv_delay;
    enum tcp_delay_samp_state send_state;
    enum tcp_delay_samp_state recv_state;
    __u64 write_start_ts;   // use for net_send_delay calculation
    __u32 write_seq;        // use for net_send_delay calculation
};

#define TCP_BACKLOG_DROPS_INC(data) __sync_fetch_and_add(&((data).backlog_drops), 1)
#define TCP_FILTER_DROPS_INC(data) __sync_fetch_and_add(&((data).filter_drops), 1)
#define TCP_TMOUT_INC(data) __sync_fetch_and_add(&((data).tmout), 1)
#define TCP_SNDBUF_LIMIT_INC(data) __sync_fetch_and_add(&((data).sndbuf_limit), 1)
#define TCP_SEND_RSTS_INC(data) __sync_fetch_and_add(&((data).send_rsts), 1)
#define TCP_RECEIVE_RSTS_INC(data) __sync_fetch_and_add(&((data).receive_rsts), 1)
#define TCP_RETRANS_INC(data, delta) __sync_fetch_and_add(&((data).total_retrans), (int)(delta))

#define TCP_RMEM_SCHEDULS_INC(data) __sync_fetch_and_add(&((data).rmem_scheduls), 1)
#define TCP_OOM_INC(data) __sync_fetch_and_add(&((data).tcp_oom), 1)

#define TCP_RX_XADD(data, delta) __sync_fetch_and_add(&((data).rx), (__u64)(delta))
#define TCP_TX_XADD(data, delta) __sync_fetch_and_add(&((data).tx), (__u64)(delta))

struct tcp_link_s {
    __u32 tgid;     // process id
    union {
        __u32 c_ip;
        unsigned char c_ip6[IP6_LEN];
    };
    union {
        __u32 s_ip;
        unsigned char s_ip6[IP6_LEN];
    };
    __u16 s_port;   // server port
    __u16 c_port;   // client port
    __u16 family;
    __u16 role;     // role: client:1/server:0
    char comm[TASK_COMM_LEN];
};

struct tcp_metrics_s {
    u32 report_flags;       // Refer to TCP_PROBE_xxx
    struct tcp_link_s link;

    struct tcp_tx_rx tx_rx_stats;
    struct tcp_abn abn_stats;
    struct tcp_windows win_stats;
    struct tcp_rtt rtt_stats;
    struct tcp_srtt srtt_stats;
    struct tcp_rate rate_stats;
    struct tcp_sockbuf sockbuf_stats;
    struct tcp_delay delay_stats;
};

struct sock_info_s {
    u32 role;           // client:1/server:0
    u32 syn_srtt;       // rtt from SYN/ACK to ACK
    u32 proc_id;        // PID
    u32 tcp_link_ok;
};

struct tcp_ts {
    u64 abn_ts;
    u64 win_ts;
    u64 rtt_ts;
    u64 txrx_ts;
    u64 sockbuf_ts;
    u64 rate_ts;
    u64 delay_ts;
};

struct sock_stats_s {
    struct tcp_ts ts_stats;
    struct tcp_metrics_s metrics;
};

struct tcp_args_s {
    __u64 sample_period;               // Sampling period, unit ns
};

#if !defined(BPF_PROG_KERN) && !defined(BPF_PROG_USER)
#include "ipc.h"

void lkup_established_tcp(int proc_map_fd, struct ipc_body_s *ipc_body);
void destroy_established_tcps(void);
int tcp_load_fd_probe(void);
void tcp_unload_fd_probe(void);
int is_tcp_fd_probe_loaded(void);

#define __OPEN_PROBE(probe_name, end, load) \
    INIT_OPEN_OPTS(probe_name); \
    PREPARE_CUSTOM_BTF(probe_name); \
    OPEN_OPTS(probe_name, end, load); \
    MAP_SET_PIN_PATH(probe_name, args_map, TCP_LINK_ARGS_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, tcp_link_map, TCP_LINK_TCP_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, sock_map, TCP_LINK_SOCKS_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, tcp_fd_map, TCP_LINK_FD_PATH, load)

#define __OPEN_PROBE_WITH_OUTPUT(probe_name, end, load, buffer) \
    INIT_OPEN_OPTS(probe_name); \
    PREPARE_CUSTOM_BTF(probe_name); \
    OPEN_OPTS(probe_name, end, load); \
    MAP_INIT_BPF_BUFFER(probe_name, tcp_output, buffer, load); \
    MAP_SET_PIN_PATH(probe_name, args_map, TCP_LINK_ARGS_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, tcp_link_map, TCP_LINK_TCP_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, sock_map, TCP_LINK_SOCKS_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, tcp_fd_map, TCP_LINK_FD_PATH, load);

#define __LOAD_PROBE(probe_name, end, load) \
    LOAD_ATTACH(tcpprobe, probe_name, end, load)

#define __OPEN_LOAD_PROBE(probe_name, end, load) \
    __OPEN_PROBE(probe_name, end, load); \
    __LOAD_PROBE(probe_name, end, load)

#define __OPEN_LOAD_PROBE_WITH_OUTPUT(probe_name, end, load, buffer) \
    __OPEN_PROBE_WITH_OUTPUT(probe_name, end, load, buffer); \
    __LOAD_PROBE(probe_name, end, load)

#define __UNLOAD_PROBE(probe_name) \
    UNLOAD(probe_name); \
    CLEANUP_CUSTOM_BTF(probe_name)

#define __SELECT_RCV_ESTABLISHED_HOOKPOINT(probe_name) \
    do { \
        bool use_raw_tracepoint = probe_kernel_version() > KERNEL_VERSION(4, 18, 0); \
        PROG_ENABLE_ONLY_IF(probe_name, bpf_raw_trace_tcp_probe, use_raw_tracepoint); \
        PROG_ENABLE_ONLY_IF(probe_name, bpf_tcp_rcv_established, !use_raw_tracepoint); \
    } while (0)

#define __SELECT_SPACE_ADJUST_HOOKPOINT(probe_name) \
    do { \
        int kernel_version = probe_kernel_version(); \
        PROG_ENABLE_ONLY_IF(probe_name, bpf_raw_trace_tcp_rcv_space_adjust, kernel_version > KERNEL_VERSION(4, 18, 0)); \
        PROG_ENABLE_ONLY_IF(probe_name, bpf_tcp_rcv_space_adjust, kernel_version < KERNEL_VERSION(4, 13, 0)); \
        PROG_ENABLE_ONLY_IF(probe_name, bpf_trace_tcp_rcv_space_adjust_func, kernel_version >= KERNEL_VERSION(4, 13, 0) && kernel_version <= KERNEL_VERSION(4, 18, 0)); \
    } while (0)

#define __SELECT_DESTROY_SOCK_HOOKPOINT(probe_name) \
    do { \
        int kernel_version = probe_kernel_version(); \
        PROG_ENABLE_ONLY_IF(probe_name, bpf_raw_trace_tcp_destroy_sock, kernel_version > KERNEL_VERSION(4, 18, 0)); \
        PROG_ENABLE_ONLY_IF(probe_name, bpf_tcp_v4_destroy_sock, kernel_version < KERNEL_VERSION(4, 13, 0)); \
        PROG_ENABLE_ONLY_IF(probe_name, bpf_trace_tcp_destroy_sock_func, kernel_version >= KERNEL_VERSION(4, 13, 0) && kernel_version <= KERNEL_VERSION(4, 18, 0)); \
    } while (0)

#define __SELECT_RESET_HOOKPOINTS(probe_name) \
    do { \
        int kernel_version = probe_kernel_version(); \
        bool use_raw_tracepoint = kernel_version > KERNEL_VERSION(4, 18, 0); \
        bool use_kprobe = kernel_version < KERNEL_VERSION(4, 13, 0); \
        bool use_tracepoint = !use_raw_tracepoint && !use_kprobe; \
        PROG_ENABLE_ONLY_IF(probe_name, bpf_raw_trace_tcp_send_reset, use_raw_tracepoint); \
        PROG_ENABLE_ONLY_IF(probe_name, bpf_raw_trace_tcp_receive_reset, use_raw_tracepoint); \
        PROG_ENABLE_ONLY_IF(probe_name, bpf_tcp_v4_send_reset, use_kprobe); \
        PROG_ENABLE_ONLY_IF(probe_name, bpf_tcp_v6_send_reset, use_kprobe); \
        PROG_ENABLE_ONLY_IF(probe_name, bpf_tcp_send_active_reset, use_kprobe); \
        PROG_ENABLE_ONLY_IF(probe_name, bpf_tcp_reset, use_kprobe); \
        PROG_ENABLE_ONLY_IF(probe_name, bpf_trace_tcp_send_reset_func, use_tracepoint); \
        PROG_ENABLE_ONLY_IF(probe_name, bpf_trace_tcp_receive_reset_func, use_tracepoint); \
    } while (0)

#endif

#endif
