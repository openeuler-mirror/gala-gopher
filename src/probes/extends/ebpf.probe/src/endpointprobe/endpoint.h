/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 */
#ifndef __ENDPOINT_H__
#define __ENDPOINT_H__

#define BPF_F_INDEX_MASK    0xffffffffULL
#define BPF_F_ALL_CPU   BPF_F_INDEX_MASK

enum socket_evt_e {
    // tcp event
    EP_STATS_LISTEN_DROPS = 0,
    EP_STATS_ACCEPT_OVERFLOW,   // alarm accpet queue full
    EP_STATS_SYN_OVERFLOW,      // alarm syn queue full
    EP_STATS_PASSIVE_OPENS,
    EP_STATS_PASSIVE_FAILS,
    EP_STATS_RETRANS_SYNACK,
    EP_STATS_RETRANS_SYN,
    EP_STATS_REQ_DROP,
    EP_STATS_ACTIVE_OPENS,
    EP_STATS_ACTIVE_FAILS,

    EP_STATS_SYN_SENT,
    EP_STATS_SYN_DROP,
    EP_STATS_SYNACK_SENT,
    EP_STATS_SYN_TOA_RECV,

    EP_STATS_CONN_CLOSE,

    // udp event
    EP_STATS_QUE_RCV_FAILED,
    EP_STATS_UDP_SENDS,
    EP_STATS_UDP_RCVS,

    EP_STATS_MAX
};

#ifdef IP6_LEN
#undef IP6_LEN
#endif
#define IP6_LEN                 16

enum socket_role_e {
    TCP_CLIENT = 0,
    TCP_SERVER,
    TCP_LISTEN_SK
};

struct conn_addr_s {
    u16 family;
    u16 port;                   // TCP server port or client connect port
    union {
        u32 ip;
        char ip6[IP6_LEN];
    };
};

struct tcp_socket_event_s {
    int tgid;                   // process id
    int is_multi;               // is_multi: 1: multi procs listen to one sock
    u64 estab_latency;          // unit: ns
    struct conn_addr_s client_ipaddr;
    struct conn_addr_s server_ipaddr;
    enum socket_evt_e evt;
    enum socket_role_e role;

    // following is for TOA
    struct conn_addr_s toa_client_ipaddr;
};

struct udp_socket_event_s {
    int tgid;                   // process id
    struct conn_addr_s local_ipaddr;
    struct conn_addr_s remote_ipaddr;
    enum socket_evt_e evt;
    u64 val;
};

struct tcp_listen_key_s {
    unsigned long inode;
    //unsigned int net_ns;
    //int port;
};

struct tcp_listen_val_s {
    unsigned int proc_id;
    int is_multi;       // 1: proc_id is pgid of multi procs, used for multi procs listen to one sock
};

#endif
