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
    EP_STATS_LOST_SYNACK,
    EP_STATS_REQ_DROP,
    EP_STATS_ACTIVE_OPENS,
    EP_STATS_ACTIVE_FAILS,

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
    TCP_SERVER
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
    struct conn_addr_s client_ipaddr;
    struct conn_addr_s server_ipaddr;
    enum socket_evt_e evt;
    enum socket_role_e role;
};

struct udp_socket_event_s {
    int tgid;                   // process id
    struct conn_addr_s local_ipaddr;
    struct conn_addr_s remote_ipaddr;
    enum socket_evt_e evt;
    u64 val;
};

#endif
