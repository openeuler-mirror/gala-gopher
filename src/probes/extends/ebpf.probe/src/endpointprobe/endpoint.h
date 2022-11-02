/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 */
#ifndef __ENDPOINT_H__
#define __ENDPOINT_H__

enum {
    // tcp listen statistic value
    EP_STATS_LISTEN_DROPS = 0,
    EP_STATS_ACCEPT_OVERFLOW,   // alarm accpet queue full
    EP_STATS_SYN_OVERFLOW,      // alarm syn queue full
    EP_STATS_PASSIVE_OPENS,
    EP_STATS_PASSIVE_FAILS,
    EP_STATS_RETRANS_SYNACK,
    EP_STATS_LOST_SYNACK,

    // tcp connect statistic value
    EP_STATS_ACTIVE_OPENS,
    EP_STATS_ACTIVE_FAILS,

    // udp statistic value
    EP_STATS_QUE_RCV_FAILED,
    EP_STATS_UDP_SENDS,
    EP_STATS_UDP_RCVS,

    EP_STATS_MAX
};

struct endpoint_stats {
    unsigned long stats[EP_STATS_MAX];
};

enum endpoint_t {
    SK_TYPE_LISTEN_TCP = 1,
    SK_TYPE_LISTEN_UDP,
    SK_TYPE_CLIENT_TCP,
    SK_TYPE_CLIENT_UDP,
};

struct endpoint_v {
    enum endpoint_t type;
    __u32 tgid;
};

struct ip {
    union {
        unsigned int ip4;               /* IPv4 地址 */
        unsigned char ip6[IP6_LEN];     /* IPv6 地址 */
    } ip;
    int family;                         /* 地址族 */
};

struct listen_sockfd_key_t {
    int tgid;               /* 用户进程 ID */
    int fd;                 /* socket的文件描述符 */
};

struct udp_client_key_t {
    int tgid;                   // process id
    struct ip ip_addr;          // udp source address
};

struct udp_server_key_t {
    int tgid;                   // process id
    struct ip ip_addr;          // udp source address
};

struct tcp_listen_key_t {
    int tgid;                   // process id
    int port;                   // tcp listen port
};

struct tcp_connect_key_t {
    int tgid;                   // process id
    struct ip ip_addr;          // tcp listen ip address
};

struct endpoint_key_t {
    enum endpoint_t type;
    union {
        struct udp_client_key_t udp_client_key;
        struct udp_server_key_t udp_server_key;
        struct tcp_listen_key_t tcp_listen_key;
        struct tcp_connect_key_t tcp_connect_key;
    } key;
};

struct endpoint_val_t {
    __u64 ts;
    int udp_err_code;
    struct endpoint_key_t key;
    struct endpoint_stats ep_stats;
};

struct endpoint_args_s {
    __u64 period;               // Sampling period, unit ns
    __u32 filter_by_task;       // Filtering PID monitoring ranges by task probe
    __u32 filter_by_tgid;       // Filtering PID monitoring ranges by specific pid
};

#endif
