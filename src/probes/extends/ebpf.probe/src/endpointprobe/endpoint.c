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
 * Author: algorithmofdish
 * Create: 2021-10-25
 * Description: endpoint_probe user prog
 ******************************************************************************/
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sched.h>
#include <fcntl.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include <bpf/bpf.h>
#include "bpf.h"
#include "tcp.skel.h"
#include "udp.skel.h"
#include "tcp.h"
#include "event.h"
#include "ipc.h"
#include "hash.h"
#include "conntrack.h"
#include "container.h"
#include "delaying_ring_buffer.h"
#include "flowtracer_reader.h"
#include "histogram.h"
#include "endpoint.h"

#define EP_ENTITY_ID_LEN 64
#define CAPACITY         4096
#define DELAY_MS         500
#define RM_ENDPOINT_MAP_PATH "/usr/bin/rm -rf /sys/fs/bpf/gala-gopher/__endpoint*"

#define OO_TCP_SOCK     "endpoint_tcp"
#define OO_UDP_SOCK     "endpoint_udp"

#define OPEN_TCP_PROBE(probe_name, end, load, buffer) \
    INIT_OPEN_OPTS(probe_name); \
    PREPARE_CUSTOM_BTF(probe_name); \
    OPEN_OPTS(probe_name, end, load); \
    MAP_INIT_BPF_BUFFER(probe_name, tcp_evt_map, buffer, load);

#define OPEN_UDP_PROBE(probe_name, end, load, buffer) \
    INIT_OPEN_OPTS(probe_name); \
    PREPARE_CUSTOM_BTF(probe_name); \
    OPEN_OPTS(probe_name, end, load); \
    MAP_INIT_BPF_BUFFER(probe_name, udp_evt_map, buffer, load);

// unit: ns
enum estab_latency_range_t {
    LT_RANGE_1 = 0,         // (0 ~ 3]ms
    LT_RANGE_2,             // (3 ~ 10]ms
    LT_RANGE_3,             // (10 ~ 50]ms
    LT_RANGE_4,             // (50 ~ 100]ms
    LT_RANGE_5,             // (100 ~ 500]ms
    LT_RANGE_6,             // (500 ~ 1000]ms
    LT_RANGE_7,            // (1000 ~ 10000]ms

    __MAX_LT_RANGE
};

struct estab_latency_histo_s {
    enum estab_latency_range_t range;
    u64 min, max;
};

struct estab_latency_histo_s estab_latency_histios[__MAX_LT_RANGE] = {
    {LT_RANGE_1, 0,          3000000},
    {LT_RANGE_2, 3000000,    10000000},
    {LT_RANGE_3, 10000000,   50000000},
    {LT_RANGE_4, 50000000,   100000000},
    {LT_RANGE_5, 100000000,  500000000},
    {LT_RANGE_6, 500000000,  1000000000},
    {LT_RANGE_7, 1000000000, 10000000000}
};
struct tcp_listen_s {
    H_HANDLE;
    struct tcp_listen_key_s key;
    struct tcp_listen_val_s val;
};

struct tcp_socket_id_s {
    int tgid;                   // process id
    int is_multi;                // 1: multi procs listen to one sock
    enum socket_role_e role;
    struct conn_addr_s client_ipaddr;
    struct conn_addr_s server_ipaddr;
    struct conn_addr_s toa_client_ipaddr;
};

struct tcp_socket_s {
    H_HANDLE;
    struct tcp_socket_id_s id;
    int inactive;
    char *client_ip;
    char *server_ip;
    char *toa_client_ip;
    u64 stats[EP_STATS_MAX];
    time_t last_rcv_data;

    struct histo_bucket_s estab_latency_buckets[__MAX_LT_RANGE];
};

struct udp_socket_id_s {
    int tgid;                   // process id
    struct conn_addr_s local_ipaddr;
    struct conn_addr_s remote_ipaddr;
};

struct udp_socket_s {
    H_HANDLE;
    struct udp_socket_id_s id;
    u64 stats[EP_STATS_MAX];
    char *local_ip;
    char *remote_ip;
    time_t last_rcv_data;
};

// 缓存toa映射，仅接收syn包时(conn_request事件)会触发
struct toa_socket_s {
    H_HANDLE;
    struct tcp_socket_id_s id;
    struct conn_addr_s toa_client_ipaddr;
};

struct endpoint_probe_s {
    struct ipc_body_s ipc_body;
    struct bpf_prog_s* prog;
    int listen_port_fd;
    struct udp_socket_s *udps;
    struct tcp_socket_s *tcps;
    struct toa_socket_s *toas;
    struct tcp_listen_s *listens;
    int tcp_socks_num;
    int udp_socks_num;
    time_t last_report;
    struct delaying_ring_buffer *drb;
};

static volatile sig_atomic_t g_stop;
static struct endpoint_probe_s g_ep_probe;

static char is_snooper(struct endpoint_probe_s *probe, int tgid)
{
    struct snooper_obj_s *snooper;
    for (int i = 0; i < probe->ipc_body.snooper_obj_num; i++) {
        if (probe->ipc_body.snooper_objs[i].type == SNOOPER_OBJ_PROC) {
            snooper = &(probe->ipc_body.snooper_objs[i]);
            if (snooper->obj.proc.proc_id == (unsigned int )tgid) {
                return 1;
            }
        }
    }
    return 0;
}

static void free_tcp_sock(struct tcp_socket_s *tcp_sock)
{
    if (tcp_sock == NULL) {
        return;
    }

    if (tcp_sock->client_ip != NULL) {
        free(tcp_sock->client_ip);
    }

    if (tcp_sock->server_ip != NULL) {
        free(tcp_sock->server_ip);
    }

    if (tcp_sock->toa_client_ip != NULL) {
        free(tcp_sock->toa_client_ip);
    }

    free(tcp_sock);
    return;
}

static void free_toa_sock(struct toa_socket_s *toa_sock)
{
    if (toa_sock == NULL) {
        return;
    }
    free(toa_sock);
    return;
}

static void free_udp_sock(struct udp_socket_s *udp_sock)
{
    if (udp_sock == NULL) {
        return;
    }

    if (udp_sock->local_ip != NULL) {
        free(udp_sock->local_ip);
    }

    if (udp_sock->remote_ip != NULL) {
        free(udp_sock->remote_ip);
    }
    free(udp_sock);
    return;
}

static void destroy_tcp_socks(struct endpoint_probe_s *probe)
{
    struct tcp_socket_s *tcp, *tmp;

    H_ITER(probe->tcps, tcp, tmp) {
        H_DEL(probe->tcps, tcp);
        free_tcp_sock(tcp);
    }
    probe->tcps = NULL;
    return;
}

static void destroy_toa_socks(struct endpoint_probe_s *probe)
{
    struct toa_socket_s *toa, *tmp;

    H_ITER(probe->toas, toa, tmp) {
        H_DEL(probe->toas, toa);
        free_toa_sock(toa);
    }
    probe->toas = NULL;
    return;
}

static void destroy_tcp_listens(struct endpoint_probe_s *probe)
{
    struct tcp_listen_s *listen, *tmp;

    H_ITER(probe->listens, listen, tmp) {
        H_DEL(probe->listens, listen);
        free(listen);
    }
    probe->listens = NULL;
    return;
}

static void destroy_udp_socks(struct endpoint_probe_s *probe)
{
    struct udp_socket_s *udp, *tmp;

    H_ITER(probe->udps, udp, tmp) {
        H_DEL(probe->udps, udp);
        free_udp_sock(udp);
    }
    probe->udps = NULL;
    return;
}

static char tcp_sock_inactive(struct tcp_socket_s *tcp)
{
#define __INACTIVE_TIME_SECS     (10 * 60)       // 10min
    time_t current = time(NULL);
    time_t secs;

    if (tcp->inactive) {
        return 1;
    }

    if (current > tcp->last_rcv_data) {
        secs = current - tcp->last_rcv_data;
        if (secs >= __INACTIVE_TIME_SECS) {
            return 1;
        }
    }

    return 0;
}

static char udp_sock_inactive(struct udp_socket_s *udp)
{
#define __INACTIVE_TIME_SECS     (10 * 60)       // 10min
    time_t current = time(NULL);
    time_t secs;

    if (current > udp->last_rcv_data) {
        secs = current - udp->last_rcv_data;
        if (secs >= __INACTIVE_TIME_SECS) {
            return 1;
        }
    }

    return 0;
}

static void aging_endpoint_socks(struct endpoint_probe_s *probe)
{
    struct tcp_socket_s *tcp, *tmp_tcp;
    struct udp_socket_s *udp, *tmp_udp;

    H_ITER(probe->tcps, tcp, tmp_tcp) {
        if (tcp_sock_inactive(tcp)) {
            H_DEL(probe->tcps, tcp);
            free_tcp_sock(tcp);
            probe->tcp_socks_num--;
        }
    }

    H_ITER(probe->udps, udp, tmp_udp) {
        if (udp_sock_inactive(udp)) {
            H_DEL(probe->udps, udp);
            free_udp_sock(udp);
            probe->udp_socks_num--;
        }
    }
}

static struct tcp_listen_s* lkup_tcp_listen(struct endpoint_probe_s *probe, const struct tcp_listen_key_s *key)
{
    struct tcp_listen_s* listen = NULL;

    H_FIND(probe->listens, key, sizeof(struct tcp_listen_key_s), listen);
    return listen;
}

static struct tcp_socket_s* lkup_tcp_socket(struct endpoint_probe_s *probe, const struct tcp_socket_id_s *id)
{
    struct tcp_socket_s* tcp = NULL;

    H_FIND(probe->tcps, id, sizeof(struct tcp_socket_id_s), tcp);
    return tcp;
}

static struct udp_socket_s* lkup_udp_socket(struct endpoint_probe_s *probe, const struct udp_socket_id_s *id)
{
    struct udp_socket_s* udp = NULL;

    H_FIND(probe->udps, id, sizeof(struct udp_socket_id_s), udp);
    return udp;
}

static struct toa_socket_s *lkup_toa_socket(struct endpoint_probe_s *probe, const struct tcp_socket_id_s *id)
{
    struct toa_socket_s *toa = NULL;
    H_FIND(probe->toas, id, sizeof(struct tcp_socket_id_s), toa);
    return toa;
}

static void output_tcp_socket(struct tcp_socket_s* tcp_sock)
{
    char estab_latency_histogram[MAX_HISTO_SERIALIZE_SIZE];
    estab_latency_histogram[0] = 0;

    if (serialize_histo(tcp_sock->estab_latency_buckets, __MAX_LT_RANGE, estab_latency_histogram, MAX_HISTO_SERIALIZE_SIZE)) {
        return;
    }

    (void)fprintf(stdout,
        "|%s|%d|%s|%s|%s|%s|%u|%u|%d"
        "|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu"
        "|%s|\n",
        OO_TCP_SOCK,
        tcp_sock->id.tgid,
        (tcp_sock->id.role == TCP_SERVER) ? "server" : "client",
        tcp_sock->client_ip,
        tcp_sock->toa_client_ip ? : "",
        tcp_sock->server_ip,
        tcp_sock->id.server_ipaddr.port,
        tcp_sock->id.server_ipaddr.family,
        tcp_sock->id.is_multi,

        tcp_sock->stats[EP_STATS_LISTEN_DROPS],
        tcp_sock->stats[EP_STATS_ACCEPT_OVERFLOW],
        tcp_sock->stats[EP_STATS_SYN_OVERFLOW],
        tcp_sock->stats[EP_STATS_PASSIVE_OPENS],
        tcp_sock->stats[EP_STATS_PASSIVE_FAILS],
        tcp_sock->stats[EP_STATS_RETRANS_SYNACK],
        tcp_sock->stats[EP_STATS_RETRANS_SYN],
        tcp_sock->stats[EP_STATS_REQ_DROP],
        tcp_sock->stats[EP_STATS_ACTIVE_OPENS],
        tcp_sock->stats[EP_STATS_ACTIVE_FAILS],
        tcp_sock->stats[EP_STATS_SYN_SENT],
        tcp_sock->stats[EP_STATS_SYN_DROP],
        tcp_sock->stats[EP_STATS_SYNACK_SENT],

        estab_latency_histogram);
    (void)fflush(stdout);
}

static void output_udp_socket(struct udp_socket_s* udp_sock)
{
    (void)fprintf(stdout,
        "|%s|%d|%s|%s|%u"
        "|%llu|%llu|%llu|\n",
        OO_UDP_SOCK,
        udp_sock->id.tgid,
        udp_sock->local_ip,
        udp_sock->remote_ip,
        udp_sock->id.local_ipaddr.family,

        udp_sock->stats[EP_STATS_QUE_RCV_FAILED],
        udp_sock->stats[EP_STATS_UDP_SENDS],
        udp_sock->stats[EP_STATS_UDP_RCVS]);
    (void)fflush(stdout);
}

static void process_tcp_establish_latency(struct tcp_socket_s *tcp, struct tcp_socket_event_s* evt)
{
    if (evt->evt != EP_STATS_ACTIVE_OPENS && evt->evt != EP_STATS_PASSIVE_OPENS) {
        return;
    }

    (void)histo_bucket_add_value(tcp->estab_latency_buckets, __MAX_LT_RANGE, evt->estab_latency);
}

static void init_tcp_sock_latency_buckets(struct histo_bucket_s latency_buckets[], size_t size)
{
    for (size_t i = 0; i < size; i++) {
        (void)init_histo_bucket(&(latency_buckets[i]), estab_latency_histios[i].min, estab_latency_histios[i].max);
    }
}

static int process_tcp_conn_close(struct tcp_socket_s *tcp, struct tcp_socket_event_s* evt)
{
    if (evt->evt != EP_STATS_CONN_CLOSE) {
        return 1;
    }

    if (tcp) {
        tcp->inactive = 1;
    }
    return 0;
}

static void transform_cluster_ip(struct endpoint_probe_s *probe_mng, struct tcp_socket_id_s *tracker)
{
    int transform = ADDR_TRANSFORM_NONE;

    char cluster_ip_backend = probe_mng->ipc_body.probe_param.cluster_ip_backend;
    if (cluster_ip_backend == 0) {
        return;
    }

    struct tcp_connect_s connect;

    connect.role = (tracker->role == TCP_CLIENT) ? 1 : 0;
    connect.family = tracker->client_ipaddr.family;

    if (connect.family == AF_INET) {
        connect.cip_addr.c_ip = tracker->client_ipaddr.ip;
        connect.sip_addr.s_ip = tracker->server_ipaddr.ip;
    } else {
        memcpy(&(connect.cip_addr), tracker->client_ipaddr.ip6, IP6_LEN);
        memcpy(&(connect.sip_addr), tracker->server_ipaddr.ip6, IP6_LEN);
    }
    connect.c_port = tracker->client_ipaddr.port;
    connect.s_port = tracker->server_ipaddr.port;

    if (cluster_ip_backend == 1) { // use conntrack
        // Only transform Kubernetes cluster IP backend for the client TCP connection.
        if (connect.role != 1) {
            return;
        }
        (void)get_cluster_ip_backend(&connect, &transform);
    } else if (cluster_ip_backend == 2) { // use FlowTracer
        transform = lookup_flowtracer(&connect);
        DEBUG("[EPPROBE] FlowTracer transform: %d\n", transform);
    }

    if (!transform) {
        return;
    }

#ifdef GOPHER_DEBUG
    char s_ip1[IP6_STR_LEN], s_ip2[IP6_STR_LEN], c_ip1[IP6_STR_LEN], c_ip2[IP6_STR_LEN];
    inet_ntop(connect.family, &tracker->server_ipaddr.ip, s_ip1, sizeof(s_ip1));
    inet_ntop(connect.family, &connect.sip_addr, s_ip2, sizeof(s_ip2));
    inet_ntop(connect.family, &tracker->client_ipaddr.ip, c_ip1, sizeof(c_ip1));
    inet_ntop(connect.family, &connect.cip_addr, c_ip2, sizeof(c_ip2));
    DEBUG("[EPPROBE]: Flow (%s:%u - %s:%u) is transformed into (%s:%u - %s:%u)\n",
            c_ip1, tracker->client_ipaddr.port, s_ip1, tracker->server_ipaddr.port,
            c_ip2, connect.c_port, s_ip2, connect.s_port);
#endif

    if (transform & ADDR_TRANSFORM_SERVER) {
        if (connect.family == AF_INET) {
            tracker->server_ipaddr.ip = connect.sip_addr.s_ip;
        } else {
            memcpy(tracker->server_ipaddr.ip6, &(connect.sip_addr.s_ip6), IP6_LEN);
        }
        tracker->server_ipaddr.port = connect.s_port;
    }
    if (transform & ADDR_TRANSFORM_CLIENT) {
        if (connect.family == AF_INET) {
            tracker->client_ipaddr.ip = connect.cip_addr.c_ip;
        } else {
            memcpy(tracker->client_ipaddr.ip6, &(connect.cip_addr.c_ip6), IP6_LEN);
        }
        tracker->client_ipaddr.port = connect.c_port;
    }

    return;
}

static void get_toa_socket(struct endpoint_probe_s *probe, const struct tcp_socket_event_s *evt,
                           const struct tcp_socket_id_s *id)
{
    struct toa_socket_s *new_toa;

    new_toa = lkup_toa_socket(probe, id);
    if (new_toa) {
        memcpy(&(new_toa->toa_client_ipaddr), &(evt->toa_client_ipaddr), sizeof(new_toa->toa_client_ipaddr));
    } else {
        new_toa = (struct toa_socket_s *)calloc(1, sizeof(struct toa_socket_s));
        if (new_toa == NULL) {
            return;
        }
        memcpy(&(new_toa->id), id, sizeof(struct tcp_socket_id_s));
        memcpy(&(new_toa->toa_client_ipaddr), &(evt->toa_client_ipaddr), sizeof(new_toa->toa_client_ipaddr));
        H_ADD_KEYPTR(probe->toas, &new_toa->id, sizeof(struct tcp_socket_id_s), new_toa);
    }
    return;
}

void __init_tcp_socket_id(struct tcp_socket_id_s *id, const struct tcp_socket_event_s *evt)
{
    memcpy(&(id->client_ipaddr), &(evt->client_ipaddr), sizeof(id->client_ipaddr));
    memcpy(&(id->server_ipaddr), &(evt->server_ipaddr), sizeof(id->server_ipaddr));
    id->is_multi = evt->is_multi;
    id->tgid = (id->is_multi == 1) ? getpgid(evt->tgid) : (evt->tgid);
    id->role = evt->role;
}

#define MAX_ENDPOINT_ENTITES    (5 * 1024)
static int add_tcp_sock_evt(struct endpoint_probe_s * probe, struct tcp_socket_event_s* evt)
{
    struct tcp_socket_id_s id = {0};
    struct tcp_socket_s *tcp, *new_tcp;
    struct toa_socket_s *toa;
    unsigned char client_ip_str[INET6_ADDRSTRLEN];
    unsigned char server_ip_str[INET6_ADDRSTRLEN];
    unsigned char toa_client_ip_str[INET6_ADDRSTRLEN];

    if (!is_snooper(probe, evt->tgid)) {
        return 0;
    }

    __init_tcp_socket_id(&id, evt);

#ifdef GOPHER_DEBUG
    char s_ip[INET6_ADDRSTRLEN] = {0}, c_ip[INET6_ADDRSTRLEN] = {0};
    (void)inet_ntop(id.server_ipaddr.family, (const void *)&(id.server_ipaddr.ip), s_ip, sizeof(s_ip));
    (void)inet_ntop(id.client_ipaddr.family, (const void *)&(id.client_ipaddr.ip), c_ip, sizeof(c_ip));
    DEBUG("[EPPROBE]: tcp socket event %d, role: %d, observed flow: (%s:%u - %s:%u), tgid: %d\n",
            evt->evt, evt->role, c_ip, id.client_ipaddr.port, s_ip, id.server_ipaddr.port, id.tgid);
#endif

    transform_cluster_ip(probe, &id);

    // syn_toa_recv事件到达，刷入toa表，处理toa表时仍需要client_port
    if (evt->evt == EP_STATS_SYN_TOA_RECV) {
        get_toa_socket(probe, evt, (const struct tcp_socket_id_s *)&id);
        return 0;
    }

    // 非syn_toa_recv事件，先查找一遍toa表，替换id中的c_ip和c_family
    toa = lkup_toa_socket(probe, (const struct tcp_socket_id_s *)&id);
    if (toa) {
        // 连接关闭事件，清理掉toa_socket表中元素
        if (evt->evt == EP_STATS_CONN_CLOSE) {
            H_DEL(probe->toas, toa);
            free(toa);
        } else {
            memcpy(&(id.toa_client_ipaddr), &(toa->toa_client_ipaddr), sizeof(id.toa_client_ipaddr));
        }
    }

    // 处理tcp_socket表时忽略client_port
    id.client_ipaddr.port = 0;
    tcp = lkup_tcp_socket(probe, (const struct tcp_socket_id_s *)&id);
    if (process_tcp_conn_close(tcp, evt) == 0) {
        return 0;
    }

    if (tcp) {
        process_tcp_establish_latency(tcp, evt);
        tcp->stats[evt->evt]++;
        tcp->last_rcv_data = time(NULL);
        tcp->inactive = 0;
        return 0;
    }

    if (probe->tcp_socks_num >= MAX_ENDPOINT_ENTITES) {
        ERROR("[ENDPOINTPROBE]: Create tcp sockets failed(upper to limited).\n");
        return -1;
    }

    new_tcp = (struct tcp_socket_s *)malloc(sizeof(struct tcp_socket_s));
    if (new_tcp == NULL) {
        return -1;
    }
    memset(new_tcp, 0, sizeof(struct tcp_socket_s));
    memcpy(&(new_tcp->id), &id, sizeof(id));
    init_tcp_sock_latency_buckets(new_tcp->estab_latency_buckets, __MAX_LT_RANGE);

    process_tcp_establish_latency(new_tcp, evt);
    new_tcp->stats[evt->evt] += 1;
    new_tcp->last_rcv_data = time(NULL);

    ip_str(new_tcp->id.client_ipaddr.family, (unsigned char *)&(new_tcp->id.client_ipaddr.ip), client_ip_str, INET6_ADDRSTRLEN);
    ip_str(new_tcp->id.server_ipaddr.family, (unsigned char *)&(new_tcp->id.server_ipaddr.ip), server_ip_str, INET6_ADDRSTRLEN);
    new_tcp->client_ip = strdup((const char *)client_ip_str);
    new_tcp->server_ip = strdup((const char *)server_ip_str);
    if (new_tcp->id.toa_client_ipaddr.family == AF_INET || new_tcp->id.toa_client_ipaddr.family == AF_INET6) {
        ip_str(new_tcp->id.toa_client_ipaddr.family, (unsigned char *)&(new_tcp->id.toa_client_ipaddr.ip), toa_client_ip_str, INET6_ADDRSTRLEN);
        new_tcp->toa_client_ip = strdup((const char *)toa_client_ip_str);
    }

    if (new_tcp->client_ip == NULL || new_tcp->server_ip == NULL) {
        goto err;
    }

    H_ADD_KEYPTR(probe->tcps, &new_tcp->id, sizeof(struct tcp_socket_id_s), new_tcp);
    probe->tcp_socks_num++;
    return 0;
err:
    free_tcp_sock(new_tcp);
    return -1;
}

static int add_udp_sock_evt(struct endpoint_probe_s * probe, struct udp_socket_event_s* evt)
{
    struct udp_socket_id_s id;
    struct udp_socket_s *udp, *new_udp;
    unsigned char local_ip_str[INET6_ADDRSTRLEN];
    unsigned char remote_ip_str[INET6_ADDRSTRLEN];

    if (!is_snooper(probe, evt->tgid)) {
        return 0;
    }

    memcpy(&(id.local_ipaddr), &(evt->local_ipaddr), sizeof(id.local_ipaddr));
    memcpy(&(id.remote_ipaddr), &(evt->remote_ipaddr), sizeof(id.remote_ipaddr));
    id.tgid = evt->tgid;
    id.local_ipaddr.port = 0;
    id.remote_ipaddr.port = 0;

    udp = lkup_udp_socket(probe, (const struct udp_socket_id_s *)&id);
    if (udp) {
        udp->stats[evt->evt] += evt->val;
        udp->last_rcv_data = time(NULL);
        return 0;
    }

    if (probe->udp_socks_num >= MAX_ENDPOINT_ENTITES) {
        return -1;
    }

    new_udp = (struct udp_socket_s *)malloc(sizeof(struct udp_socket_s));
    if (new_udp == NULL) {
        return -1;
    }
    memset(new_udp, 0, sizeof(struct udp_socket_s));
    memcpy(&(new_udp->id), &id, sizeof(id));
    new_udp->stats[evt->evt] += evt->val;
    new_udp->last_rcv_data = time(NULL);

    ip_str(new_udp->id.local_ipaddr.family, (unsigned char *)&(new_udp->id.local_ipaddr.ip), local_ip_str, INET6_ADDRSTRLEN);
    ip_str(new_udp->id.remote_ipaddr.family, (unsigned char *)&(new_udp->id.remote_ipaddr.ip), remote_ip_str, INET6_ADDRSTRLEN);
    new_udp->local_ip = strdup((const char *)local_ip_str);
    new_udp->remote_ip = strdup((const char *)remote_ip_str);

    if (new_udp->local_ip == NULL || new_udp->remote_ip == NULL) {
        goto err;
    }

    H_ADD_KEYPTR(probe->udps, &new_udp->id, sizeof(struct udp_socket_id_s), new_udp);
    probe->udp_socks_num++;
    return 0;
err:
    free_udp_sock(new_udp);
    return -1;
}

static int proc_tcp_sock_evt(void *ctx, void *data, u32 size)
{
    struct endpoint_probe_s *probe = ctx;
    if (drb_put(probe->drb, data, size)) {
        WARN("[EPPROBE] Not enough space to put event into the ring buffer. Event is discarded.\n");
    }
    return 0;
}

static int proc_tcp_sock_evt_continue(void *ctx, void *data, u32 size)
{
    char *p = data;
    size_t remain_size = (size_t)size, step_size = sizeof(struct tcp_socket_event_s), offset = 0;
    struct tcp_socket_event_s *evt;
    struct endpoint_probe_s *probe = ctx;

    do {
        if (remain_size < step_size) {
            break;
        }
        p = (char *)data + offset;
        evt  = (struct tcp_socket_event_s *)p;

        (void)add_tcp_sock_evt(probe, evt);

        offset += step_size;
        remain_size -= step_size;
    } while (1);

    return 0;
}

static int proc_udp_sock_evt(void *ctx, void *data, u32 size)
{
    char *p = data;
    size_t remain_size = (size_t)size, step_size = sizeof(struct udp_socket_event_s), offset = 0;
    struct udp_socket_event_s *evt;
    struct endpoint_probe_s *probe = ctx;

    do {
        if (remain_size < step_size) {
            break;
        }
        p = (char *)data + offset;
        evt  = (struct udp_socket_event_s *)p;

        (void)add_udp_sock_evt(probe, evt);

        offset += step_size;
        remain_size -= step_size;
    } while (1);

    return 0;
}

static void sig_int(int signo)
{
    g_stop = 1;
}

static int get_netns_fd(pid_t pid)
{
    const char *fmt = "/proc/%d/ns/net";
    char path[PATH_LEN];

    path[0] = 0;
    (void)snprintf(path, PATH_LEN, fmt, pid);
    return open(path, O_RDONLY);
}

static int add_tcp_listen(struct endpoint_probe_s *probe, struct tcp_listen_port *tlp, int ino)
{
    struct tcp_listen_key_s key;
    struct tcp_listen_s *listen;

    key.inode = ino;

    listen = lkup_tcp_listen(probe, (const struct tcp_listen_key_s *)&key);
    if (listen) {
        if (listen->val.proc_id == tlp->pid) {
            return 0;
        } else if (listen->val.is_multi == 1) {
            return 0;
        } else {
            listen->val.is_multi = 1;
            return 0;
        }
    }

    listen = (struct tcp_listen_s *)malloc(sizeof(struct tcp_listen_s));
    if (listen == NULL) {
        return -1;
    }
    memset(listen, 0, sizeof(struct tcp_listen_s));
    memcpy(&(listen->key), &key, sizeof(key));
    listen->val.proc_id = tlp->pid;
    H_ADD_KEYPTR(probe->listens, &listen->key, sizeof(struct tcp_listen_key_s), listen);
    return 0;
}

static void load_tcp_listens(struct endpoint_probe_s *probe)
{
    int ret;
    struct tcp_listen_ports* tlps;
    struct tcp_listen_port *tlp;

    tlps = get_listen_ports();
    if (tlps == NULL) {
        goto err;
    }

    for (int i = 0; i < tlps->tlp_num; i++) {
        tlp = tlps->tlp[i];
        if (tlp && is_snooper(probe, tlp->pid)) {
            unsigned long ino;
            ret = get_listen_sock_inode(tlp, &ino);
            if (ret < 0) {
                ERROR("[EPPROBE]: get listen sock inode failed.(PID = %u, COMM = %s, PORT = %u)\n",
                    tlp->pid, tlp->comm, tlp->port);
                continue;
            }
            ret = add_tcp_listen(probe, tlp, ino);
            if (ret) {
                ERROR("[EPPROBE]: Add listen port failed.(PID = %u, COMM = %s, PORT = %u)\n",
                    tlp->pid, tlp->comm, tlp->port);
            } else {
                INFO("[EPPROBE]: Add listen port succeed.(PID = %u, COMM = %s, PORT = %u)\n",
                    tlp->pid, tlp->comm, tlp->port);
            }
        }
    }

err:
    if (tlps) {
        free_listen_ports(&tlps);
    }

    return;
}

static void reload_listen_port(struct endpoint_probe_s *probe)
{
    int ret, netns_fd;
    struct snooper_con_info_s *container;
    struct ipc_body_s *ipc_body = &probe->ipc_body;

    destroy_tcp_listens(probe);

    netns_fd = get_netns_fd(getpid());
    if (netns_fd <= 0) {
        ERROR("[EPPROBE]: Get netns fd failed.\n");
        return;
    }

    load_tcp_listens(probe);

    for (int i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        if (ipc_body->snooper_objs[i].type != SNOOPER_OBJ_CON) {
            continue;
        }

        container = &(ipc_body->snooper_objs[i].obj.con_info);
        ret = enter_container_netns((const char *)container->con_id);
        if (ret) {
            ERROR("[EPPROBE]: Enter container netns failed.(container_name = %s)\n", container->container_name);
            continue;
        }

        load_tcp_listens(probe);

        (void)exit_container_netns(netns_fd);
    }

    (void)close(netns_fd);
    return;
}

static void reload_listen_map(struct endpoint_probe_s *probe)
{
    struct tcp_listen_val_s value;
    struct tcp_listen_key_s k = {0};
    struct tcp_listen_key_s nk = {0};
    struct tcp_listen_s *listen, *tmp;

    while (bpf_map_get_next_key(probe->listen_port_fd, &k, &nk) == 0) {
        (void)bpf_map_lookup_elem(probe->listen_port_fd, &nk, &value);
        (void)bpf_map_delete_elem(probe->listen_port_fd, &nk);
    }

    H_ITER(probe->listens, listen, tmp) {
        (void)bpf_map_update_elem(probe->listen_port_fd, &(listen->key), &(listen->val), BPF_ANY);
    }
    return;
}

#ifdef ENABLE_REPORT_EVENT
static void build_tcp_id(struct tcp_socket_s *tcp_sock, char *buf, int buf_len)
{
    (void)snprintf(buf, buf_len, "%d_%s_%s_%u_%u",
                    tcp_sock->id.tgid,
                    tcp_sock->client_ip,
                    tcp_sock->server_ip,
                    tcp_sock->id.server_ipaddr.port,
                    tcp_sock->id.role);
    return;
}

static void build_tcp_lable(struct tcp_socket_s *tcp_sock, struct event_info_s *evt)
{
    (void)snprintf(evt->ip, sizeof(evt->ip),
        "Client %s, Server %s:%u",
        tcp_sock->client_ip,
        tcp_sock->server_ip,
        tcp_sock->id.server_ipaddr.port);
    evt->pid = tcp_sock->id.tgid;
    return;
}

static void report_tcp_sock(struct tcp_socket_s *tcp_sock)
{
    char entityId[EP_ENTITY_ID_LEN];
    struct event_info_s evt = {0};

    if (tcp_sock->stats[EP_STATS_LISTEN_DROPS] > 0) {
        build_tcp_id(tcp_sock, entityId, EP_ENTITY_ID_LEN);

        evt.metrics = "listendrop";
        evt.entityId = entityId;
        evt.entityName = OO_TCP_SOCK;
        build_tcp_lable(tcp_sock, &evt);

        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "TCP listen drops(%llu).",
                    tcp_sock->stats[EP_STATS_LISTEN_DROPS]);
    }

    if (tcp_sock->stats[EP_STATS_ACCEPT_OVERFLOW] != 0) {
        if (entityId[0] == 0)
            build_tcp_id(tcp_sock, entityId, EP_ENTITY_ID_LEN);

        evt.metrics = "accept_overflow";
        evt.entityId = entityId;
        evt.entityName = OO_TCP_SOCK;
        build_tcp_lable(tcp_sock, &evt);

        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "TCP accept queue overflow(%llu).",
                    tcp_sock->stats[EP_STATS_ACCEPT_OVERFLOW]);
    }

    if (tcp_sock->stats[EP_STATS_SYN_OVERFLOW] != 0) {
        if (entityId[0] == 0)
            build_tcp_id(tcp_sock, entityId, EP_ENTITY_ID_LEN);

        evt.metrics = "syn_overflow";
        evt.entityId = entityId;
        evt.entityName = OO_TCP_SOCK;
        build_tcp_lable(tcp_sock, &evt);

        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "TCP syn queue overflow(%llu).",
                    tcp_sock->stats[EP_STATS_SYN_OVERFLOW]);
    }

    if (tcp_sock->stats[EP_STATS_RETRANS_SYNACK] != 0) {
        if (entityId[0] == 0)
            build_tcp_id(tcp_sock, entityId, EP_ENTITY_ID_LEN);

        evt.metrics = "retran_synacks";
        evt.entityId = entityId;
        evt.entityName = OO_TCP_SOCK;
        build_tcp_lable(tcp_sock, &evt);
        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "TCP SYN/ACK retransmission occurs.(%llu).",
                    tcp_sock->stats[EP_STATS_RETRANS_SYNACK]);
    }

    if (tcp_sock->stats[EP_STATS_REQ_DROP] != 0) {
        if (entityId[0] == 0)
            build_tcp_id(tcp_sock, entityId, EP_ENTITY_ID_LEN);

        evt.metrics = "req_drops";
        evt.entityId = entityId;
        evt.entityName = OO_TCP_SOCK;
        build_tcp_lable(tcp_sock, &evt);
        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "TCP request drops(listen closed).(%llu).",
                    tcp_sock->stats[EP_STATS_REQ_DROP]);
    }
    return;
}

static void report_tcp_socks(struct endpoint_probe_s * probe)
{
    struct tcp_socket_s *tcp, *tcp_tmp;

    if (probe->ipc_body.probe_param.logs == 0)
        return;

    H_ITER(probe->tcps, tcp, tcp_tmp) {
        report_tcp_sock(tcp);
    }
    return;
}
#else
static void report_tcp_socks(struct endpoint_probe_s * probe)
{
    return;
}
#endif

static int endpoint_load_probe_tcp(struct endpoint_probe_s *probe, struct bpf_prog_s *prog, char is_load)
{
    struct bpf_buffer *buffer = NULL;

    OPEN_TCP_PROBE(tcp, err, is_load, buffer);
    if (is_load) {

        int kernel_version = probe_kernel_version();
        PROG_ENABLE_ONLY_IF(tcp, bpf_raw_trace_tcp_retransmit_synack, kernel_version > KERNEL_VERSION(4, 18, 0));
        PROG_ENABLE_ONLY_IF(tcp, bpf_trace_tcp_retransmit_synack_func, kernel_version <= KERNEL_VERSION(4, 18, 0));

        LOAD_ATTACH(endpoint, tcp, err, is_load);

        prog->skels[prog->num].skel = tcp_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)tcp_bpf__destroy;
        prog->custom_btf_paths[prog->num] = tcp_open_opts.btf_custom_path;

        int ret = bpf_buffer__open(buffer, proc_tcp_sock_evt, NULL, probe);
        if (ret) {
            ERROR("[ENDPOINT] Open 'tcp_evt_map' bpf_buffer failed.\n");
            goto err;
        }
        prog->buffers[prog->num] = buffer;
        prog->num++;
        probe->listen_port_fd = GET_MAP_FD(tcp, tcp_listen_port);
    }

    return 0;
err:
    bpf_buffer__free(buffer);
    UNLOAD(tcp);
    CLEANUP_CUSTOM_BTF(tcp);
    return -1;
}

static int endpoint_load_probe_udp(struct endpoint_probe_s *probe, struct bpf_prog_s *prog, char is_load)
{
    struct bpf_buffer *buffer = NULL;

    OPEN_UDP_PROBE(udp, err, is_load, buffer);
    if (is_load) {

        LOAD_ATTACH(endpoint, udp, err, is_load);

        prog->skels[prog->num].skel = udp_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)udp_bpf__destroy;
        prog->custom_btf_paths[prog->num] = udp_open_opts.btf_custom_path;

        int ret = bpf_buffer__open(buffer, proc_udp_sock_evt, NULL, probe);
        if (ret) {
            ERROR("[ENDPOINT] Open 'udp_evt_map' bpf_buffer failed.\n");
            goto err;
        }
        prog->buffers[prog->num] = buffer;
        prog->num++;
    }

    return 0;
err:
    bpf_buffer__free(buffer);
    UNLOAD(udp);
    CLEANUP_CUSTOM_BTF(udp);
    return -1;
}

static int endpoint_load_probe(struct endpoint_probe_s *probe, struct ipc_body_s *ipc_body)
{
    char is_load_tcp, is_load_udp;
    struct bpf_prog_s *new_prog = NULL;

    is_load_tcp = ipc_body->probe_range_flags & PROBE_RANGE_SOCKET_TCP;
    is_load_udp = ipc_body->probe_range_flags & PROBE_RANGE_SOCKET_UDP;
    if (!(is_load_tcp | is_load_udp)) {
        return 0;
    }

    new_prog = alloc_bpf_prog();
    if (new_prog == NULL) {
        return -1;
    }

    if (endpoint_load_probe_tcp(probe, new_prog, is_load_tcp)) {
        goto err;
    }

    if (endpoint_load_probe_udp(probe, new_prog, is_load_udp)) {
        goto err;
    }

    probe->last_report = time(NULL);
    probe->prog = new_prog;
    return 0;

err:
    unload_bpf_prog(&new_prog);
    return -1;
}

static int poll_endpoint_pb(struct endpoint_probe_s *probe)
{
    int ret;
    struct bpf_prog_s* prog = probe->prog;

    if (prog == NULL) {
        return -1;
    }

    for (int i = 0; i < prog->num && i < SKEL_MAX_NUM; i++) {
        if (prog->buffers[i]) {
            ret = bpf_buffer__poll(prog->buffers[i], THOUSAND);
            if (ret < 0 && ret != -EINTR) {
                return ret;
            }
        }
    }

    return 0;
}

static void poll_drb(struct endpoint_probe_s *probe)
{
    const struct drb_item *item;
    while ((item = drb_look(probe->drb))) {
        proc_tcp_sock_evt_continue(probe, item->data, item->size);
        drb_pop(probe->drb);
    }
}

static char is_report_tmout(struct endpoint_probe_s *probe)
{
    time_t current = time(NULL);
    time_t secs;

    if (current > probe->last_report) {
        secs = current - probe->last_report;
        if (secs >= probe->ipc_body.probe_param.period) {
            probe->last_report = current;
            return 1;
        }
    }

    return 0;
}

static void reset_tcp_socket(struct tcp_socket_s* tcp_sock)
{
    memset(&(tcp_sock->stats), 0, sizeof(u64) * EP_STATS_MAX);
    (void)histo_bucket_reset(tcp_sock->estab_latency_buckets, __MAX_LT_RANGE);
}

static void reset_udp_socket(struct udp_socket_s* udp_sock)
{
    memset(&(udp_sock->stats), 0, sizeof(u64) * EP_STATS_MAX);
}

static void reset_endpoint_stats(struct endpoint_probe_s *probe)
{
    struct tcp_socket_s *tcp, *tcp_tmp;
    struct udp_socket_s *udp, *udp_tmp;

    H_ITER(probe->tcps, tcp, tcp_tmp) {
        reset_tcp_socket(tcp);
    }

    H_ITER(probe->udps, udp, udp_tmp) {
        reset_udp_socket(udp);
    }

    return;
}

static void report_endpoint(struct endpoint_probe_s *probe)
{
    struct tcp_socket_s *tcp, *tcp_tmp;
    struct udp_socket_s *udp, *udp_tmp;

    if (!is_report_tmout(probe)) {
        return;
    }

    H_ITER(probe->tcps, tcp, tcp_tmp) {
        output_tcp_socket(tcp);
    }

    H_ITER(probe->udps, udp, udp_tmp) {
        output_udp_socket(udp);
    }

    aging_endpoint_socks(probe);
    reset_endpoint_stats(probe);
    return;
}

static void clean_endpoint_pin_map()
{
    FILE *fp = popen(RM_ENDPOINT_MAP_PATH, "r");
    if (fp != NULL) {
        (void)pclose(fp);
        fp = NULL;
    }
}

int main(int argc, char **argv)
{
    int ret = -1, msq_id;
    struct ipc_body_s ipc_body;

    memset(&g_ep_probe, 0, sizeof(g_ep_probe));

    clean_endpoint_pin_map();

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        ERROR("[ENDPOINTPROBE] Can't set signal handler: %d\n", errno);
        return errno;
    }

    msq_id = create_ipc_msg_queue(IPC_EXCL);
    if (msq_id < 0) {
        ERROR("[ENDPOINTPROBE] Get ipc msg queue failed.\n");
        return -1;
    }

    g_ep_probe.drb = drb_new(CAPACITY, DELAY_MS);
    if (!g_ep_probe.drb) {
        ERROR("[ENDPOINTPROBE] Failed to allocate delaying ring buffer.\n");
        return -1;
    }

    INIT_BPF_APP(endpoint, EBPF_RLIM_LIMITED);
    INFO("[ENDPOINTPROBE] Successfully started!\n");

    while(!g_stop) {
        ret = recv_ipc_msg(msq_id, (long)PROBE_SOCKET, &ipc_body);
        if (ret == 0) {
            if (ipc_body.probe_range_flags != g_ep_probe.ipc_body.probe_range_flags) {
                unload_bpf_prog(&(g_ep_probe.prog));
                if (endpoint_load_probe(&g_ep_probe, &ipc_body)) {
                    break;
                }
            }

            /* Probe range was changed to 0 */
            if (g_ep_probe.prog == NULL) {
                continue;
            }

            destroy_ipc_body(&(g_ep_probe.ipc_body));
            (void)memcpy(&(g_ep_probe.ipc_body), &ipc_body, sizeof(g_ep_probe.ipc_body));
            reload_listen_port(&g_ep_probe);
            reload_listen_map(&g_ep_probe);
        }

        if (poll_endpoint_pb(&g_ep_probe)) {
            sleep(1);
        }

        poll_drb(&g_ep_probe);
        report_tcp_socks(&g_ep_probe);
        report_endpoint(&g_ep_probe);
    }

    destroy_tcp_socks(&g_ep_probe);
    destroy_toa_socks(&g_ep_probe);
    destroy_udp_socks(&g_ep_probe);
    destroy_tcp_listens(&g_ep_probe);

    unload_bpf_prog(&(g_ep_probe.prog));
    destroy_ipc_body(&(g_ep_probe.ipc_body));

    drb_destroy(g_ep_probe.drb);
    clean_endpoint_pin_map();
    return ret;
}
