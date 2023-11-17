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
#include "endpoint.h"
#include "tcp.h"
#include "event.h"
#include "ipc.h"
#include "hash.h"
#include "conntrack.h"

#define EP_ENTITY_ID_LEN 64

#define OO_TCP_SOCK     "endpoint_tcp"
#define OO_UDP_SOCK     "endpoint_udp"

#define __LOAD_ENDPOINT_PROBE(probe_name, end, load) \
    OPEN(probe_name, end, load); \
    LOAD_ATTACH(endpoint, probe_name, end, load)

struct tcp_socket_id_s {
    int tgid;                   // process id
    enum socket_role_e role;
    struct conn_addr_s client_ipaddr;
    struct conn_addr_s server_ipaddr;
};

struct tcp_socket_s {
    H_HANDLE;
    struct tcp_socket_id_s id;
    char *client_ip;
    char *server_ip;
    u64 stats[EP_STATS_MAX];
    time_t last_rcv_data;
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

struct endpoint_probe_s {
    struct ipc_body_s ipc_body;
    struct bpf_prog_s* prog;
    int tcp_output_fd;
    int udp_output_fd;
    struct udp_socket_s *udps;
    struct tcp_socket_s *tcps;
    int tcp_socks_num;
    int udp_socks_num;
    time_t last_report;
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
    free(tcp_sock);
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

void aging_tcp_socks(struct endpoint_probe_s *probe)
{
    struct tcp_socket_s *tcp, *tmp;

    H_ITER(probe->tcps, tcp, tmp) {
        if (tcp_sock_inactive(tcp)) {
            H_DEL(probe->tcps, tcp);
            free_tcp_sock(tcp);
            probe->tcp_socks_num--;
        }
    }
}

void aging_udp_socks(struct endpoint_probe_s *probe)
{
    struct udp_socket_s *udp, *tmp;

    H_ITER(probe->udps, udp, tmp) {
        if (udp_sock_inactive(udp)) {
            H_DEL(probe->udps, udp);
            free_udp_sock(udp);
            probe->udp_socks_num--;
        }
    }
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

static void output_tcp_socket(struct tcp_socket_s* tcp_sock)
{
    (void)fprintf(stdout,
        "|%s|%u|%s|%s|%s|%u|%u"
        "|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|\n",
        OO_TCP_SOCK,
        tcp_sock->id.tgid,
        (tcp_sock->id.role == TCP_SERVER) ? "server" : "client",
        tcp_sock->client_ip,
        tcp_sock->server_ip,
        tcp_sock->id.server_ipaddr.port,
        tcp_sock->id.server_ipaddr.family,

        tcp_sock->stats[EP_STATS_LISTEN_DROPS],
        tcp_sock->stats[EP_STATS_ACCEPT_OVERFLOW],
        tcp_sock->stats[EP_STATS_SYN_OVERFLOW],
        tcp_sock->stats[EP_STATS_PASSIVE_OPENS],
        tcp_sock->stats[EP_STATS_PASSIVE_FAILS],
        tcp_sock->stats[EP_STATS_RETRANS_SYNACK],
        tcp_sock->stats[EP_STATS_LOST_SYNACK],
        tcp_sock->stats[EP_STATS_REQ_DROP],
        tcp_sock->stats[EP_STATS_ACTIVE_OPENS],
        tcp_sock->stats[EP_STATS_ACTIVE_FAILS]);
    (void)fflush(stdout);
}

static void output_udp_socket(struct udp_socket_s* udp_sock)
{
    (void)fprintf(stdout,
        "|%s|%u|%s|%s|%u"
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

static void transform_cluster_ip(struct endpoint_probe_s * probe, struct tcp_socket_s *tcp_sock, struct tcp_socket_event_s* evt)
{
    int transform = 0;

    if (probe->ipc_body.probe_param.cluster_ip_backend == 0) {
        return;
    }

    // Only transform Kubernetes cluster IP backend for the client TCP connection.
    if (tcp_sock->id.role != TCP_CLIENT) {
        return;
    }

    struct tcp_connect_s connect;

    connect.role = (tcp_sock->id.role == TCP_CLIENT) ? 1 : 0;
    connect.family = tcp_sock->id.client_ipaddr.family;

    if (connect.family == AF_INET) {
        connect.cip_addr.c_ip = tcp_sock->id.client_ipaddr.ip;
        connect.sip_addr.s_ip = tcp_sock->id.server_ipaddr.ip;
    } else {
        memcpy(&(connect.cip_addr), &(tcp_sock->id.client_ipaddr.ip), IP6_LEN);
        memcpy(&(connect.sip_addr), &(tcp_sock->id.server_ipaddr.ip), IP6_LEN);
    }
    connect.c_port = evt->client_ipaddr.port;
    connect.s_port = evt->server_ipaddr.port;

    (void)get_cluster_ip_backend(&connect, &transform);
    if (!transform) {
        return;
    }

    if (connect.family == AF_INET) {
        tcp_sock->id.client_ipaddr.ip = connect.sip_addr.s_ip;
    } else {
        memcpy(&(tcp_sock->id.client_ipaddr.ip), &(connect.sip_addr), IP6_LEN);
    }
    tcp_sock->id.client_ipaddr.port = connect.s_port;
    return;
}

#define MAX_ENDPOINT_ENTITES    (5 * 1024)
static int add_tcp_sock_evt(struct endpoint_probe_s * probe, struct tcp_socket_event_s* evt)
{
    struct tcp_socket_id_s id;
    struct tcp_socket_s *tcp, *new_tcp;
    unsigned char client_ip_str[INET6_ADDRSTRLEN];
    unsigned char server_ip_str[INET6_ADDRSTRLEN];

    if (!is_snooper(probe, evt->tgid)) {
        return 0;
    }

    memcpy(&(id.client_ipaddr), &(evt->client_ipaddr), sizeof(id.client_ipaddr));
    memcpy(&(id.server_ipaddr), &(evt->server_ipaddr), sizeof(id.server_ipaddr));
    id.tgid = evt->tgid;
    id.client_ipaddr.port = 0;
    id.role = evt->role;

    tcp = lkup_tcp_socket(probe, (const struct tcp_socket_id_s *)&id);
    if (tcp) {
        tcp->stats[evt->evt]++;
        tcp->last_rcv_data = time(NULL);
        return 0;
    }

    if (probe->tcp_socks_num >= MAX_ENDPOINT_ENTITES) {
        return -1;
    }

    new_tcp = (struct tcp_socket_s *)malloc(sizeof(struct tcp_socket_s));
    if (new_tcp == NULL) {
        return -1;
    }
    memset(new_tcp, 0, sizeof(struct tcp_socket_s));
    memcpy(&(new_tcp->id), &id, sizeof(id));
    new_tcp->stats[evt->evt] += 1;
    new_tcp->last_rcv_data = time(NULL);

    transform_cluster_ip(probe, new_tcp, evt);

    ip_str(new_tcp->id.client_ipaddr.family, (unsigned char *)&(new_tcp->id.client_ipaddr.ip), client_ip_str, INET6_ADDRSTRLEN);
    ip_str(new_tcp->id.server_ipaddr.family, (unsigned char *)&(new_tcp->id.server_ipaddr.ip), server_ip_str, INET6_ADDRSTRLEN);
    new_tcp->client_ip = strdup((const char *)client_ip_str);
    new_tcp->server_ip = strdup((const char *)server_ip_str);

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

static void proc_tcp_sock_evt(void *ctx, int cpu, void *data, u32 size)
{
    char *p = data;
    int remain_size = (int)size, step_size = sizeof(struct tcp_socket_event_s), offset = 0;
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

    return;
}

static void proc_udp_sock_evt(void *ctx, int cpu, void *data, u32 size)
{
    char *p = data;
    int remain_size = (int)size, step_size = sizeof(struct udp_socket_event_s), offset = 0;
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

    return;
}

static void sig_int(int signo)
{
    g_stop = 1;
}

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

    if (tcp_sock->stats[EP_STATS_LOST_SYNACK] != 0) {
        if (entityId[0] == 0)
            build_tcp_id(tcp_sock, entityId, EP_ENTITY_ID_LEN);

        evt.metrics = "lost_synacks";
        evt.entityId = entityId;
        evt.entityName = OO_TCP_SOCK;
        build_tcp_lable(tcp_sock, &evt);

        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "TCP connection setup failure due to loss of SYN/ACK(%llu).",
                    tcp_sock->stats[EP_STATS_LOST_SYNACK]);
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

static int endpoint_load_probe_tcp(struct bpf_prog_s *prog, char is_load)
{
    __LOAD_ENDPOINT_PROBE(tcp, err, is_load);
    if (is_load) {
        prog->skels[prog->num].skel = tcp_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)tcp_bpf__destroy;
        prog->num++;
        g_ep_probe.tcp_output_fd = GET_MAP_FD(tcp, tcp_evt_map);
    }

    return 0;
err:
    UNLOAD(tcp);
    return -1;
}

static int endpoint_load_probe_udp(struct bpf_prog_s *prog, char is_load)
{
    __LOAD_ENDPOINT_PROBE(udp, err, is_load);
    if (is_load) {
        prog->skels[prog->num].skel = udp_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)udp_bpf__destroy;
        prog->num++;
        g_ep_probe.udp_output_fd = GET_MAP_FD(udp, udp_evt_map);
    }

    return 0;
err:
    UNLOAD(udp);
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

    if (endpoint_load_probe_tcp(new_prog, is_load_tcp)) {
        goto err;
    }

    if (endpoint_load_probe_udp(new_prog, is_load_udp)) {
        goto err;
    }

    if (is_load_tcp) {
        new_prog->pbs[0] = create_pref_buffer3(probe->tcp_output_fd, proc_tcp_sock_evt, NULL, probe);
        if (new_prog->pbs[0] == NULL) {
            ERROR("[ENDPOINTPROBE] Create tcp sock perf buffer failed.\n");
            goto err;
        }
    }

    if (is_load_udp) {
        new_prog->pbs[1] = create_pref_buffer3(probe->udp_output_fd, proc_udp_sock_evt, NULL, probe);
        if (new_prog->pbs[1] == NULL) {
            ERROR("[ENDPOINTPROBE] Create udp sock perf buffer failed.\n");
            goto err;
        }
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
        if (prog->pbs[i]) {
            ret = perf_buffer__poll(prog->pbs[i], THOUSAND);
            if (ret < 0  && ret != -EINTR) {
                return ret;
            }
        }
    }

    return 0;
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

    return;
}

int main(int argc, char **argv)
{
    int ret = -1, msq_id;
    struct ipc_body_s ipc_body;

    memset(&g_ep_probe, 0, sizeof(g_ep_probe));

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        ERROR("[ENDPOINTPROBE] Can't set signal handler: %d\n", errno);
        return errno;
    }

    msq_id = create_ipc_msg_queue(IPC_EXCL);
    if (msq_id < 0) {
        ERROR("[ENDPOINTPROBE] Create ipc msg queue failed.\n");
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
        }

        if (poll_endpoint_pb(&g_ep_probe)) {
            sleep(1);
        }

        report_endpoint(&g_ep_probe);
        report_tcp_socks(&g_ep_probe);
        aging_tcp_socks(&g_ep_probe);
        aging_udp_socks(&g_ep_probe);
    }

    destroy_tcp_socks(&g_ep_probe);
    destroy_udp_socks(&g_ep_probe);

    unload_bpf_prog(&(g_ep_probe.prog));
    destroy_ipc_body(&(g_ep_probe.ipc_body));

    return ret;
}
