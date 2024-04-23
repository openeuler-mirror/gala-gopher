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
 * Create: 2021-06-21
 * Description: nginx_probe bpf prog
 ******************************************************************************/
#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif
#define BPF_PROG_USER
#include "bpf.h"
#include "nginx_probe.h"

char LICENSE[] SEC("license") = "GPL";
/* 4 LB
    ngx_stream_proxy_connect
    uprobe: obtain client sock addr
        ngx_stream_session_t->connection->sockaddr
    uretprobe: obtain server sock addr 并关联client

 */

#define HASH_ITEM_CNTS 10240

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(void **));
    __uint(max_entries, HASH_ITEM_CNTS);
} para_hs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct ip_addr));
    __uint(value_size, sizeof(struct ngx_metric));
    __uint(max_entries, HASH_ITEM_CNTS);
} hs SEC(".maps");

static void bpf_copy_ip_addr(const struct sockaddr *addr, struct ip_addr *ip)
{
    ip->family = _(addr->sa_family);
    if (ip->family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        ip->ipaddr.ip4 = _(addr_in->sin_addr.s_addr);
        ip->port = _(addr_in->sin_port);
    } else {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
        ip->port = _(addr_in6->sin6_port);
        bpf_core_read_user(ip->ipaddr.ip6, IP6_LEN, addr_in6->sin6_addr.in6_u.u6_addr8);
    }
    return;
}

UPROBE(ngx_http_upstream_handler, pt_regs)
{
    //__u64 tid = bpf_get_current_pid_tgid();
    struct ngx_event_s *evt = (struct ngx_event_s *)PT_REGS_PARM1(ctx);

    struct ngx_connection_s *c = (struct ngx_connection_s *)_(evt->data);
    if (c == (void *)0)
        return 0;

    struct ngx_http_request_s *r = (struct ngx_http_request_s *)_(c->data);
    if (r == (void *)0)
        return 0;

    struct ngx_http_upstream_s *u = (struct ngx_http_upstream_s *)_(r->upstream);
    if (u == (void *)0)
        return 0;

    c = (struct ngx_connection_s *)_(r->connection);
    if (c == (void *)0)
        return 0;

    struct ngx_metric metric = {0};

    metric.is_l7 = 1;
    struct sockaddr *tmp = _(c->sockaddr);
    bpf_copy_ip_addr(tmp, &metric.src_ip);

    tmp = _(c->local_sockaddr);
    bpf_copy_ip_addr(tmp, &metric.ngx_ip);

    ngx_str_t *p_name;
    bpf_core_read_user(&p_name, sizeof(void **), &(u->peer.name));
    if (p_name == (void *)0)
        return 0;

    unsigned char *dt;
    bpf_core_read_user(&dt, sizeof(void **), &(p_name->data));
    if (dt == (void *)0)
        return 0;

    bpf_core_read_user_str(metric.dst_ip_str, INET6_ADDRSTRLEN, dt);

    bpf_map_update_elem(&hs, &(metric.src_ip), &metric, BPF_ANY);
    return 0;
}

UPROBE(ngx_stream_proxy_init_upstream, pt_regs)
{
    //struct ngx_stream_upstream_s *stream;
    __u64 tid = bpf_get_current_pid_tgid();
    struct ngx_stream_session_s *s = (struct ngx_stream_session_s *)PT_REGS_PARM1(ctx);

    bpf_map_update_elem(&para_hs, &tid, &s, BPF_ANY);
    return 0;
}

URETPROBE(ngx_stream_proxy_init_upstream, pt_regs)
{
    struct ngx_connection_s *conn;
    //struct ngx_connection_s *peer_conn;
    //struct sockaddr *client_addr;
    struct ngx_metric metric = {0};
    struct ngx_stream_upstream_s *stream;
    ngx_str_t *p_name;

    struct sockaddr *tmp;

    struct ngx_stream_session_s *s;
    struct ngx_stream_session_s **t;

    __u64 tid = bpf_get_current_pid_tgid();
    t = (struct ngx_stream_session_s **)bpf_map_lookup_elem(&para_hs, &tid);
    if (t == (void *)0) {
        bpf_printk("bpf_map_lookup_elem para_hs tid:%lu failed\n", tid);
        return 0;
    }

    s = *t;
    conn = _(s->connection);

    tmp = _(conn->sockaddr);
    bpf_copy_ip_addr(tmp, &metric.src_ip);

    tmp = _(conn->local_sockaddr);
    bpf_copy_ip_addr(tmp, &metric.ngx_ip);

    bpf_core_read_user(&stream, sizeof(void **), &(s->upstream));
    if (stream == (void *)0) {
        bpf_printk("stream null:%p\n", stream);
        return 0;
    }

    p_name = _(stream->peer.name);
    if (p_name == (void *)0) {
        bpf_printk("peer.name null\n");
        return 0;
    }

    unsigned char *dt = _(p_name->data);
    if (dt == (void *)0) {
        bpf_printk("name->data null\n");
        return 0;
    }
    bpf_core_read_user_str(metric.dst_ip_str, INET6_ADDRSTRLEN, dt);
    bpf_map_update_elem(&hs, &(metric.src_ip), &metric, BPF_ANY);

    return 0;
}

UPROBE(ngx_close_connection, pt_regs)
{
    struct ngx_connection_s *conn = (struct ngx_connection_s *)PT_REGS_PARM1(ctx);
    struct ngx_metric *metric;

    struct ip_addr src_ip = {0};
    struct sockaddr *client_addr;

    client_addr = _(conn->sockaddr);
    bpf_copy_ip_addr(client_addr, &src_ip);
    metric = (struct ngx_metric *)bpf_map_lookup_elem(&hs, &src_ip);
    if (metric == (void *)0)
        return 0;

    metric->is_finish = 1;
    bpf_map_update_elem(&hs, &src_ip, metric, BPF_ANY);
    return 0;
}