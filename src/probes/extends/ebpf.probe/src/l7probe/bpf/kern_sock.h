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
 * Create: 2023-03-14
 * Description: kernel socket tracing
 ******************************************************************************/
#ifndef __KERN_SOCK_H__
#define __KERN_SOCK_H__

#pragma once

#ifdef BPF_PROG_KERN

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "bpf.h"
#include "connect.h"
#include "l7.h"
#include "kern_sock_conn.h"


#if (CURRENT_KERNEL_VERSION  >= KERNEL_VERSION(5, 10, 0))
#define __USE_RING_BUF
#endif
/*
    Used to tracing syscall 'accept/accept4' event to generate 'sock_conn_s' obj.
    Syscall function prototype:
    int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
*/
struct sys_accept_args_s {
    struct sockaddr *addr;
    struct socket* newsock;
};

/*
    Used to tracing syscall 'connect' event to generate 'sock_conn_s' obj.
    Syscall function prototype:
    int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    ssize_t sendto(int sockfd, const void *buf, size_t len,
        int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
    ssize_t recvfrom(int sockfd, void *buf, size_t len,
        int flags, struct sockaddr *src_addr, socklen_t *addrlen);
    ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
    ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
*/
struct sys_connect_args_s {
    int fd;
    const struct sockaddr* addr;
};

/*
    Used to tracing syscall 'write/send...' args.
    Syscall function prototype:
    ssize_t write(int fd, const void *buf, size_t count);
    ssize_t send(int sockfd, const void *buf, size_t len, int flags);
    ssize_t read(int fd, void *buf, size_t count);
    ssize_t recv(int sockfd, void *buf, size_t len, int flags);

    ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
    ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
    ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
    ssize_t readv(int fd, const struct iovec *iov, int iovcnt);

    ssize_t sendto(int sockfd, const void *buf, size_t len,
        int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
    ssize_t recvfrom(int sockfd, void *buf, size_t len,
        int flags, struct sockaddr *src_addr, socklen_t *addrlen);
*/
struct sock_data_args_s {
    struct conn_id_s conn_id;
    enum l7_direction_t direct;
    char is_socket_op;

    // For send()/recv()/write()/read().
    char* buf;

    // For sendmsg()/recvmsg()/writev()/readv().
    struct iovec* iov;
    size_t iovlen;
};

#define __KPROBE_SYSCALL(arch, func) KPROBE(arch##func, pt_regs)

#define KPROBE_SYSCALL(func) \
    #if defined(__TARGET_ARCH_x86) \
        __KPROBE_SYSCALL(__x64_sys_, func) \
    #elif defined(__TARGET_ARCH_arm64) \
        __KPROBE_SYSCALL(__arm64_sys_, func) \
    #endif

#define __KRETPROBE_SYSCALL(arch, func) KRETPROBE(arch##func, pt_regs)

#define KRETPROBE_SYSCALL(func) \
    #if defined(__TARGET_ARCH_x86) \
        __KRETPROBE_SYSCALL(__x64_sys_, func) \
    #elif defined(__TARGET_ARCH_arm64) \
        __KRETPROBE_SYSCALL(__arm64_sys_, func) \
    #endif


#ifdef __USE_RING_BUF
#define GOPHER_BPF_MAP_TYPE_PERF   BPF_MAP_TYPE_RINGBUF
#else
#define GOPHER_BPF_MAP_TYPE_PERF   BPF_MAP_TYPE_PERF_EVENT_ARRAY
#endif

struct {
    __uint(type, GOPHER_BPF_MAP_TYPE_PERF);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 64);
} conn_data_events SEC(".maps");

struct {
    __uint(type, GOPHER_BPF_MAP_TYPE_PERF);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 64);
} conn_control_events SEC(".maps");

struct {
    __uint(type, GOPHER_BPF_MAP_TYPE_PERF);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 64);
} conn_stats_events SEC(".maps");

#ifndef __USE_RING_BUF
// Use the BPF map to cache socket data to avoid the restriction
// that the BPF program stack does not exceed 512 bytes.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct conn_data_s));
    __uint(max_entries, 1);
} sock_data_buffer SEC(".maps");
#endif

static __always_inline __maybe_unused u64 get_cur_cpuacct_cgrp_id(void)
{
    u64 cgroup_id;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct css_set *cgroups = _(task->cgroups);
    struct cgroup_subsys_state *css = _(cgroups->subsys[cpuacct_cgrp_id]);
    struct kernfs_node *kn = BPF_CORE_READ(css, cgroup, kn);

#if (CURRENT_KERNEL_VERSION < KERNEL_VERSION(5, 5, 0))
    cgroup_id = _(kn->id.id);
#else
    cgroup_id = _(kn->id);
#endif
    return cgroup_id;
}

static __always_inline void submit_perf_buf(void* ctx, char *buf, size_t bytes_count, struct conn_data_s* conn_data)
{
    if (buf == NULL || bytes_count == 0) {
        return;
    }

    bpf_probe_read(&conn_data->data, CONN_DATA_MAX_SIZE, buf);
    conn_data->data_size = bytes_count;

#ifdef __USE_RING_BUF
    bpf_ringbuf_submit(conn_data, 0);
#else
    (void)bpf_perf_event_output(ctx, &sock_data_buffer, BPF_F_CURRENT_CPU, conn_data, sizeof(struct conn_data_s));
#endif
    return;
}

static __always_inline __maybe_unused void submit_conn_data(void* ctx, struct sock_data_args_s* args,
                                    struct conn_data_s* conn_data, size_t bytes_count)
{
    int i;
    int bytes_sent = 0, bytes_remaining = 0, bytes_truncated = 0;

    if (args->buf) {
        #pragma unroll
        for (i = 0; i < LOOP_LIMIT; ++i) {
            bytes_remaining = (int)bytes_count - bytes_sent;
            bytes_truncated = (bytes_remaining > CONN_DATA_MAX_SIZE && (i != LOOP_LIMIT - 1)) ? CONN_DATA_MAX_SIZE : bytes_remaining;
            if (bytes_truncated <= 0) {
                return;
            }
            // summit perf buf
            submit_perf_buf(ctx, args->buf + bytes_sent, (size_t)bytes_truncated, conn_data);
            bytes_sent += bytes_truncated;

            conn_data->offset_pos += (u64)bytes_truncated;
        }
    } else if (args->iov) {
        #pragma unroll
        for (i = 0; i < LOOP_LIMIT && i < args->iovlen && bytes_sent < bytes_count; ++i) {
            struct iovec iov_cpy = {0};
            bpf_probe_read(&iov_cpy, sizeof(iov_cpy), &args->iov[i]);
            bytes_remaining = (int)bytes_count - bytes_sent;
            if (bytes_truncated <= 0) {
                return;
            }
            size_t iov_len = min(iov_cpy.iov_len, (size_t)bytes_remaining);

            // summit perf buf
            submit_perf_buf(ctx, (char *)iov_cpy.iov_base, iov_len, conn_data);
            bytes_sent += iov_len;

            conn_data->offset_pos += (u64)iov_len;
        }
    }
}

static __always_inline __maybe_unused void get_sockaddr(struct conn_info_s* conn_info, const struct socket* socket)
{
    u16 family, port;

#if (CURRENT_LIBBPF_VERSION  >= LIBBPF_VERSION(0, 8))
    family = BPF_CORE_READ(socket, sk, __sk_common.skc_family);
    port = BPF_CORE_READ(socket, sk, __sk_common.skc_dport);

    conn_info->remote_addr.sa.sa_family = family;
    if (family == AF_INET) {
        conn_info->remote_addr.in4.sin_port = port;
        BPF_CORE_READ_INTO(conn_info->remote_addr.in4.sin_addr.s_addr,
            socket, sk, __sk_common.skc_daddr);
    } else if (family == AF_INET6) {
        conn_info->remote_addr.in6.sin6_port = port;
        BPF_CORE_READ_INTO(conn_info->remote_addr.in6.sin6_addr,
            sk, __sk_common.skc_v6_daddr);
    }
#else
    struct sock* sk = NULL;
    sk = _(socket->sk);
    family = _(sk->__sk_common.skc_family);
    port = _(sk->__sk_common.skc_dport);

    conn_info->remote_addr.sa.sa_family = family;

    if (family == AF_INET) {
        conn_info->remote_addr.in4.sin_port = port;
        conn_info->remote_addr.in4.sin_addr.s_addr = _(sk->__sk_common.skc_daddr);
    } else if (family == AF_INET6) {
      conn_info->remote_addr.in6.sin6_port = port;
      (void)bpf_probe_read(&conn_info->remote_addr.in6.sin6_addr, IP6_LEN, &sk->__sk_common.skc_v6_daddr);
    }
#endif
}

static __always_inline __maybe_unused int submit_conn_close(void *ctx, conn_ctx_t id, int fd)
{
    int tgid = (int)(id >> INT_LEN);
    struct sock_conn_s* sock_conn = get_sock_conn(tgid, fd);
    if (sock_conn == NULL) {
        return 0;
    }

#ifdef __USE_RING_BUF
    struct conn_ctl_s *e = bpf_ringbuf_reserve(&conn_control_events, sizeof(struct conn_ctl_s), 0);
    if (!e) {
        goto end;
    }
#else
    struct conn_ctl_s evt = {0};
    struct conn_ctl_s *e = &evt;
#endif

    e->type = CONN_EVT_CLOSE;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->conn_id = sock_conn->info.id;
    e->close.rd_bytes = sock_conn->rd_bytes;
    e->close.wr_bytes = sock_conn->wr_bytes;

    // submit conn open event.
#ifdef __USE_RING_BUF
    bpf_ringbuf_submit(e, 0);
#else
    (void)bpf_perf_event_output(ctx, &conn_control_events, BPF_F_CURRENT_CPU, e, sizeof(struct conn_ctl_s));
#endif

#ifdef __USE_RING_BUF
end:
#endif
    bpf_map_delete_elem(&conn_tbl, &id);

    return 0;
}


static __always_inline __maybe_unused struct sock_conn_s* new_sock_conn(void *ctx, int tgid, int fd, enum l4_role_t l4_role,
                                     const struct sockaddr* addr, const struct socket* socket)
{
    struct conn_id_s id = {0};
    struct sock_conn_s sock_conn = {0};

    id.fd = fd;
    id.tgid = tgid;

    sock_conn.info.id.fd = fd;
    sock_conn.info.id.tgid = tgid;
    sock_conn.info.is_ssl = 0;
    sock_conn.info.protocol = PROTO_UNKNOW;
    sock_conn.info.l4_role = l4_role;
    if (addr != NULL) {
        sock_conn.info.remote_addr = *((union sockaddr_t*)addr);
    } else if (socket != NULL) {
        get_sockaddr(&sock_conn.info, socket);
    }

    // new conn obj
    (void)bpf_map_update_elem(&conn_tbl, &id, &sock_conn, BPF_ANY);
    return get_sock_conn(tgid, fd);
}

static __always_inline __maybe_unused int submit_conn_open(void *ctx, int tgid, int fd, enum l4_role_t l4_role,
                                     const struct sockaddr* addr, const struct socket* socket)
{
    struct sock_conn_s* sock_conn = get_sock_conn(tgid, fd);
    if (sock_conn != NULL && sock_conn->info.is_reported != 0) {
        return 0;   // avoid report redundant events
    }

    // new sock connection
    if (!sock_conn) {
        sock_conn = new_sock_conn(tgid);
    }

    if (sock_conn == NULL) {
        return -1;
    }

#ifdef __USE_RING_BUF
    struct conn_ctl_s *e = bpf_ringbuf_reserve(&conn_control_events, sizeof(struct conn_ctl_s), 0);
    if (!e) {
        return -1;
    }
#else
    struct conn_ctl_s evt = {0};
    struct conn_ctl_s *e = &evt;
#endif

    e->type = CONN_EVT_OPEN;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->conn_id = sock_conn->info.id;
    e->open.addr = sock_conn.info.remote_addr;
    e->open.l4_role = sock_conn.info.l4_role;
    e->open.is_ssl = sock_conn.info.is_ssl;

    // submit conn open event.
#ifdef __USE_RING_BUF
    bpf_ringbuf_submit(e, 0);
#else
    (void)bpf_perf_event_output(ctx, &conn_control_events, BPF_F_CURRENT_CPU, e, sizeof(struct conn_ctl_s));
#endif
    sock_conn->info.is_reported = 1;
    return 0;
}

static __always_inline __maybe_unused struct conn_data_s* store_conn_data_buf(enum l7_direction_t direction, struct sock_conn_s* sock_conn)
{
    int key = 0;
#ifdef __USE_RING_BUF
    struct conn_data_s *conn_data = bpf_ringbuf_reserve(&conn_data_events, sizeof(struct conn_data_s), 0);
#else
    struct conn_data_s* conn_data = bpf_map_lookup_elem(&sock_data_buffer, &key);
#endif

    if (conn_data == NULL) {
        return NULL;
    }

    conn_data->timestamp_ns = bpf_ktime_get_ns();
    conn_data->direction = direction;
    conn_data->conn_id = sock_conn->info->id;
    conn_data->proto = sock_conn->info->protocol;
    conn_data->l7_role = sock_conn->info->l7_role;
    conn_data->offset_pos = (direction == L7_EGRESS) ? sock_conn->wr_bytes : sock_conn->rd_bytes;
    return conn_data;
}

static __always_inline __maybe_unused int update_sock_conn_proto(struct sock_conn_s* sock_conn, enum l7_direction_t direction,
                                                            const char* buf, size_t count)
{
    if (sock_conn->info.protocol != PROTO_UNKNOW) {
        return 0;
    }

    struct l7_proto_s l7pro = {0};
    if (get_l7_protocol(buf, count, PROTO_ALL_ENABLE, &l7pro)) {
        return -1;
    }

    if (l7pro.proto == PROTO_UNKNOW) {
        return -1;
    }
    sock_conn->info.protocol = l7pro.proto;
    // ROLE_CLIENT: message(MESSAGE_REQUEST) -> direct(L7_EGRESS)
    // ROLE_CLIENT: message(MESSAGE_RESPONSE) -> direct(L7_INGRESS)
    // ROLE_SERVER: message(MESSAGE_REQUEST) -> direct(L7_INGRESS)
    // ROLE_SERVER: message(MESSAGE_RESPONSE) -> direct(L7_EGRESS)
    sock_conn->info.l7_role  = ((direction == L7_EGRESS) ^ (l7pro.type == MESSAGE_RESPONSE)) ? L7_CLIENT : L7_SERVER;
}

static __always_inline __maybe_unused void submit_sock_conn_stats(void *ctx, struct sock_conn_s* sock_conn,
                                                                enum l7_direction_t direction, size_t bytes_count)
{
    if (direction == L7_EGRESS) {
        sock_conn->wr_bytes += bytes_count;
    } else if (direction == L7_INGRESS) {
        sock_conn->rd_bytes += bytes_count;
    } else {
        return;
    }

#ifdef __USE_RING_BUF
    struct conn_stats_s *e = bpf_ringbuf_reserve(&conn_stats_events, sizeof(struct conn_stats_s), 0);
    if (!e) {
        return;
    }
#else
    struct conn_stats_s evt = {0};
    struct conn_stats_s *e = &evt;
#endif

    e->timestamp_ns = bpf_ktime_get_ns();
    e->conn_id = sock_conn->info.id;
    e->wr_bytes = sock_conn->wr_bytes
    e->rd_bytes = sock_conn->rd_bytes;

    // submit conn stats event.
#ifdef __USE_RING_BUF
    bpf_ringbuf_submit(e, 0);
#else
    (void)bpf_perf_event_output(ctx, &conn_stats_events, BPF_F_CURRENT_CPU, e, sizeof(struct conn_stats_s));
#endif
    return;
}

static __always_inline __maybe_unused void submit_sock_data(void *ctx, conn_ctx_t id,
            enum l7_direction_t direction, struct sock_data_args_s* args, size_t bytes_count)
{
    struct sock_conn_s* sock_conn = get_sock_conn(args->conn_id.tgid, args->conn_id.fd);
    if (sock_conn == NULL) {
        return;
    }

    if (!sock_conn->info.is_ssl) {
        if (args->buf) {
            update_sock_conn_proto(sock_conn, direction, args->buf, bytes_count);
        } else if (args->iov) {
            struct iovec iov_cpy;
            bpf_probe_read(&iov_cpy, sizeof(iov_cpy), &args->iov[0]);
            size_t iov_len = (size_t)min(iov_cpy.iov_len, bytes_count);
            update_sock_conn_proto(sock_conn, direction, iov_cpy->iov_base, iov_len);
        } else {
            return;
        }

        struct conn_data_s* conn_data;
        conn_data = store_conn_data_buf(direction, sock_conn);
        if (conn_data == NULL) {
            return;
        }

        submit_conn_data(ctx, args, conn_data, bytes_count);
    }

    submit_sock_conn_stats(ctx, sock_conn, direction, bytes_count);
    return;
}

#endif

#endif
