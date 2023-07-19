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
#include <bpf/bpf_endian.h>
#include "bpf.h"

#include "include/connect.h"
#include "bpf/filter_bpf.h"
#include "bpf/kern_sock_conn.h"

#ifdef BPF_PROG_USER
struct iovec {
    void *iov_base;
    size_t iov_len;
};
#endif

#define BPF_F_INDEX_MASK        0xffffffffULL
#define BPF_F_CURRENT_CPU       BPF_F_INDEX_MASK

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
    int SSL_read(SSL *s, void *buf, int num);
    int SSL_write(SSL *s, const void *buf, int num);
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

    char is_ssl;
    char pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(conn_ctx_t));
    __uint(value_size, sizeof(struct sys_accept_args_s));
    __uint(max_entries, __MAX_CONCURRENCY);
} sys_accept_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(conn_ctx_t));
    __uint(value_size, sizeof(struct sys_connect_args_s));
    __uint(max_entries, __MAX_CONCURRENCY);
} sys_connect_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(conn_ctx_t));
    __uint(value_size, sizeof(struct sock_data_args_s));
    __uint(max_entries, __MAX_CONCURRENCY);
} sock_data_args SEC(".maps");


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
} conn_data_buffer SEC(".maps");
#endif

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, L7_DATA_BUFFER_MAXSIZE);
    __uint(max_entries, 1);
} l7_data_buffer SEC(".maps");

static __always_inline void submit_perf_buf(void* ctx, char *buf, size_t bytes_count, struct conn_data_s* conn_data)
{
    size_t copied_size;
    if (buf == NULL || bytes_count == 0) {
        return;
    }

    copied_size = (bytes_count > CONN_DATA_MAX_SIZE) ? CONN_DATA_MAX_SIZE : bytes_count;
    bpf_probe_read(&conn_data->data, copied_size, buf);
    conn_data->data_size = copied_size;

#ifdef __USE_RING_BUF
    bpf_ringbuf_submit(conn_data, 0);
#else
    (void)bpf_perf_event_output(ctx, &conn_data_events, BPF_F_CURRENT_CPU, conn_data, sizeof(struct conn_data_s));
#endif
    return;
}

static __always_inline __maybe_unused struct conn_data_s* store_conn_data_buf(enum l7_direction_t direction, struct sock_conn_s* sock_conn)
{
#ifdef __USE_RING_BUF
    struct conn_data_s *conn_data = bpf_ringbuf_reserve(&conn_data_events, sizeof(struct conn_data_s), 0);
#else
    int key = 0;
    struct conn_data_s* conn_data = bpf_map_lookup_elem(&conn_data_buffer, &key);
#endif

    if (conn_data == NULL) {
        return NULL;
    }

    conn_data->timestamp_ns = bpf_ktime_get_ns();
    conn_data->direction = direction;
    conn_data->conn_id = sock_conn->info.id;
    conn_data->proto = sock_conn->info.protocol;
    conn_data->l7_role = sock_conn->info.l7_role;
    conn_data->offset_pos = (direction == L7_EGRESS) ? sock_conn->wr_bytes : sock_conn->rd_bytes;
    return conn_data;
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
    e->wr_bytes = sock_conn->wr_bytes;
    e->rd_bytes = sock_conn->rd_bytes;

    // submit conn stats event.
#ifdef __USE_RING_BUF
    bpf_ringbuf_submit(e, 0);
#else
    (void)bpf_perf_event_output(ctx, &conn_stats_events, BPF_F_CURRENT_CPU, e, sizeof(struct conn_stats_s));
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

static __always_inline __maybe_unused char *read_from_buf_ptr(char* buf)
{
    u32 key = 0;
    char *buffer = bpf_map_lookup_elem(&l7_data_buffer, &key);
    if (!buffer)
        return NULL;
    bpf_probe_read_str(buffer, L7_DATA_BUFFER_MAXSIZE, buf);
    return buffer;
}

static __always_inline __maybe_unused void submit_sock_data(void *ctx, struct sock_conn_s* sock_conn, conn_ctx_t id,
            enum l7_direction_t direction, struct sock_data_args_s* args, size_t bytes_count)
{
    if (sock_conn->info.is_ssl != args->is_ssl) {
        return;
    }
    return;// TODO
    if (args->buf) {
        char *buffer = read_from_buf_ptr(args->buf);
        update_sock_conn_proto(sock_conn, direction, buffer, bytes_count);
    } else if (args->iov) {
        struct iovec iov_cpy = {0};
        bpf_probe_read(&iov_cpy, sizeof(iov_cpy), &args->iov[0]);
        size_t iov_len = (size_t)min(iov_cpy.iov_len, bytes_count);
        update_sock_conn_proto(sock_conn, direction, iov_cpy.iov_base, iov_len);
    } else {
        return;
    }

    struct conn_data_s* conn_data;
    conn_data = store_conn_data_buf(direction, sock_conn);
    if (conn_data == NULL) {
        return;
    }

    submit_conn_data(ctx, args, conn_data, bytes_count);

    submit_sock_conn_stats(ctx, sock_conn, direction, bytes_count);

    return;
}

#endif
