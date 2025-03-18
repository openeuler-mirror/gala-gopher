/*
 * bpf code runs in the Linux kernel
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef __KERN_SOCK_H__
#define __KERN_SOCK_H__

#pragma once
#include <bpf/bpf_endian.h>
#include "bpf.h"

#include "connect.h"
#include "bpf/filter_bpf.h"
#include "bpf/kern_sock_conn.h"

#ifdef BPF_PROG_USER
struct iovec {
    void *iov_base;
    size_t iov_len;
};
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
    int SSL_read(SSL *s, void *buf, int num);
    int SSL_write(SSL *s, const void *buf, int num);
*/
struct sock_data_args_s {
    struct conn_id_s conn_id;
    enum l7_direction_t direct;
    char is_socket_op;

    // For send()/recv()/write()/read().
    const char* buf;

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
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8192 * 1024);
} conn_tracker_events SEC(".maps");

// Use the BPF map to cache socket data to avoid the restriction
// that the BPF program stack does not exceed 512 bytes.

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, L7_DATA_BUFFER_MAXSIZE);
    __uint(max_entries, 1);
} l7_data_buffer SEC(".maps");

static __always_inline void submit_perf_buf(void* ctx, const char *buf, size_t bytes_count, struct conn_data_s* conn_data)
{
    volatile size_t copied_size;

    copied_size = (bytes_count > CONN_DATA_MAX_SIZE) ? CONN_DATA_MAX_SIZE : bytes_count;
    conn_data->msg.data_size = (u32)copied_size;

    bpf_probe_read_user(conn_data->buf.data, copied_size & CONN_DATA_MAX_SIZE, buf);
    if (probe_ringbuf()) {
        conn_data->msg.payload_size = (u32)sizeof(conn_data->buf);
    } else {
        conn_data->msg.payload_size = (u32)copied_size;
    }
    conn_data->msg.evt = TRACKER_EVT_DATA;

    bpfbuf_submit(ctx, &conn_tracker_events, conn_data, sizeof(struct conn_data_msg_s) + (copied_size & CONN_DATA_MAX_SIZE));
    return;
}

static __always_inline __maybe_unused struct conn_data_s* store_conn_data_buf(enum l7_direction_t direction, struct sock_conn_s* sock_conn)
{
    struct conn_data_s* conn_data = bpfbuf_reserve(&conn_tracker_events, sizeof(struct conn_data_s));

    if (conn_data == NULL) {
        return NULL;
    }

    conn_data->msg.timestamp_ns = bpf_ktime_get_ns();
    conn_data->msg.direction = direction;
    conn_data->msg.conn_id = sock_conn->info.id;
    conn_data->msg.proto = sock_conn->info.protocol;
    conn_data->msg.is_ssl = sock_conn->info.is_ssl;
    conn_data->msg.l7_role = sock_conn->info.l7_role;
    conn_data->msg.offset_pos = (direction == L7_EGRESS) ? sock_conn->wr_bytes : sock_conn->rd_bytes;
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

    struct conn_stats_s* e = bpfbuf_reserve(&conn_tracker_events, sizeof(struct conn_stats_s));
    if (!e) {
        return;
    }

    e->evt = TRACKER_EVT_STATS;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->conn_id = sock_conn->info.id;
    e->wr_bytes = sock_conn->wr_bytes;
    e->rd_bytes = sock_conn->rd_bytes;

    // submit conn stats event.
    bpfbuf_submit(ctx, &conn_tracker_events, e, sizeof(struct conn_stats_s));
    return;
}

static __always_inline __maybe_unused void submit_conn_data(void* ctx, struct sock_data_args_s* args,
                                        size_t bytes_count, enum l7_direction_t direction, struct sock_conn_s* sock_conn)
{
    int i;
    int bytes_sent = 0, bytes_remaining = 0, bytes_truncated = 0;

    struct conn_data_s* conn_data;

    if (args->buf) {
        #pragma unroll
        for (i = 0; i < LOOP_LIMIT; ++i) {
            bytes_remaining = (int)bytes_count - bytes_sent;
            bytes_truncated = (bytes_remaining > CONN_DATA_MAX_SIZE && (i != LOOP_LIMIT - 1)) ? CONN_DATA_MAX_SIZE : bytes_remaining;
            if (bytes_truncated <= 0) {
                return;
            }

            conn_data = store_conn_data_buf(direction, sock_conn);
            if (conn_data == NULL) {
                return;
            }

            // summit perf buf
            conn_data->msg.index = i;
            conn_data->msg.offset_pos = (u64)(bytes_truncated + bytes_sent);
            submit_perf_buf(ctx, args->buf + bytes_sent, (size_t)bytes_truncated, conn_data);
            bytes_sent += bytes_truncated;
        }
    } else if (args->iov) {
        #pragma unroll
        for (i = 0; i < LOOP_LIMIT && i < args->iovlen && bytes_sent < bytes_count; ++i) {
            struct iovec iov_cpy = {0};
            bpf_probe_read_user(&iov_cpy, sizeof(iov_cpy), &args->iov[i]);
            bytes_remaining = (int)bytes_count - bytes_sent;
            bytes_truncated = (bytes_remaining > CONN_DATA_MAX_SIZE && (i != LOOP_LIMIT - 1)) ? CONN_DATA_MAX_SIZE : bytes_remaining;
            if (bytes_truncated <= 0) {
                return;
            }

            conn_data = store_conn_data_buf(direction, sock_conn);
            if (conn_data == NULL) {
                return;
            }
            size_t iov_len = min(iov_cpy.iov_len, (size_t)bytes_remaining);

            // summit perf buf
            conn_data->msg.index = i;
            conn_data->msg.offset_pos = (u64)(iov_len + bytes_sent);
            submit_perf_buf(ctx, (char *)iov_cpy.iov_base, iov_len, conn_data);
            bytes_sent += iov_len;
        }
    }
}

static __always_inline __maybe_unused char *read_from_buf_ptr(const char* buf)
{
    u32 key = 0;
    char *buffer = bpf_map_lookup_elem(&l7_data_buffer, &key);
    if (!buffer)
        return NULL;
    bpf_probe_read_user(buffer, L7_DATA_BUFFER_MAXSIZE, buf);
    return buffer;
}

static __always_inline __maybe_unused void submit_sock_data(void *ctx, struct sock_conn_s* sock_conn, conn_ctx_t id,
            enum l7_direction_t direction, struct sock_data_args_s* args, size_t bytes_count)
{
    char *buffer;

    if (sock_conn->info.is_ssl != args->is_ssl) {
        return;
    }

    u32 proto = get_filter_proto();

    if (args->buf) {
        buffer = read_from_buf_ptr(args->buf);
        if (!buffer) {
            return;
        }
        if (update_sock_conn_proto(sock_conn, direction, buffer, bytes_count, proto)) {
            return;
        }
    } else if (args->iov) {
        struct iovec iov_cpy = {0};
        // Using bpf_core_read will get error: failed to resolve CO-RE relocation <byte_off> [xx] struct sock_data_args_s.iov
        bpf_probe_read_user(&iov_cpy, sizeof(iov_cpy), &args->iov[0]);
        buffer = read_from_buf_ptr((char *)iov_cpy.iov_base);
        if (!buffer) {
            return;
        }
        size_t iov_len = (size_t)min(iov_cpy.iov_len, bytes_count);
        if (update_sock_conn_proto(sock_conn, direction, buffer, iov_len, proto)) {
            return;
        }
    } else {
        return;
    }

    submit_conn_data(ctx, args, bytes_count, direction, sock_conn);

    submit_sock_conn_stats(ctx, sock_conn, direction, bytes_count);

    return;
}

#endif
