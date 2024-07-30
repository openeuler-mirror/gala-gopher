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

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#define BPF_PROG_USER
#include "kern_sock.h"

char g_license[] SEC("license") = "GPL";

enum {
    PROG_SSL_READ = 0,
    PROG_SSL_WRITE,
};

#define __MAX_SSL_ENTRIES 1024

// ssl struct in openssl 1.1.1
typedef long (*bio_callback_fn)(void);
struct ssl_method_st {};

struct bio_st {
    const struct ssl_method_st* method;
    bio_callback_fn callback;
    bio_callback_fn callback_ex;
    char* cb_arg;
    int init;
    int shutdown;
    int flags; /* extra storage */
    int retry_reason;
    int num;
};

struct ssl_st {
    int version; // protocol version
    const struct ssl_method_st *method;
    struct bio_st *rbio; // used by SSL_read
    struct bio_st *wbio; // used by SSL_write
}; // end of ssl struct in openssl 1.1.1

#ifndef __PERF_OUT_MAX
#define __PERF_OUT_MAX (64)
#endif

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(int));
    __uint(max_entries, __MAX_CONCURRENCY);
} ssl_fd_map SEC(".maps");

static __always_inline int get_fd_from_ssl_fd_map(u64 ssl_addr)
{
    int *fd_ptr;

    fd_ptr = (int *)bpf_map_lookup_elem(&ssl_fd_map, &ssl_addr);
    if (fd_ptr) {
        return *fd_ptr;
    }

    return 0;
}

static __always_inline int get_fd_from_ssl(struct ssl_st* ssl_st_p, enum l7_direction_t rw_type)
{
    int fd;

    if (ssl_st_p == NULL) {
        return -1;
    }
    struct bio_st *bio_p = (rw_type == L7_INGRESS) ? _(ssl_st_p->rbio) : _(ssl_st_p->wbio);

    if (bio_p == NULL) {
        return -1;
    }

    fd = _(bio_p->num);

    if (fd == 0) {
        fd = get_fd_from_ssl_fd_map((u64)ssl_st_p);
    }

    return fd;
}

UPROBE(SSL_read, pt_regs)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);

    if (!is_filter_id(FILTER_TGID, proc_id)) {
        return 0;
    }

    int fd = get_fd_from_ssl((struct ssl_st*)PT_REGS_PARM1(ctx), L7_INGRESS);
    if (fd < 0) {
        return 0;
    }

    set_sock_conn_ssl(proc_id, fd);

    struct sock_data_args_s args = {0};
    args.conn_id.fd = fd;
    args.conn_id.tgid = proc_id;
    args.direct = L7_INGRESS;
    args.buf = (char *)PT_REGS_PARM2(ctx);
    args.is_ssl = 1;
    bpf_map_update_elem(&sock_data_args, &id, &args, BPF_ANY);
    return 0;
}

URETPROBE(SSL_read, pt_regs)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct sock_data_args_s* args = bpf_map_lookup_elem(&sock_data_args, &id);
    if (args != NULL) {
        size_t bytes_count = (size_t)PT_REGS_RC(ctx);
        if (bytes_count <= 0) {
            goto end;
        }

        struct sock_conn_s* sock_conn = lkup_sock_conn(args->conn_id.tgid, args->conn_id.fd);
        if (sock_conn) {
            submit_sock_data(ctx, sock_conn, id, L7_INGRESS, args, (size_t)bytes_count);
        }
    }

end:
    bpf_map_delete_elem(&sock_data_args, &id);
    return 0;
}

UPROBE(SSL_write, pt_regs)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);

    if (!is_filter_id(FILTER_TGID, proc_id)) {
        return 0;
    }

    int fd = get_fd_from_ssl((struct ssl_st*)PT_REGS_PARM1(ctx), L7_EGRESS);
    if (fd < 0) {
        return 0;
    }

    set_sock_conn_ssl(proc_id, fd);

    struct sock_data_args_s args = {0};
    args.conn_id.fd = fd;
    args.conn_id.tgid = proc_id;
    args.direct = L7_EGRESS;
    args.buf = (char *)PT_REGS_PARM2(ctx);
    args.is_ssl = 1;
    bpf_map_update_elem(&sock_data_args, &id, &args, BPF_ANY);
    return 0;
}

URETPROBE(SSL_write, pt_regs)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct sock_data_args_s* args = bpf_map_lookup_elem(&sock_data_args, &id);
    if (args != NULL) {
        size_t bytes_count = (size_t)PT_REGS_RC(ctx);
        if (bytes_count <= 0) {
            goto end;
        }

        struct sock_conn_s* sock_conn = lkup_sock_conn(args->conn_id.tgid, args->conn_id.fd);
        if (sock_conn) {
            submit_sock_data(ctx, sock_conn, id, L7_EGRESS, args, (size_t)bytes_count);
        }
    }

end:
    bpf_map_delete_elem(&sock_data_args, &id);
    return 0;
}

static __always_inline void process_ssl_set_fd(struct pt_regs *ctx)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);
    u64 ssl_addr;
    int fd;

    if (!is_filter_id(FILTER_TGID, proc_id)) {
        return;
    }

    ssl_addr = (u64)PT_REGS_PARM1(ctx);
    fd = (int)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&ssl_fd_map, &ssl_addr, &fd, BPF_ANY);
}

// int SSL_set_fd(SSL *s, int fd)
UPROBE(SSL_set_fd, pt_regs)
{
    process_ssl_set_fd(ctx);
    return 0;
}

// int SSL_set_rfd(SSL *s, int fd)
UPROBE(SSL_set_rfd, pt_regs)
{
    process_ssl_set_fd(ctx);
    return 0;
}

// int SSL_set_wfd(SSL *s, int fd)
UPROBE(SSL_set_wfd, pt_regs)
{
    process_ssl_set_fd(ctx);
    return 0;
}

