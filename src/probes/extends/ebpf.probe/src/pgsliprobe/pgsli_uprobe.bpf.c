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
#include "bpf.h"
#include <bpf/bpf_endian.h>
#include "pgsliprobe.h"
#include "pgsliprobe_bpf.h"

char g_license[] SEC("license") = "GPL";

enum {
    PROG_SSL_READ = 0,
    PROG_SSL_WRITE,
};

// ssl struct in opennssl 1.1.1
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
}; // end of ssl struct in opennssl 1.1.1


static __always_inline int get_fd_from_ssl(struct ssl_st* ssl_st_p, enum msg_event_rw_t rw_type)
{
    int fd;

    if (ssl_st_p == NULL) {
        return -1;
    }
    struct bio_st *bio_p = (rw_type == MSG_READ) ? _(ssl_st_p->rbio) : _(ssl_st_p->wbio);

    if (bio_p == NULL) {
        return -1;
    }

    fd = _(bio_p->num);
    return fd;
}

UPROBE(SSL_read, pt_regs)
{
    UPROBE_PARMS_STASH(SSL_read, ctx, PROG_SSL_READ);
}

URETPROBE(SSL_read, pt_regs)
{
    struct probe_val val;
    if (PROBE_GET_PARMS(SSL_read, ctx, val, PROG_SSL_READ) < 0) {
        return 0;
    }

    struct ssl_st* ssl_st_p = (struct ssl_st*)PROBE_PARM1(val);
    int fd = get_fd_from_ssl(ssl_st_p, MSG_READ);
    if (fd < 0) {
        return 0;
    }

    process_rdwr_msg(fd, (const char *)PROBE_PARM2(val), (int)PT_REGS_RC(ctx), MSG_READ, ctx);
    return 0;
}

UPROBE(SSL_write, pt_regs)
{
    struct ssl_st* ssl_st_p = (struct ssl_st*)PT_REGS_PARM1(ctx);
    int fd = get_fd_from_ssl(ssl_st_p, MSG_WRITE);
    if (fd < 0) {
        return 0;
    }

    process_rdwr_msg(fd, (char *)PT_REGS_PARM2(ctx), (int)PT_REGS_PARM3(ctx), MSG_WRITE, ctx);
    return 0;
}
