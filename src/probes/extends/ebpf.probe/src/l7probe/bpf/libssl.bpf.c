/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wo_cow
 * Create: 2023-03-13
 * Description: openssl layer 
 ******************************************************************************/
#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#define BPF_PROG_USER
#include "bpf.h"
#include <bpf/bpf_endian.h>
#include "include/conn_tracker.h"

char g_license[] SEC("license") = "GPL";

enum {
    PROG_SSL_READ = 0,
    PROG_SSL_WRITE,
};


#define __MAX_SSL_ENTRIES 1024


// ssl struct in openssl 1.1.1
typedef long (*bio_callback_fn)();
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
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, __PERF_OUT_MAX);
} ssl_msg_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct ssl_msg_t));
    __uint(max_entries, 1);
} tmp_map SEC(".maps");

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

static __always_inline void process_rdwr_msg(struct ssl_st* ssl_st_p, const char *ori_buf, int count,
                                             enum msg_event_rw_t rw_type, struct pt_regs *ctx)
{
    const char *buf;

    if (ori_buf == NULL || count <= 0) {
        return;
    }
    int fd = get_fd_from_ssl(ssl_st_p, rw_type);
    if (fd < 0) {
        return;
    }

    u64 tgid = bpf_get_current_pid_tgid();
    u32 key = 0;
    struct ssl_msg_t *ssl_msg = bpf_map_lookup_elem(&tmp_map, &key);
    if (!ssl_msg)
        return;
    ssl_msg->msg_type = rw_type;
    ssl_msg->tgid = tgid;
    ssl_msg->fd = fd;
    ssl_msg->count = count;
    ssl_msg->ts_nsec = bpf_ktime_get_ns();

    bpf_probe_read(&buf, sizeof(const char*), &ori_buf);
    int len = count < MAX_MSG_LEN_SSL ? (count & (MAX_MSG_LEN_SSL - 1)) : MAX_MSG_LEN_SSL;
    bpf_probe_read_user(ssl_msg->msg, len, buf);
    bpf_perf_event_output(ctx, &ssl_msg_map, BPF_F_CURRENT_CPU, ssl_msg, sizeof(struct ssl_msg_t));
    return;
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
    
    process_rdwr_msg((struct ssl_st*)PROBE_PARM1(val), (const char *)PROBE_PARM2(val), (int)PT_REGS_RC(ctx), MSG_READ, ctx);
    return 0;
}

UPROBE(SSL_write, pt_regs)
{
    process_rdwr_msg((struct ssl_st*)PT_REGS_PARM1(ctx), (char *)PT_REGS_PARM2(ctx), (int)PT_REGS_PARM3(ctx), MSG_WRITE, ctx);
    return 0;
}

