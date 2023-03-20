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
 * Author: wo_cow
 * Create: 2022-7-29
 * Description: pgsli_uprobe bpf prog
 ******************************************************************************/
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
