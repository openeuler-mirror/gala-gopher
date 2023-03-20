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
 * Author: Ernest
 * Create: 2022-08-27
 * Description: sslprobe bpf prog
 ******************************************************************************/
#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif
#define BPF_PROG_USER

#include "httpprobe.bpf.h"

typedef long (*bio_callback_fn)(void);

char g_linsence[] SEC("license") = "GPL";

enum msg_event_rw_t {
    MSG_READ,
    MSG_WRITE,
};

struct bio_st {
    const struct ssl_method_st* method;
    bio_callback_fn callback;
    bio_callback_fn callback_ex;
    char* cb_arg;
    int init;
    int shutdown;
    int flags;
    int retry_reason;
    int num;
};

struct ssl_st {
    int version;
    const struct ssl_method_st *method;
    struct bio_st *rbio;
    struct bio_st *wbio;
};

static __always_inline int get_fd_from_ssl(const struct ssl_st* ssl_st_p, enum msg_event_rw_t rw_type)
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

UPROBE_RET(SSL_read, pt_regs, CTX_USER)
{
    char buf[REQ_BUF_SIZE] = {0};
    struct conn_key_t key = {0};
    struct conn_data_t *data = NULL;
    struct probe_val val = {0};
    struct ssl_st* ssl_st_p = NULL;

    if (PROBE_GET_PARMS(SSL_read, ctx, val, CTX_USER) < 0 || (int)PT_REGS_RC(ctx) < REQ_BUF_SIZE) {
        bpf_printk("SSL_read fail...");
        return 0;
    }
    key.tgid = bpf_get_current_pid_tgid() >> TGID_LSHIFT_LEN;
    ssl_st_p = (struct ssl_st*)PROBE_PARM1(val);
    key.skfd = get_fd_from_ssl(ssl_st_p, MSG_READ);
    data = bpf_map_lookup_elem(&conn_map, &key);
    if (data == NULL || data->status == READY_FOR_SEND) {
        return 0;
    }
    bpf_probe_read(buf, REQ_BUF_SIZE, (const char *)PROBE_PARM2(val));
    data->method = parse_req_method(buf);
    if (data->method == HTTP_UNKNOWN) {
        data->status = READY_FOR_RECVIVE;
        return 0;
    }
    data->status = READY_FOR_SEND;
    data->recvtime = bpf_ktime_get_ns();
    return 0;
}

UPROBE_RET(SSL_write, pt_regs, CTX_USER)
{
    struct conn_key_t ckey = {0};
    struct conn_data_t *cdata = NULL;
    struct conn_samp_key_t cskey = {0};
    struct conn_samp_data_t *csdata = NULL;
    struct probe_val val = {0};
    struct ssl_st* ssl_st_p = NULL;

    if (PROBE_GET_PARMS(SSL_write, ctx, val, CTX_USER) < 0 || (int)PT_REGS_RC(ctx) <= REQ_BUF_SIZE - 1) {
        bpf_printk("SSL_write fail...");
        return 0;
    }
    ckey.tgid = bpf_get_current_pid_tgid() >> TGID_LSHIFT_LEN ;
    ssl_st_p = (struct ssl_st*)PROBE_PARM1(val);
    ckey.skfd = get_fd_from_ssl(ssl_st_p, MSG_WRITE);
    cdata = bpf_map_lookup_elem(&conn_map, &ckey);
    if (cdata == NULL || cdata->status == READY_FOR_RECVIVE) {
        return 0;
    }
 
    cskey.sk = (struct sock *)cdata->sock;
    if (cskey.sk == 0) {
        return 0;
    }
    csdata = (struct conn_samp_data_t *)bpf_map_lookup_elem(&conn_samp_map, &cskey);
    if (csdata == NULL) {
        return 0;
    }
    csdata->method = cdata->method;
    csdata->status = READY_FOR_SKBSENT;
    csdata->recvtime = cdata->recvtime;
    csdata->endseq = 0;
    
    cdata->status = READY_FOR_RECVIVE;
    cdata->recvtime = 0;
    cdata->method = HTTP_UNKNOWN;
    return 0;
}