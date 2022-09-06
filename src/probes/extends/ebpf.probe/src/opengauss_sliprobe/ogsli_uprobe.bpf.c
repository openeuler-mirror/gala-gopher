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
 * Description: ogsli_uprobe bpf prog
 ******************************************************************************/
#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#define BPF_PROG_USER
#include "bpf.h"
#include <bpf/bpf_endian.h>
#include "opengauss_sli.h"
#include "opengauss_bpf.h"

char g_license[] SEC("license") = "GPL";

#define BPF_F_INDEX_MASK        0xffffffffULL
#define BPF_F_CURRENT_CPU       BPF_F_INDEX_MASK

#ifndef __PERIOD
#define __PERIOD NS(30)
#endif

enum {
    PROG_SSL_READ = 0,
    PROG_SSL_WRITE,
};

enum msg_event_rw_t {
    MSG_READ, // 读消息事件
    MSG_WRITE, // 写消息事件
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

struct bpf_map_def SEC("maps") msg_event_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
};

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

static __always_inline char read_first_byte_from_buf(const char *ori_buf, int ori_len)
{
    char msg[MAX_MSG_LEN_SSL] = {0};
    const char *buf;
    int len;

    if (ori_len < 0 || ori_buf == NULL) {
        return 0;
    }
    bpf_probe_read(&buf, sizeof(const char*), &ori_buf);
    len = ori_len < MAX_MSG_LEN_SSL ? (ori_len & (MAX_MSG_LEN_SSL - 1)) : MAX_MSG_LEN_SSL;
    bpf_probe_read_user(msg, len, buf);

    // case 'd': copy data
    // case 'R': Reply collect info
    if (msg[0] < 'A' || msg[0] >'z' || msg[0] == 'd' || msg[0] == 'R') {
    //if (!(msg[0] == 'Q' || msg[0] == 'P')) {
        return 0;
    }
    return msg[0];
}

static __always_inline void sample_finished(struct conn_data_t *conn_data, struct conn_samp_data_t *csd)
{
    if (conn_data->latency.rtt_nsec == 0) {
        conn_data->latency.rtt_nsec = csd->rtt_ts_nsec;
        conn_data->latency.req_cmd = csd->req_cmd;
        conn_data->latency.rsp_cmd = csd->rsp_cmd;
    }
    if (conn_data->max.rtt_nsec < csd->rtt_ts_nsec) {
        conn_data->max.rtt_nsec = csd->rtt_ts_nsec;
        conn_data->max.req_cmd = csd->req_cmd;
        conn_data->max.rsp_cmd = csd->rsp_cmd;
    }
    csd->status = SAMP_INIT;
}

static __always_inline u64 get_period()
{
    u32 key = 0;
    u64 period = __PERIOD;

    struct ogsli_args_s *args;
    args = (struct ogsli_args_s *)bpf_map_lookup_elem(&args_map, &key);
    if (args) {
        period = args->period;
    }

    return period; // units from second to nanosecond
}

static __always_inline void periodic_report(u64 ts_nsec, struct conn_data_t *conn_data,
    struct conn_key_t *conn_key, struct pt_regs *ctx)
{
    long err;
    u64 period = get_period();
    // 表示没有任何采样数据，不上报
    if (conn_data->latency.rtt_nsec == 0) {
        return;
    }

    if (ts_nsec > conn_data->last_report_ts_nsec &&
        ts_nsec - conn_data->last_report_ts_nsec >= period) {
        // rtt larger than period is considered an invalid value
        if (conn_data->latency.rtt_nsec < period && conn_data->max.rtt_nsec < period) {
            struct msg_event_data_t msg_evt_data = {0};
            msg_evt_data.tgid = conn_key->tgid;
            msg_evt_data.fd = conn_key->fd;
            msg_evt_data.conn_info = conn_data->conn_info;
            msg_evt_data.latency = conn_data->latency;
            msg_evt_data.max = conn_data->max;
            err = bpf_perf_event_output(ctx, &msg_event_map, BPF_F_CURRENT_CPU,
                                        &msg_evt_data, sizeof(struct msg_event_data_t));
            if (err < 0) {
                bpf_printk("message event sent failed.\n");
            }
        }
        conn_data->latency.rtt_nsec = 0;
        conn_data->max.rtt_nsec = 0;
        conn_data->last_report_ts_nsec = ts_nsec;
    }

    return;
}

static __always_inline void process_rdwr_msg(int fd, const char *buf, int count, enum msg_event_rw_t rw_type,
                                             struct pt_regs *ctx)
{
    u32 tgid = bpf_get_current_pid_tgid() >> INT_LEN;
    u64 ts_nsec = bpf_ktime_get_ns();
    struct conn_samp_data_t *csd;
    if (count <= 0) {
        return;
    }
    struct conn_key_t conn_key = {.fd = fd, .tgid = tgid};
    struct conn_data_t *conn_data = (struct conn_data_t *)bpf_map_lookup_elem(&conn_map, &conn_key);
    if (conn_data == NULL) {
        return;
    }
 
    csd = (struct conn_samp_data_t *)bpf_map_lookup_elem(&conn_samp_map, &conn_data->sk);
    if (csd == NULL) {
        return;
    }

    char cmd = read_first_byte_from_buf(buf, count);
    if (cmd == 0) {
        return;
    }
    
    if (rw_type == MSG_READ) { // MSG_READ
        if (csd->status == SAMP_FINISHED) {
            sample_finished(conn_data, csd);
        }

        // 周期上报
        periodic_report(ts_nsec, conn_data, &conn_key, ctx);

        if (csd->status != SAMP_INIT) {
            // 超过采样周期，则重置采样状态，避免采样状态一直处于不可达的情况
            if (ts_nsec > csd->start_ts_nsec &&
                ts_nsec - csd->start_ts_nsec >= __PERIOD) {
                csd->status = SAMP_INIT;
                csd->start_ts_nsec = 0;
            }
            return;
        }

        csd->req_cmd = cmd;
#ifndef KERNEL_SUPPORT_TSTAMP
        if (csd->start_ts_nsec == 0) {
            csd->start_ts_nsec = ts_nsec;
        }
#endif
        csd->status = SAMP_READ_READY;
    } else {  // MSG_WRITE
        csd->rsp_cmd = cmd;
        if (csd->status == SAMP_READ_READY) {
            csd->status = SAMP_WRITE_READY;
        }
    }

    return;
}

UPROBE(SSL_read, pt_regs)
{
    UPROBE_PARMS_STASH(SSL_read, ctx, PROG_SSL_READ);
}

URETPROBE(SSL_read, pt_regs)
{
    u32 tgid __maybe_unused = bpf_get_current_pid_tgid() >> INT_LEN;
    struct probe_val val;
    if (PROBE_GET_PARMS(SSL_read, ctx, val, PROG_SSL_READ) < 0) {
        return;
    }

    struct ssl_st* ssl_st_p = (struct ssl_st*)PROBE_PARM1(val);
    int fd = get_fd_from_ssl(ssl_st_p, MSG_READ);
    if (fd < 0) {
        return;
    }

    process_rdwr_msg(fd, (const char *)PROBE_PARM2(val), (int)PT_REGS_RC(ctx), MSG_READ, ctx);
}

UPROBE(SSL_write, pt_regs)
{
    u32 tgid __maybe_unused = bpf_get_current_pid_tgid() >> INT_LEN;
    struct ssl_st* ssl_st_p = (struct ssl_st*)PT_REGS_PARM1(ctx);
    int fd = get_fd_from_ssl(ssl_st_p, MSG_WRITE);
    if (fd < 0) {
        return;
    }

    process_rdwr_msg(fd, (char *)PT_REGS_PARM2(ctx), (int)PT_REGS_PARM3(ctx), MSG_WRITE, ctx);
}
