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
 * Description: pgsliprobe bpf header file
 ******************************************************************************/
#ifndef __PGSLIPROBE_BPF_H__
#define __PGSLIPROBE_BPF_H__

#ifndef __PERIOD
#define __PERIOD NS(30)
#endif

#define MAX_MSG_LEN_SSL 32
#define MAX_COMMAND_REQ_SIZE (32 - 1)
#define MAX_CONN_LEN            8192

#define BPF_F_INDEX_MASK    0xffffffffULL
#define BPF_F_ALL_CPU   BPF_F_INDEX_MASK

#ifndef __PERF_OUT_MAX
#define __PERF_OUT_MAX (64)
#endif

enum samp_status_t {
    SAMP_INIT = 0,
    SAMP_READ_READY,
    SAMP_WRITE_READY,
    SAMP_SKB_READY,
    SAMP_FINISHED,
};

enum msg_event_rw_t {
    MSG_READ, // 读消息事件
    MSG_WRITE, // 写消息事件
};

struct conn_key_t {
    __u32 tgid;
    int fd;
};

struct conn_data_t {
    struct conn_info_t conn_info;
    void *sk; // tcp连接对应的 sk 地址
    struct rtt_cmd_t latency;
    struct rtt_cmd_t max;
    __u64 last_report_ts_nsec;
};

struct conn_samp_data_t {
    enum samp_status_t status;
    u32 end_seq;
    u64 start_ts_nsec;
    u64 rtt_ts_nsec;
    char req_cmd;
};

struct bpf_map_def SEC("maps") conn_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct conn_key_t),
    .value_size = sizeof(struct conn_data_t),
    .max_entries = MAX_CONN_LEN,
};

// Data collection args
struct bpf_map_def SEC("maps") args_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32), // const value 0
    .value_size = sizeof(struct ogsli_args_s), // args
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") conn_samp_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32), // struct sock *
    .value_size = sizeof(struct conn_samp_data_t),
    .max_entries = MAX_CONN_LEN,
};

struct bpf_map_def SEC("maps") output = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = __PERF_OUT_MAX,
};

static __always_inline void sample_finished(struct conn_data_t *conn_data, struct conn_samp_data_t *csd)
{
    if (conn_data->latency.rtt_nsec == 0) {
        conn_data->latency.rtt_nsec = csd->rtt_ts_nsec;
        conn_data->latency.req_cmd = csd->req_cmd;
    }
    if (conn_data->max.rtt_nsec < csd->rtt_ts_nsec) {
        conn_data->max.rtt_nsec = csd->rtt_ts_nsec;
        conn_data->max.req_cmd = csd->req_cmd;
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


static __always_inline char read_first_byte_from_buf(const char *ori_buf, int ori_len, enum msg_event_rw_t rw_type)
{
    char msg[MAX_MSG_LEN_SSL] = {0};
    const char *buf;
    int len;

    if (ori_buf == NULL) {
        return 0;
    }
    bpf_probe_read(&buf, sizeof(const char*), &ori_buf);
    len = ori_len < MAX_MSG_LEN_SSL ? (ori_len & (MAX_MSG_LEN_SSL - 1)) : MAX_MSG_LEN_SSL;
    bpf_probe_read_user(msg, len, buf);
    if (rw_type == MSG_READ) {
        if (msg[0] == 'B' || msg[0] == 'Q')
            return msg[0];
        else
            return 0;
    }

    return msg[0];
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
        if (conn_data->latency.rtt_nsec < period * 2 && conn_data->max.rtt_nsec < period * 2) {
            struct msg_event_data_t msg_evt_data = {0};
            msg_evt_data.tgid = conn_key->tgid;
            msg_evt_data.fd = conn_key->fd;
            msg_evt_data.conn_info = conn_data->conn_info;
            msg_evt_data.latency = conn_data->latency;
            msg_evt_data.max = conn_data->max;
            err = bpf_perf_event_output(ctx, &output, BPF_F_ALL_CPU,
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
    char cmd;
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

    if (rw_type == MSG_READ) { // MSG_READ
        if (csd->status == SAMP_READ_READY) {
            return;
        }
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
            }
            return;
        }
        cmd = read_first_byte_from_buf(buf, count, rw_type);
        if (cmd == 0) {
            return;
        }
        csd->req_cmd = cmd;

#ifndef KERNEL_SUPPORT_TSTAMP
        csd->start_ts_nsec = ts_nsec;
#else
        if (csd->start_ts_nsec == 0) {
            csd->start_ts_nsec = ts_nsec;
        }
#endif
        csd->status = SAMP_READ_READY;
    } else {  // MSG_WRITE
        if (csd->status == SAMP_READ_READY) {
            cmd = read_first_byte_from_buf(buf, count, rw_type);
            if (cmd == 0) {
                return;
            }
            csd->status = SAMP_WRITE_READY;
        }
    }

    return;
}

#endif