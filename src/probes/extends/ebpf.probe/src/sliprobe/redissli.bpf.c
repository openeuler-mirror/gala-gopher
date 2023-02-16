/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: algorithmofdish
 * Create: 2022-3-8
 * Description: redis SLI probe bpf prog
 ******************************************************************************/
#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif
#define BPF_PROG_USER
#include "bpf.h"
#include "redissli.h"

#define MAX_CONN_LEN            8192

#define BPF_F_INDEX_MASK        0xffffffffULL
#define BPF_F_CURRENT_CPU       BPF_F_INDEX_MASK

enum {
    PROG_READQUERYFROMCLIENT = 0,
    PROG_PROCESSCOMMAND,
    PROG_WRITETOCLIENT,
    PROG_FREECLIENT,
};

char g_license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct conn_key_t));
    __uint(value_size, sizeof(struct conn_data_t));
    __uint(max_entries, MAX_CONN_LEN);
} conn_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} conn_cmd_evt_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));  // const value 0
    __uint(value_size, sizeof(u64));  // period time as second
    __uint(max_entries, 1);
} period_map SEC(".maps");

static __always_inline int get_client_fd(client *c)
{
    connection *conn = _(c->conn);
    int fd = _(conn->fd);
    return fd;
}

static __always_inline void init_conn_key(struct conn_key_t *conn_key, int fd, int tgid)
{
    conn_key->fd = fd;
    conn_key->tgid = tgid;
}

static __always_inline void init_conn_id(struct conn_id_t *conn_id, int fd, int tgid)
{
    conn_id->fd = fd;
    conn_id->tgid = tgid;
    conn_id->ts_nsec = bpf_ktime_get_ns();
}

static __always_inline struct conn_data_t *create_conn_from_client(client *c)
{
    unsigned int tgid = bpf_get_current_pid_tgid() >> INT_LEN;
    int fd = get_client_fd(c);

    struct conn_key_t conn_key;
    struct conn_data_t conn_data = {0};

    init_conn_key(&conn_key, fd, tgid);
    init_conn_id(&conn_data.id, fd, tgid);
    conn_data.last_smp_ts_nsec = bpf_ktime_get_ns();
    bpf_map_update_elem(&conn_map, &conn_key, &conn_data, BPF_ANY);

    return (struct conn_data_t *)bpf_map_lookup_elem(&conn_map, &conn_key);
}

static __always_inline struct conn_data_t *get_conn_from_client(client *c)
{
    struct conn_key_t conn_key;
    unsigned int tgid = bpf_get_current_pid_tgid() >> INT_LEN;
    int fd = get_client_fd(c);

    init_conn_key(&conn_key, fd, tgid);
    return (struct conn_data_t *)bpf_map_lookup_elem(&conn_map, &conn_key);
}

#define __PERIOD ((u64)30 * 1000000000)
static __always_inline u64 get_period()
{
    u32 key = 0;
    u64 period = __PERIOD;

    u64 *value = (u64 *)bpf_map_lookup_elem(&period_map, &key);
    if (value)
        period = *value;

    return period; // units from second to nanosecond
}

// 监控 readQueryFromClient 事件，初始化客户端连接，并更新请求消息到达应用层的时间点
UPROBE(readQueryFromClient, pt_regs)
{
    u64 ts_nsec = bpf_ktime_get_ns();
    connection *conn = (connection *)PT_REGS_PARM1(ctx);
    client *c = (client *)_(conn->private_data);

    struct conn_data_t *conn_data;

    conn_data = get_conn_from_client(c);
    if (conn_data == (void *)0) {
        conn_data = create_conn_from_client(c);
    }
    if (conn_data == (void *)0) {
        return;
    }

    // 当前周期已有采样数据时，不更新客户端连接
    if (conn_data->cmd_nums > 0) {
        return;
    }

    conn_data->last_read_ts_nsec = ts_nsec;
    conn_data->rd_bufsize = 0;
    conn_data->rd_listsize = 0;
}

// 监控 redis 命令处理函数，获取命令的元数据信息
UPROBE(processCommand, pt_regs)
{
    client *c = (client *)PT_REGS_PARM1(ctx);

    struct conn_data_t *conn_data;
    struct redis_cmd_data_t *cmd;
    robj **argv;
    robj *argv0;
    void *name;

    conn_data = get_conn_from_client(c);
    if (conn_data == (void *)0) {
        return;
    }

    // 当前周期已有采样数据时，后续数据不再处理
    if (conn_data->cmd_nums > 0) {
        return;
    }

    // 添加一个新请求
    cmd = &(conn_data->cmds[0]);
    argv = _(c->argv);
    argv0 = _(argv[0]);
    name = _(argv0->ptr);
    bpf_probe_read_str(cmd->name, MAX_REDIS_CMD_LEN, name);
    cmd->start_ts_nsec = conn_data->last_read_ts_nsec;
    cmd->finished = 0;
    conn_data->cmd_nums = 1;

    // 更新客户端写缓冲区的状态
    conn_data->cur_bufpos = _(c->bufpos);
    conn_data->cur_listpos = _(c->reply_bytes);

    UPROBE_PARMS_STASH(processCommand, ctx, PROG_PROCESSCOMMAND);
}

URETPROBE(processCommand, pt_regs)
{
    u64 ts_nsec = bpf_ktime_get_ns();
    struct probe_val val;
    client *c;

    struct conn_data_t *conn_data;
    struct redis_cmd_data_t *cmd;
    u64 cur_bufpos;
    u64 cur_listpos;

    if (PROBE_GET_PARMS(processCommand, ctx, val, PROG_PROCESSCOMMAND) < 0) {
        return;
    }
    c = (client *)PROBE_PARM1(val);

    conn_data = get_conn_from_client(c);
    if (conn_data == (void *)0) {
        return;
    }

    cmd = &(conn_data->cmds[0]);
    cur_bufpos = _(c->bufpos);
    cur_listpos = _(c->reply_bytes);
    if (conn_data->cur_bufpos < cur_bufpos) {   // 应答消息写入静态 buffer
        cmd->has_reply = 1;
        cmd->store_type = STATIC_BUFFER;
        cmd->wr_bufpos = cur_bufpos;
    } else if (conn_data->cur_listpos < cur_listpos) {  // 应答消息写入动态 list
        cmd->has_reply = 1;
        cmd->store_type = DYNAMIC_LIST;
        cmd->wr_listpos = cur_listpos;
    } else {    // 无应答消息
        cmd->has_reply = 0;
        cmd->store_type = NO_STORAGE;
        cmd->end_ts_nsec = ts_nsec;
        cmd->finished = 1;
    }
}

// 监控 writeToClient 事件，获取应答消息离开应用层的时间点
// int writeToClient(client *c, int handler_installed);
UPROBE(writeToClient, pt_regs)
{
    client *c = (client *)PT_REGS_PARM1(ctx);

    struct conn_data_t *conn_data;

    conn_data = get_conn_from_client(c);
    if (conn_data == (void *)0) {
        return;
    }
    conn_data->cur_bufpos = _(c->bufpos);
    conn_data->cur_listpos = _(c->reply_bytes);

    UPROBE_PARMS_STASH(writeToClient, ctx, PROG_WRITETOCLIENT);
}

static __always_inline void submit_conn_cmd_event(struct conn_data_t *conn_data, struct pt_regs *ctx)
{
    struct cmd_event_data_t cmd_data;

    cmd_data.conn_id = conn_data->id;
    cmd_data.timeout_nsec = conn_data->cmds[0].end_ts_nsec - conn_data->cmds[0].start_ts_nsec;
    __builtin_memcpy(&cmd_data.name, &conn_data->cmds[0].name, MAX_REDIS_CMD_LEN);

    bpf_perf_event_output(ctx, &conn_cmd_evt_map, BPF_F_CURRENT_CPU, &cmd_data, sizeof(struct cmd_event_data_t));
}

URETPROBE(writeToClient, pt_regs)
{
    u64 ts_nsec = bpf_ktime_get_ns();
    struct probe_val val;
    client *c;

    struct conn_data_t *conn_data;
    u64 cur_bufpos;
    u64 cur_listpos;
    u64 period;

    if (PROBE_GET_PARMS(writeToClient, ctx, val, PROG_WRITETOCLIENT) < 0) {
        return;
    }
    c = (client *)PROBE_PARM1(val);

    conn_data = get_conn_from_client(c);
    if (conn_data == (void *)0) {
        return;
    }

    // 更新客户端连接已处理的响应字节数
    cur_bufpos = _(c->bufpos);
    cur_listpos = _(c->reply_bytes);
    if (cur_bufpos < conn_data->cur_bufpos) {
        conn_data->rd_bufsize += conn_data->cur_bufpos - cur_bufpos;
    }
    if (cur_listpos < conn_data->cur_listpos) {
        conn_data->rd_listsize += conn_data->cur_listpos - cur_listpos;
    }

    if (conn_data->cmd_nums == 0) {
        return;
    }

    // 当已处理的响应字节数大于 redis 请求的写入位置时，则该请求在应用层处理完毕，记录该请求的结束时间点
    if (!conn_data->cmds[0].finished) {
        if (conn_data->cmds[0].store_type == STATIC_BUFFER && conn_data->cmds[0].wr_bufpos <= conn_data->rd_bufsize) {
            conn_data->cmds[0].end_ts_nsec = ts_nsec;
            conn_data->cmds[0].finished = 1;
        }
        if (conn_data->cmds[0].store_type == DYNAMIC_LIST && conn_data->cmds[0].wr_listpos <= conn_data->rd_listsize) {
            conn_data->cmds[0].end_ts_nsec = ts_nsec;
            conn_data->cmds[0].finished = 1;
        }
    }

    // 若超过采样周期，则将已处理好的请求发送给用户态，并且重置采样时间点，采样新的 redis 请求
    period = get_period();
    if (ts_nsec - conn_data->last_smp_ts_nsec > period) {
        if (conn_data->cmds[0].finished) {
            submit_conn_cmd_event(conn_data, ctx);
        }
        conn_data->last_smp_ts_nsec = ts_nsec;
        conn_data->cmd_nums = 0;
    }
}

// 端口 redis 客户端连接
UPROBE(freeClient, pt_regs)
{
    client *c = (client *)PT_REGS_PARM1(ctx);

    struct conn_key_t conn_key;
    struct conn_data_t *conn_data;
    unsigned int tgid = bpf_get_current_pid_tgid() >> INT_LEN;
    int fd = get_client_fd(c);

    init_conn_key(&conn_key, fd, tgid);
    conn_data = (struct conn_data_t *)bpf_map_lookup_elem(&conn_map, &conn_key);
    if (conn_data == (void *)0) {
        return;
    }

    if (conn_data->cmd_nums > 0 && conn_data->cmds[0].finished) {
        submit_conn_cmd_event(conn_data, ctx);
    }

    bpf_map_delete_elem(&conn_map, &conn_key);
}