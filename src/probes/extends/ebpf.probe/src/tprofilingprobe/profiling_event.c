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
 * Author: algorithmofdish
 * Create: 2023-04-03
 * Description: handling thread profiling event
 ******************************************************************************/
#include <stdio.h>
#include <time.h>
#include <linux/futex.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "event.h"
#include "strbuf.h"
#include "proc_info.h"
#include "profiling_event.h"
#include "kern_symb.h"

#define LEN_OF_RESOURCE 1024
#define LEN_OF_ATTRS    8192

static __u64 g_boot_time = 0;
static proc_info_t *g_proc_table = NULL;

static int get_sys_boot_time(__u64 *boot_time);
static __u64 get_unix_time_from_uptime(__u64 uptime);

static void set_syscall_name(unsigned long nr, char *name);
static int set_evt_resource(trace_event_data_t *evt_data, char *evt_resource, int resource_size);
static int set_evt_attrs(trace_event_data_t *evt_data, char *evt_attrs, int attrs_size);

int init_sys_boot_time()
{
    return get_sys_boot_time(&g_boot_time);
}

static __u64 get_unix_time_from_uptime(__u64 uptime)
{
    return g_boot_time + uptime;
}

void output_profiling_event(trace_event_data_t *evt_data)
{
    __u64 timestamp = 0;
    char resource[LEN_OF_RESOURCE] = {0};
    char attrs[LEN_OF_ATTRS] = {0};
    struct otel_log ol = {0};

    timestamp = get_unix_time_from_uptime(evt_data->timestamp) / NSEC_PER_MSEC;
    if (set_evt_resource(evt_data, resource, LEN_OF_RESOURCE)) {
        return;
    }
    if (set_evt_attrs(evt_data, attrs, LEN_OF_ATTRS)) {
        return;
    }

    ol.timestamp = timestamp;
    ol.sec = EVT_SEC_INFO;
    ol.resource = resource;
    ol.attrs = attrs;
    ol.body = "";

    emit_otel_log(&ol);
}

// system boot time = current time - uptime since system boot.
static int get_sys_boot_time(__u64 *boot_time)
{
    struct timespec ts_cur_time = {0};
    struct timespec ts_uptime = {0};
    __u64 cur_time = 0;
    __u64 uptime = 0;

    if (clock_gettime(CLOCK_REALTIME, &ts_cur_time)) {
        return -1;
    }
    cur_time = (__u64)ts_cur_time.tv_sec * NSEC_PER_SEC + ts_cur_time.tv_nsec;

    if (clock_gettime(CLOCK_BOOTTIME, &ts_uptime)) {
        return -1;
    }
    uptime = (__u64)ts_uptime.tv_sec * NSEC_PER_SEC + ts_uptime.tv_nsec;

    if (uptime >= cur_time) {
        return -1;
    }
    *boot_time = cur_time - uptime;

    return 0;
}

extern syscall_meta_t *g_syscall_meta_table;

static syscall_meta_t *get_syscall_meta(unsigned long nr)
{
    syscall_meta_t *scm;

    HASH_FIND(hh, g_syscall_meta_table, &nr, sizeof(unsigned long), scm);
    if (scm == NULL) {
        fprintf(stderr, "WARN: cannot find syscall metadata of syscall number:%ld.\n", nr);
    }

    return scm;
}

static void set_syscall_name(unsigned long nr, char *name)
{
    syscall_meta_t *scm;

    scm = get_syscall_meta(nr);
    if (scm == NULL) {
        return;
    }
    strcpy(name, scm->name);
}

static char *get_proc_comm(int tgid)
{
    proc_info_t *pi;

    pi = HASH_find_proc_info(&g_proc_table, tgid);
    if (pi == NULL) {
        pi = add_proc_info(&g_proc_table, tgid);
        if (pi == NULL) {
            return NULL;
        }
    }

    return pi->comm;
}

static int set_evt_resource(trace_event_data_t *evt_data, char *evt_resource, int resource_size)
{
    int expect_size = 0;
    char *proc_comm;

    proc_comm = get_proc_comm(evt_data->tgid);
    if (proc_comm == NULL) {
        return -1;
    }

    expect_size = snprintf(evt_resource, resource_size,
                           "{\"thread.pid\":\"%d\",\"thread.tgid\":\"%d\",\"thread.comm\":\"%s\""
                           ",\"process.comm\":\"%s\"}",
                           evt_data->pid, evt_data->tgid, evt_data->comm, proc_comm);
    if (expect_size >= resource_size) {
        fprintf(stderr, "ERROR: resource size not large enough\n");
        return -1;
    }

    return 0;
}

extern int g_stackmap_fd;

int get_addr_stack(__u64 *addr_stack, int uid)
{
    if (g_stackmap_fd <= 0) {
        fprintf(stderr, "ERROR: cannot get stack map fd:%d.\n", g_stackmap_fd);
        return -1;
    }

    if (uid <= 0) {
        return -1;
    }
    if (bpf_map_lookup_elem(g_stackmap_fd, &uid, addr_stack) != 0) {
        return -1;
    }

    return 0;
}

static void stack_transfer_addrs2symbs(__u64 *addrs, int addr_num,
                                      char *symbs_str, int symb_size, proc_info_t *proc_info)
{
    struct proc_symbs_s *symbs;
    struct addr_symb_s symb = {0};
    char *symb_name;
    int i;
    strbuf_t symbs_buf = {
        .buf = symbs_str,
        .size = symb_size
    };
    int ret;

    symbs = proc_info->symbs;

    for (i = addr_num - 1; i >= 0; i--) {
        if (!addrs[i]) {
            continue;
        }

        memset(&symb, 0, sizeof(symb));
        ret = proc_search_addr_symb(symbs, addrs[i], &symb, proc_info->comm);
        if (ret) {
            symb_name = "";
        } else {
            symb_name = symb.sym ?: symb.mod;
        }

        ret = snprintf(symbs_buf.buf, symbs_buf.size, "%s;", symb_name);
        if (ret < 0 || ret >= symbs_buf.size) {
            // it is allowed that stack may be truncated
            fprintf(stderr, "WARN: stack buffer not large enough.\n");
            return;
        }
        strbuf_update_offset(&symbs_buf, ret);
    }
}

static int get_symb_stack(char *symbs_str, int symb_size, trace_event_data_t *evt_data)
{
    __u64 ip[PERF_MAX_STACK_DEPTH] = {0};

    proc_info_t *pi;
    struct proc_symbs_s *symbs;
    int uid;

    uid = evt_data->syscall_d.stack_info.uid;
    if (get_addr_stack(ip, uid)) {
        return -1;
    }

    pi = get_proc_info(&g_proc_table, evt_data->tgid);
    if (pi == NULL) {
        return -1;
    }

    // cache process symbol table if not
    symbs = get_symb_info(pi);
    if (symbs == NULL) {
        return -1;
    }

    stack_transfer_addrs2symbs(ip, PERF_MAX_STACK_DEPTH, symbs_str, symb_size, pi);

    return 0;
}

#define FUNC_NAME_LEN 32

static int append_stack_attrs(strbuf_t *attrs_buf, trace_event_data_t *evt_data)
{
    int ret;
    char symbs_str[PERF_MAX_STACK_DEPTH * FUNC_NAME_LEN] = {0};

    ret = get_symb_stack(symbs_str, sizeof(symbs_str), evt_data);
    if (ret) {
        return 0;
    }

    ret = snprintf(attrs_buf->buf, attrs_buf->size, ",\"func.stack\":\"%s\"", symbs_str);
    if (ret < 0 || ret >= attrs_buf->size) {
        fprintf(stderr, "ERROR: Failed to set func.stack attribute.\n");
        return -1;
    }
    strbuf_update_offset(attrs_buf, ret);

    return 0;
}

static int append_regular_file_attrs(strbuf_t *attrs_buf, fd_info_t *fd_info)
{
    int ret;

    ret = snprintf(attrs_buf->buf, attrs_buf->size,
                   ",\"event.type\":\"%s\",\"file.path\":\"%s\"",
                   PROFILE_EVT_TYPE_FILE, fd_info->reg_info.name);
    if (ret < 0 || ret >= attrs_buf->size) {
        fprintf(stderr, "ERROR: Failed to set file.path attribute.\n");
        return -1;
    }
    strbuf_update_offset(attrs_buf, ret);

    return 0;
}

static int append_sock_attrs(strbuf_t *attrs_buf, fd_info_t *fd_info)
{
    int ret;
    sock_info_t *si = &fd_info->sock_info;

    switch (si->type) {
        case SOCK_TYPE_IPV4:
        case SOCK_TYPE_IPV6:
            ret = snprintf(attrs_buf->buf, attrs_buf->size,
                           ",\"event.type\":\"%s\",\"sock.conn\": \"%s\"",
                           PROFILE_EVT_TYPE_NET, si->ip_info.conn);
            if (ret < 0 || ret >= attrs_buf->size) {
                fprintf(stderr, "ERROR: Failed to set sock attributes.\n");
                return -1;
            }
            strbuf_update_offset(attrs_buf, ret);
            break;
        default:
            return -1;
    }
    return 0;
}

static int append_fd_attrs(strbuf_t *attrs_buf, trace_event_data_t *evt_data)
{
    int tgid = evt_data->tgid;
    int fd = evt_data->syscall_d.ext_info.fd_info.fd;
    proc_info_t *pi;
    fd_info_t *fi;

    pi = get_proc_info(&g_proc_table, tgid);
    if (pi == NULL) {
        return -1;
    }

    fi = get_fd_info(pi, fd);
    if (fi == NULL) {
        return -1;
    }

    switch (fi->type) {
        case FD_TYPE_REG:
            return append_regular_file_attrs(attrs_buf, fi);
        case FD_TYPE_SOCK:
            return append_sock_attrs(attrs_buf, fi);
        default:
            return -1;
    }
}

static int is_futex_wait_op(int op)
{
    int op_cmd = op & FUTEX_CMD_MASK;
    if (op_cmd == FUTEX_WAIT || op_cmd == FUTEX_WAIT_BITSET || op_cmd == FUTEX_LOCK_PI) {
        return 1;
    }
    return 0;
}

static int is_futex_wake_op(int op)
{
    int op_cmd = op & FUTEX_CMD_MASK;
    if (op_cmd == FUTEX_WAKE || op_cmd == FUTEX_WAKE_BITSET || op_cmd == FUTEX_UNLOCK_PI) {
        return 1;
    }
    return 0;
}

static int append_futex_attrs(strbuf_t *attrs_buf, trace_event_data_t *evt_data)
{
    int ret;
    char futexOp[8] = {0};
    int op;

    op = evt_data->syscall_d.ext_info.futex_info.op;
    if (is_futex_wait_op(op)) {
        strcpy(futexOp, "wait");
    } else if (is_futex_wake_op(op)) {
        strcpy(futexOp, "wake");
    }

    ret = snprintf(attrs_buf->buf, attrs_buf->size,
                   ",\"event.type\":\"%s\",\"futex.addr\":\"%p\",\"futex.op\":\"%s\"",
                   PROFILE_EVT_TYPE_FUTEX, evt_data->syscall_d.ext_info.futex_info.addr, futexOp);
    if (ret < 0 || ret >= attrs_buf->size) {
        fprintf(stderr, "ERROR: Failed to set futex attributes.\n");
        return -1;
    }
    strbuf_update_offset(attrs_buf, ret);

    return 0;
}

static int append_untyped_attrs(strbuf_t *attrs_buf, trace_event_data_t *evt_data)
{
    int ret;

    ret = snprintf(attrs_buf->buf, attrs_buf->size, ",\"event.type\":\"%s\"", PROFILE_EVT_TYPE_OTHER);
    if (ret < 0 || ret >= attrs_buf->size) {
        fprintf(stderr, "ERROR: Failed to set untyped attributes.\n");
        return -1;
    }
    strbuf_update_offset(attrs_buf, ret);

    return 0;
}
static int append_syscall_attrs_by_nr(strbuf_t *attrs_buf, trace_event_data_t *evt_data)
{
    syscall_meta_t *scm;
    unsigned long nr = evt_data->syscall_d.nr;
    bool typed = false;
    int ret;

    scm = get_syscall_meta(nr);
    if (!scm) {
        return -1;
    }

    if (scm->flag & SYSCALL_FLAG_FD) {
        if (append_fd_attrs(attrs_buf, evt_data)) {
            return -1;
        }
        typed = true;
    }

    if (nr == SYSCALL_FUTEX_ID) {
        if (append_futex_attrs(attrs_buf, evt_data)) {
            return -1;
        }
        typed = true;
    }

    if (scm->flag & SYSCALL_FLAG_STACK) {
        // 获取函数调用栈
        ret = append_stack_attrs(attrs_buf, evt_data);
        if (ret) {
            return -1;
        }
    }

    if (!typed) {
        return append_untyped_attrs(attrs_buf, evt_data);
    }

    return 0;
}

static int append_syscall_common_attrs(strbuf_t *attrs_buf, trace_event_data_t *evt_data)
{
    syscall_data_t *syscall_d = &evt_data->syscall_d;
    char evt_name[EVENT_NAME_LEN] = {0};
    __u64 start_time, end_time;
    double duration;
    int ret;

    set_syscall_name(syscall_d->nr, evt_name);

    start_time = get_unix_time_from_uptime(syscall_d->start_time) / NSEC_PER_MSEC;
    end_time = get_unix_time_from_uptime(syscall_d->start_time + syscall_d->duration) / NSEC_PER_MSEC;
    if (start_time > end_time) {
        fprintf(stderr, "ERROR: Event start time large than end time\n");
        return -1;
    }
    duration = (double)syscall_d->duration / NSEC_PER_MSEC;

    ret = snprintf(attrs_buf->buf, attrs_buf->size,
                   "\"event.name\":\"%s\",\"start_time\":%llu,\"end_time\":%llu,\"duration\":%.3lf,\"count\":%d",
                   evt_name, start_time, end_time, duration, syscall_d->count);
    if (ret < 0 || ret >= attrs_buf->size) {
        fprintf(stderr, "ERROR: attributes size not large enough.\n");
        return -1;
    }
    strbuf_update_offset(attrs_buf, ret);

    return 0;
}

static int set_syscall_evt_attrs(strbuf_t *attrs_buf, trace_event_data_t *evt_data)
{
    int ret;

    ret = append_syscall_common_attrs(attrs_buf, evt_data);
    if (ret) {
        return -1;
    }
    ret = append_syscall_attrs_by_nr(attrs_buf, evt_data);
    if (ret) {
        return -1;
    }

    return 0;
}

static int set_oncpu_evt_attrs(strbuf_t *attrs_buf, trace_event_data_t *evt_data)
{
    oncpu_data_t *oncpu_d = &evt_data->oncpu_d;
    __u64 start_time, end_time;
    double duration;
    int ret;

    start_time = get_unix_time_from_uptime(oncpu_d->start_time) / NSEC_PER_MSEC;
    end_time = get_unix_time_from_uptime(oncpu_d->start_time + oncpu_d->duration) / NSEC_PER_MSEC;
    if (start_time > end_time) {
        fprintf(stderr, "ERROR: Event start time large than end time.\n");
        return -1;
    }
    duration = (double)oncpu_d->duration / NSEC_PER_MSEC;

    ret = snprintf(attrs_buf->buf, attrs_buf->size,
                   "\"event.name\":\"%s\",\"start_time\":%llu,\"end_time\":%llu,\"duration\":%.3lf,"
                   "\"count\":%d,\"event.type\":\"%s\"",
                   "oncpu", start_time, end_time, duration, oncpu_d->count, PROFILE_EVT_TYPE_ONCPU);
    if (ret < 0 || ret >= attrs_buf->size) {
        fprintf(stderr, "ERROR: attributes size not large enough.\n");
        return -1;
    }
    strbuf_update_offset(attrs_buf, ret);

    return 0;
}

static int set_typed_evt_attrs(strbuf_t *attrs_buf, trace_event_data_t *evt_data)
{
    switch (evt_data->type) {
        case EVT_TYPE_SYSCALL:
            return set_syscall_evt_attrs(attrs_buf, evt_data);
        case EVT_TYPE_ONCPU:
            return set_oncpu_evt_attrs(attrs_buf, evt_data);
        default:
            fprintf(stderr, "ERROR: unknown event type %d.\n", evt_data->type);
            return -1;
    }
}

static int set_evt_attrs(trace_event_data_t *evt_data, char *evt_attrs, int attrs_size)
{
    int ret;
    strbuf_t sbuf = {
        .buf = evt_attrs,
        .size = attrs_size
    };

    if (sbuf.size < 2) {
        fprintf(stderr, "ERROR: attributes size not large enough.\n");
        return -1;
    }
    strbuf_append_chr(&sbuf, '{');

    ret = set_typed_evt_attrs(&sbuf, evt_data);
    if (ret) {
        return -1;
    }

    if (sbuf.size < 2) {
        fprintf(stderr, "ERROR: attributes size not large enough.\n");
        return -1;
    }
    strbuf_append_chr(&sbuf, '}');
    strbuf_append_chr(&sbuf, '\0');

    return 0;
}