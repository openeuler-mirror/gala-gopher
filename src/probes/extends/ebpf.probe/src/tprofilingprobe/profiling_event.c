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
#include <utlist.h>
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
#include "kern_symb.h"
#include "proc_info.h"
#include "profiling_event.h"

#define LEN_OF_RESOURCE 1024
#define LEN_OF_ATTRS    8192

static int get_sys_boot_time(__u64 *boot_time);
static __u64 get_unix_time_from_uptime(__u64 uptime);

static void set_syscall_name(unsigned long nr, char *name);
static int set_evt_attrs_batch(thrd_info_t *thrd_info, char *evt_attrs, int attrs_size);
static int filter_by_thread_bl(trace_event_data_t *evt_data);
static void cache_thrd_event(thrd_info_t **thrd_info_ptr, trace_event_data_t *evt_data);
static void try_report_thrd_events(thrd_info_t *thrd_info);

int init_sys_boot_time(__u64 *sysBootTime)
{
    return get_sys_boot_time(sysBootTime);
}

static __u64 get_unix_time_from_uptime(__u64 uptime)
{
    return tprofiler.sysBootTime + uptime;
}

void output_profiling_event(trace_event_data_t *evt_data)
{
    thrd_info_t *ti = NULL;

    if (filter_by_thread_bl(evt_data)) {
        return;
    }

    cache_thrd_event(&ti, evt_data);
    if (ti == NULL) {
        return;
    }

    try_report_thrd_events(ti);
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

static syscall_meta_t *get_syscall_meta(unsigned long nr)
{
    syscall_meta_t *scm;

    HASH_FIND(hh, tprofiler.scmTable, &nr, sizeof(unsigned long), scm);
    if (scm == NULL) {
        fprintf(stderr, "WARN: cannot find syscall metadata of syscall number:%lu.\n", nr);
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

static int set_evt_resource(thrd_info_t *thrd_info, char *evt_resource, int resource_size)
{
    int expect_size = 0;
    proc_info_t *pi;
    container_info_t *ci;

    pi = thrd_info->proc_info;
    if (pi == NULL) {
        return -1;
    }
    ci = &pi->container_info;

    expect_size = snprintf(evt_resource, resource_size,
                           "{\"thread.pid\":\"%d\",\"thread.tgid\":\"%d\",\"thread.comm\":\"%s\""
                           ",\"process.comm\":\"%s\",\"container.id\":\"%s\",\"container.name\":\"%s\"}",
                           thrd_info->pid, pi->tgid, thrd_info->comm, pi->comm, ci->id, ci->name);
    if (expect_size >= resource_size) {
        fprintf(stderr, "ERROR: resource size not large enough\n");
        return -1;
    }

    return 0;
}

static void set_cached_event_data(event_elem_t *cached_evt, trace_event_data_t *evt_data)
{
    event_data_t *cached_evt_data = EVT_DATA(cached_evt);

    cached_evt_data->type = evt_data->type;
    if (evt_data->type == EVT_TYPE_SYSCALL) {
        memcpy(&cached_evt_data->syscall_d, &evt_data->syscall_d, sizeof(syscall_data_t));
    } else if (evt_data->type == EVT_TYPE_ONCPU) {
        memcpy(&cached_evt_data->oncpu_d, &evt_data->oncpu_d, sizeof(oncpu_data_t));
    }
}

static void cache_thrd_event(thrd_info_t **thrd_info_ptr, trace_event_data_t *evt_data)
{
    proc_info_t *pi;
    thrd_info_t *ti;
    event_elem_t *cached_evt;

    pi = get_proc_info(&tprofiler.procTable, evt_data->tgid);
    if (pi == NULL) {
        return;
    }

    ti = get_thrd_info(pi, evt_data->pid);
    if (ti == NULL) {
        return;
    }
    if (ti->comm[0] == 0) {
        (void)snprintf(ti->comm, sizeof(ti->comm), "%s", evt_data->comm);
    }

    cached_evt = create_event_elem(sizeof(event_data_t));
    if (cached_evt == NULL) {
        return;
    }
    cached_evt->thrd_info = ti;
    set_cached_event_data(cached_evt, evt_data);

    DL_APPEND(ti->cached_evts, cached_evt);
    ti->evt_num++;
    *thrd_info_ptr = ti;
}

static void report_thrd_events(thrd_info_t *thrd_info)
{
    char resource[LEN_OF_RESOURCE];
    char attrs[LEN_OF_ATTRS];
    struct otel_log ol;
    int ret;

    resource[0] = 0;
    if (set_evt_resource(thrd_info, resource, LEN_OF_RESOURCE)) {
        return;
    }

    while (thrd_info->evt_num > 0) {
        attrs[0] = 0;
        ret = set_evt_attrs_batch(thrd_info, attrs, LEN_OF_ATTRS);
        if (ret) {
            clean_cached_events(thrd_info);
            return;
        }

        ol.timestamp = (u64)time(NULL) * MSEC_PER_SEC;
        ol.sec = EVT_SEC_INFO;
        ol.resource = resource;
        ol.attrs = attrs;
        ol.body = "";

        emit_otel_log(&ol);
    }
}

static inline bool can_report(time_t now, time_t last)
{
    if (now < last + tprofiler.report_period) {
        return false;
    }
    return true;
}

/*
 * 若满足以下条件之一，则触发线程 profiling 事件的上报：
 * 1. 超过上报周期
 * 2. 超过单个线程最大缓存的事件数量
*/
static void try_report_thrd_events(thrd_info_t *thrd_info)
{
    time_t now;

    now = time(NULL);
    if (thrd_info->evt_num <= MAX_CACHE_EVENT_NUM && !can_report(now, thrd_info->last_report_time)) {
        return;
    }
    if (thrd_info->cached_evts == NULL || thrd_info->evt_num == 0) {
        return;
    }

    report_thrd_events(thrd_info);

    thrd_info->last_report_time = now;
}

int get_addr_stack(__u64 *addr_stack, int uid)
{
    if (tprofiler.stackMapFd <= 0) {
        fprintf(stderr, "ERROR: cannot get stack map fd:%d.\n", tprofiler.stackMapFd);
        return -1;
    }

    if (uid <= 0) {
        return -1;
    }
    if (bpf_map_lookup_elem(tprofiler.stackMapFd, &uid, addr_stack) != 0) {
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

static int get_symb_stack(char *symbs_str, int symb_size, event_elem_t *cached_evt)
{
    __u64 ip[PERF_MAX_STACK_DEPTH] = {0};

    proc_info_t *pi;
    struct proc_symbs_s *symbs;
    int uid;

    uid = EVT_DATA_SC(cached_evt)->stack_info.uid;
    if (get_addr_stack(ip, uid)) {
        return -1;
    }

    pi = cached_evt->thrd_info->proc_info;
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

static int append_stack_attrs(strbuf_t *attrs_buf, event_elem_t *cached_evt)
{
    int ret;
    char symbs_str[PERF_MAX_STACK_DEPTH * FUNC_NAME_LEN] = {0};

    ret = get_symb_stack(symbs_str, sizeof(symbs_str), cached_evt);
    if (ret) {
        return -1;
    }

    ret = snprintf(attrs_buf->buf, attrs_buf->size, ",\"func.stack\":\"%s\"", symbs_str);
    if (ret < 0 || ret >= attrs_buf->size) {
        return -ERR_TP_NO_BUFF;
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
        return -ERR_TP_NO_BUFF;
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
                return -ERR_TP_NO_BUFF;
            }
            strbuf_update_offset(attrs_buf, ret);
            break;
        default:
            return -1;
    }
    return 0;
}

static int append_fd_attrs(strbuf_t *attrs_buf, event_elem_t *cached_evt)
{
    int fd = EVT_DATA_SC(cached_evt)->ext_info.fd_info.fd;
    proc_info_t *pi;
    fd_info_t *fi;

    pi = cached_evt->thrd_info->proc_info;
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

static int append_futex_attrs(strbuf_t *attrs_buf, event_elem_t *cached_evt)
{
    int ret;
    char futexOp[8] = {0};
    int op;

    op = EVT_DATA_SC(cached_evt)->ext_info.futex_info.op;
    if (is_futex_wait_op(op)) {
        strcpy(futexOp, "wait");
    } else if (is_futex_wake_op(op)) {
        strcpy(futexOp, "wake");
    }

    ret = snprintf(attrs_buf->buf, attrs_buf->size,
                   ",\"event.type\":\"%s\",\"futex.op\":\"%s\"",
                   PROFILE_EVT_TYPE_LOCK, futexOp);
    if (ret < 0 || ret >= attrs_buf->size) {
        return -ERR_TP_NO_BUFF;
    }
    strbuf_update_offset(attrs_buf, ret);

    return 0;
}

static int append_untyped_attrs(strbuf_t *attrs_buf, syscall_meta_t *scm)
{
    char *evt_type;
    int ret;

    evt_type = scm->default_type[0] != '\0' ? scm->default_type : PROFILE_EVT_TYPE_OTHER;
    ret = snprintf(attrs_buf->buf, attrs_buf->size, ",\"event.type\":\"%s\"", evt_type);
    if (ret < 0 || ret >= attrs_buf->size) {
        return -ERR_TP_NO_BUFF;
    }
    strbuf_update_offset(attrs_buf, ret);

    return 0;
}
static int append_syscall_attrs_by_nr(strbuf_t *attrs_buf, event_elem_t *cached_evt)
{
    syscall_meta_t *scm;
    unsigned long nr = EVT_DATA_SC(cached_evt)->nr;
    bool typed = false;
    int ret;

    scm = get_syscall_meta(nr);
    if (!scm) {
        return -1;
    }

    if (scm->flag & SYSCALL_FLAG_FD) {
        ret = append_fd_attrs(attrs_buf, cached_evt);
        if (ret) {
            return ret;
        }
        typed = true;
    }

    if (nr == SYSCALL_FUTEX_ID) {
        ret = append_futex_attrs(attrs_buf, cached_evt);
        if (ret) {
            return ret;
        }
        typed = true;
    }

    if (scm->flag & SYSCALL_FLAG_STACK) {
        // 获取函数调用栈
        ret = append_stack_attrs(attrs_buf, cached_evt);
        if (ret) {
            return ret;
        }
    }

    if (!typed) {
        return append_untyped_attrs(attrs_buf, scm);
    }

    return 0;
}

static int append_syscall_common_attrs(strbuf_t *attrs_buf, event_elem_t *cached_evt)
{
    syscall_data_t *syscall_d = EVT_DATA_SC(cached_evt);
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
        return -ERR_TP_NO_BUFF;
    }
    strbuf_update_offset(attrs_buf, ret);

    return 0;
}

static int set_syscall_evt_attrs(strbuf_t *attrs_buf, event_elem_t *cached_evt)
{
    int ret;

    ret = append_syscall_common_attrs(attrs_buf, cached_evt);
    if (ret) {
        return ret;
    }
    ret = append_syscall_attrs_by_nr(attrs_buf, cached_evt);
    if (ret) {
        return ret;
    }

    return 0;
}

static int set_oncpu_evt_attrs(strbuf_t *attrs_buf, event_elem_t *cached_evt)
{
    oncpu_data_t *oncpu_d = EVT_DATA_CPU(cached_evt);
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
        return -ERR_TP_NO_BUFF;
    }
    strbuf_update_offset(attrs_buf, ret);

    return 0;
}

static int set_typed_evt_attrs(strbuf_t *attrs_buf, event_elem_t *cached_evt)
{
    trace_event_type_t type = EVT_DATA_TYPE(cached_evt);

    switch (type) {
        case EVT_TYPE_SYSCALL:
            return set_syscall_evt_attrs(attrs_buf, cached_evt);
        case EVT_TYPE_ONCPU:
            return set_oncpu_evt_attrs(attrs_buf, cached_evt);
        default:
            fprintf(stderr, "ERROR: unknown event type %d.\n", type);
            return -1;
    }
}

// format like: `{"key1":"value1","key2":value2}`
static int set_evt_attrs_single(strbuf_t *attrs_buf, event_elem_t *cached_evt)
{
    int ret;

    ret = strbuf_append_chr_with_check(attrs_buf, '{');
    if (ret) {
        return -ERR_TP_NO_BUFF;
    }

    ret = set_typed_evt_attrs(attrs_buf, cached_evt);
    if (ret) {
        return ret;
    }

    ret = strbuf_append_chr_with_check(attrs_buf, '}');
    if (ret) {
        return -ERR_TP_NO_BUFF;
    }

    return 0;
}

/*
 * 批量添加缓存的线程 profiling 事件到属性列表中。
 * 考虑到一次上报的事件的内存容量的限制，当添加的 profiling 事件达到内存容量的上限时，
 * 允许将已添加的 profiling 事件先上报，剩余的 profiling 事件添加到下一次上报的事件中。
 *
 * 针对添加单个线程 profiling 事件失败的情况，处理如下：
 * 1. 若返回错误码 -ERR_TP_NO_BUFF ，表示 buff 容量不足，恢复 buff 到上一次的状态，并不再添加新的 profiling 事件。
 * 2. 若返回其它错误，表示该 profiling 事件添加失败，忽略它并继续添加新的 profiling 事件。
 *
 * 返回值：当成功添加的线程 profiling 事件数量大于 0 时才返回成功，否则返回失败。
*/
static int append_evt_attrs_batch(strbuf_t *attrs_buf, thrd_info_t *thrd_info)
{
    strbuf_t buf_back;
    event_elem_t *cached_evt = NULL;
    int consumed_num = 0;
    int succeed_num = 0;
    bool is_first = true;
    int ret = 0;

    DL_FOREACH(thrd_info->cached_evts, cached_evt) {
        memcpy(&buf_back, attrs_buf, sizeof(strbuf_t));

        if (!is_first) {
            ret = strbuf_append_chr_with_check(attrs_buf, ',');
            if (ret) {
                ret = -ERR_TP_NO_BUFF;
                break;
            }
        }
        is_first = false;

        ret = set_evt_attrs_single(attrs_buf, cached_evt);
        if (ret) {
            memcpy(attrs_buf, &buf_back, sizeof(strbuf_t));
            if (ret == -ERR_TP_NO_BUFF) {
                break;
            }
        } else {
            succeed_num++;
        }
        consumed_num++;
    }

    if (succeed_num == 0) {
        if (ret == -ERR_TP_NO_BUFF) {
            return ret;
        }
        return -1;
    }
    delete_first_k_events(thrd_info, consumed_num);

    return 0;
}

// format like: `{"values":[{},{}]}`
static int set_evt_attrs_batch(thrd_info_t *thrd_info, char *evt_attrs, int attrs_size)
{
    strbuf_t sbuf = {
        .buf = evt_attrs,
        .size = attrs_size
    };
    const char *prefix = "{\"values\":[";
    const char *suffix = "]}";
    const int suffix_size = strlen(suffix) + 1;
    int ret;

    ret = strbuf_append_str_with_check(&sbuf, prefix, strlen(prefix));
    if (ret) {
        fprintf(stderr, "ERROR: attributes size not large enough.\n");
        return -1;
    }
    // reserve space for the suffix
    if (sbuf.size < suffix_size) {
        fprintf(stderr, "ERROR: attributes size not large enough.\n");
        return -1;
    }
    sbuf.size -= suffix_size;

    ret = append_evt_attrs_batch(&sbuf, thrd_info);
    if (ret) {
        if (ret == -ERR_TP_NO_BUFF) {
            fprintf(stderr, "ERROR: attributes size not large enough.\n");
        }
        return -1;
    }

    sbuf.size += suffix_size;
    strbuf_append_str(&sbuf, suffix, suffix_size - 1);
    strbuf_append_chr(&sbuf, '\0');

    return 0;
}

static int filter_by_thread_bl(trace_event_data_t *evt_data)
{
    ThrdBlacklist *thrdBl = &tprofiler.thrdBl;
    BlacklistItem *blItem;
    char procComm[TASK_COMM_LEN] = {0};
    int i, j;

    if (tprofiler.threadBlMapFd <= 0) {
        return 0;
    }

    if (set_proc_comm(evt_data->tgid, procComm, TASK_COMM_LEN)) {
        return 0;
    }

    for (i = 0; i < thrdBl->blNum; i++) {
        blItem = &thrdBl->blItems[i];
        if (strcmp(procComm, blItem->procComm)) {
            continue;
        }

        for (j = 0; j < blItem->thrdNum; j++) {
            if (strcmp(evt_data->comm, blItem->thrdComms[j]) == 0) {
                (void)bpf_map_update_elem(tprofiler.threadBlMapFd, &evt_data->pid, &evt_data->tgid, BPF_ANY);
                return -1;
            }
        }
    }

    return 0;
}