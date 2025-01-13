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
#include <stdlib.h>
#include <time.h>
#include <utlist.h>
#include <dirent.h>
#include <sys/stat.h>
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
#include "args.h"
#include "kern_symb.h"
#include "proc_info.h"
#include "trace_viewer_fmt.h"
#include "mem_usage.h"
#include "profiling_event.h"
#include "topk_heap.h"
#include "container.h"

#define LEN_OF_RESOURCE 1024
#define LEN_OF_ATTRS    (8192 - LEN_OF_RESOURCE)

#define FUNC_NAME_LEN 64
#define MAX_FUNC_NAME_LEN (2 * FUNC_NAME_LEN)

#define MAX_STACK_STR_LEN ((PERF_MAX_STACK_DEPTH + MAX_PYTHON_STACK_DEPTH_MAX) * MAX_FUNC_NAME_LEN)

typedef int (*func_set_evt_fmt)(struct trace_event_fmt_s *, struct local_store_s *, event_elem_t *);

static int get_sys_boot_time(__u64 *boot_time);
static __u64 get_unix_time_from_uptime(__u64 uptime);

void output_mem_glibc_event(trace_event_data_t *evt_data);
static void set_syscall_name(unsigned long nr, char *name);
static int set_evt_attrs_batch(thrd_info_t *thrd_info, char *evt_attrs, int attrs_size);
static int filter_by_thread_bl(trace_event_data_t *evt_data);
static void cache_thrd_event(thrd_info_t **thrd_info_ptr, trace_event_data_t *evt_data);
static void try_report_thrd_events(thrd_info_t *thrd_info);
void report_thrd_events_local(thrd_info_t *thrd_info);
static int get_symb_stack_user(char *symbs_str, int symb_size, int uid, proc_info_t *proc_info);
static int get_symb_stack_py(char *symbs_str, int symb_size, u64 pyid);
static int get_symb_stack(char *symbs_str, int symb_size, stack_trace_t *stack, proc_info_t *proc_info);

static char *g_pthrd_name_tbl[PTHREAD_MAX_ID] = {
    NULL,
    PTHREAD_MUTEX_LOCK_NAME,
    PTHREAD_MUTEX_TIMEDLOCK_NAME,
    PTHREAD_MUTEX_TRYLOCK_NAME,
    PTHREAD_RWLOCK_RDLOCK_NAME,
    PTHREAD_RWLOCK_WRLOCK_NAME,
    PTHREAD_RWLOCK_TIMEDRDLOCK_NAME,
    PTHREAD_RWLOCK_TIMEDWRLOCK_NAME,
    PTHREAD_RWLOCK_TRYRDLOCK_NAME,
    PTHREAD_RWLOCK_TRYWRLOCK_NAME,
    PTHREAD_SPIN_LOCK_NAME,
    PTHREAD_SPIN_TRYLOCK_NAME,
    PTHREAD_TIMEDJOIN_NP_NAME,
    PTHREAD_TRYJOIN_NP_NAME,
    PTHREAD_YIELD_NAME,
    SEM_TIMEDWAIT_NAME,
    SEM_TRYWAIT_NAME,
    SEM_WAIT_NAME
};

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

    if (evt_data->type == EVT_TYPE_MEM_GLIBC) {
        output_mem_glibc_event(evt_data);
        return;
    }

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
        TP_WARN("Cannot find syscall metadata of syscall number:%lu.\n", nr);
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
                           ",\"process.comm\":\"%s\",\"process.name\":\"%s\""
                           ",\"container.id\":\"%s\",\"container.name\":\"%s\"}",
                           thrd_info->pid, pi->tgid, thrd_info->comm,
                           pi->comm, pi->proc_name, ci->id, ci->name);
    if (expect_size >= resource_size) {
        TP_ERROR("Resource size not large enough\n");
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
    } else if (evt_data->type == EVT_TYPE_OFFCPU) {
        memcpy(&cached_evt_data->offcpu_d, &evt_data->offcpu_d, sizeof(offcpu_data_t));
    } else if (evt_data->type == EVT_TYPE_PYGC) {
        memcpy(&cached_evt_data->pygc_d, &evt_data->pygc_d, sizeof(pygc_data_t));
    } else if (evt_data->type == EVT_TYPE_PTHREAD) {
        memcpy(&cached_evt_data->pthrd_d, &evt_data->pthrd_d, sizeof(pthrd_data_t));
    } else if (evt_data->type == EVT_TYPE_ONCPU_PERF) {
        memcpy(&cached_evt_data->sample_d, &evt_data->sample_d, sizeof(oncpu_sample_data_t));
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

#define LOCAL_REPORT_PERIOD 5

static inline bool can_report(time_t now, time_t last)
{
    int report_period = tprofiler.report_period;

    if (tprofiler.output_chan == PROFILING_CHAN_LOCAL) {
        report_period = LOCAL_REPORT_PERIOD;
    }
    if (now < last + report_period) {
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

    if (tprofiler.output_chan == PROFILING_CHAN_LOCAL) {
        report_thrd_events_local(thrd_info);
    } else if (tprofiler.output_chan == PROFILING_CHAN_KAFKA) {
        report_thrd_events(thrd_info);
    } else {
        return;
    }

    thrd_info->last_report_time = now;
}

int get_addr_stack(__u64 *addr_stack, int uid)
{
    int stackMapFd = get_current_stack_map();

    if (stackMapFd <= 0) {
        TP_ERROR("Can not get stack map fd: %d.\n", stackMapFd);
        return -1;
    }

    if (uid <= 0) {
        return -1;
    }
    if (bpf_map_lookup_elem(stackMapFd, &uid, addr_stack) != 0) {
        return -1;
    }

    return 0;
}

static void get_user_symb_name(char symb_name[], int size, struct addr_symb_s *symb)
{
    symb_name[0] = '\0';
    if (symb != NULL) {
        if (symb->sym != NULL) {
            // it is allowed that symbol name may be truncated
            (void)snprintf(symb_name, size, "%s", symb->sym);
            return;
        }
    }
    // default
    (void)snprintf(symb_name, size, DFT_STACK_SYMB_NAME);
    return;
}

static void get_user_symb_ext(char symb_ext[], int size, struct addr_symb_s *symb)
{
    char *mod_basename = NULL;

    symb_ext[0] = '\0';
    if (symb->mod != NULL && symb->relat_addr > 0) {
        mod_basename = strrchr(symb->mod, '/');
        if (mod_basename == NULL) {
            mod_basename = symb->mod;
        } else {
            mod_basename++;
        }
        (void)snprintf(symb_ext, size, "(%s:0x%llx)", mod_basename, symb->relat_addr);
    }
    return;
}

static int stack_transfer_addrs2symbs(__u64 *addrs, int addr_num,
                                      char *symbs_str, int symb_size, proc_info_t *proc_info)
{
    struct proc_symbs_s *symbs;
    struct addr_symb_s symb = {0};
    char symb_name[MAX_FUNC_NAME_LEN];
    char symb_ext[MAX_FUNC_NAME_LEN];
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
        symb_name[0] = 0;
        symb_ext[0] = 0;
        if (ret) {
            get_user_symb_name(symb_name, sizeof(symb_name), NULL);
        } else {
            get_user_symb_name(symb_name, sizeof(symb_name), &symb);
            get_user_symb_ext(symb_ext, sizeof(symb_ext), &symb);
        }

        ret = snprintf(symbs_buf.buf, symbs_buf.size, "%s[u]%s;", symb_name, symb_ext);
        if (ret < 0 || ret >= symbs_buf.size) {
            TP_WARN("Stack buffer not large enough.\n");
            return -1;
        }
        strbuf_update_offset(&symbs_buf, ret);
    }

    return 0;
}

static struct stats_stack_elem *get_stack_elem(event_elem_t *evt)
{
    trace_event_type_t typ = EVT_DATA_TYPE(evt);
    struct stats_stack_elem *elem = NULL;

    if (typ == EVT_TYPE_SYSCALL) {
        elem = &(EVT_DATA_SC(evt)->stats.stats_stack);
    } else if (typ == EVT_TYPE_OFFCPU) {
        elem = &(EVT_DATA_OFFCPU(evt)->stats_stack);
    } else if (typ == EVT_TYPE_PYGC) {
        elem = &(EVT_DATA_PYGC(evt)->stats_stack);
    } else if (typ == EVT_TYPE_PTHREAD) {
        elem = &(EVT_DATA_PTHRD(evt)->stats_stack);
    } else if (typ == EVT_TYPE_ONCPU_PERF) {
        elem = &(EVT_DATA_CPU_SAMPLE(evt)->stats_stack);
    }

    return elem;
} 

static int get_symb_stack_user(char *symbs_str, int symb_size, int uid, proc_info_t *proc_info)
{
    __u64 ip[PERF_MAX_STACK_DEPTH] = {0};
    struct proc_symbs_s *symbs;
    int ret;

    if (get_addr_stack(ip, uid)) {
        return -1;
    }

    // cache process symbol table if not
    symbs = get_symb_info(proc_info);
    if (symbs == NULL) {
        return -1;
    }

    ret = stack_transfer_addrs2symbs(ip, PERF_MAX_STACK_DEPTH, symbs_str, symb_size, proc_info);
    if (ret) {
        return -1;
    }

    return 0;
}

static int get_symb_stack_py(char *symbs_str, int symb_size, u64 pyid)
{
    int pyStackMapFd = get_current_py_stack_map();
    struct py_stack py_stack;
    struct py_symbol sym;
    int i;
    int ret;

    strbuf_t symbs_buf = {
        .buf = symbs_str,
        .size = symb_size
    };

    if (pyid == 0){
        return 0;
    }
    if (bpf_map_lookup_elem(pyStackMapFd, &pyid, &py_stack) != 0) {
        return -1;
    }
    bpf_map_delete_elem(pyStackMapFd, &pyid);

    for (i = py_stack.stack_len - 1; i >= 0; i--) {
        if (bpf_map_lookup_elem(tprofiler.pySymbMapFd, &py_stack.stack[i & (MAX_PYTHON_STACK_DEPTH_MAX - 1)], &sym) == 0) {
            if (sym.class_name[0] != '\0') {
                ret = snprintf(symbs_buf.buf, symbs_buf.size, "%s#%s[p];", sym.class_name, sym.func_name);
            } else {
                ret = snprintf(symbs_buf.buf, symbs_buf.size, "%s[p];", sym.func_name);
            }
        } else {
            char *symb_name;
            symb_name = DFT_STACK_SYMB_NAME;
            ret = snprintf(symbs_buf.buf, symbs_buf.size , "%s[p];", symb_name);
        }

        if (ret < 0 || ret >= symbs_buf.size) {
            // it is allowed that stack may be truncated
            TP_WARN("Stack buffer not large enough.\n");
            return -ERR_TP_NO_BUFF;
        }

        strbuf_update_offset(&symbs_buf, ret);
    }

    return 0;

}

static int get_symb_stack(char *symbs_str, int symb_size, stack_trace_t *stack, proc_info_t *proc_info)
{
    int ret;

    symbs_str[0] = 0;
    ret = get_symb_stack_py(symbs_str, symb_size, stack->pyid);
    if (ret){
        TP_DEBUG("Failed to get python symbol stack\n");
        return -1;
    }

    int len = strlen(symbs_str);
    ret = get_symb_stack_user(symbs_str + len, symb_size - len, stack->uid, proc_info);
    if (ret) {
        TP_DEBUG("Failed to get user symbol stack\n");
        return -1;
    }

    return 0;
}

static int append_stack_attrs(strbuf_t *attrs_buf, event_elem_t *cached_evt)
{
    int ret;
    char symbs_str[PERF_MAX_STACK_DEPTH * FUNC_NAME_LEN];
    struct stats_stack_elem *stack_elem;

    stack_elem = get_stack_elem(cached_evt);
    if (!stack_elem) {
        return -1;
    }

    proc_info_t *pi = cached_evt->thrd_info->proc_info;
    if (pi == NULL) {
        return -1;
    }

    ret = get_symb_stack(symbs_str, sizeof(symbs_str), &stack_elem->stack, pi);
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

// example: {}
static int append_empty_attr(strbuf_t *attrs_buf, bool first_flag)
{
    int ret;
    char *comma = first_flag ? "" : ",";

    ret = snprintf(attrs_buf->buf, attrs_buf->size, "%s{}", comma);
    if (ret < 0 || ret >= attrs_buf->size) {
        return -ERR_TP_NO_BUFF;
    }
    strbuf_update_offset(attrs_buf, ret);

    return 0;
}

// example: {"file.path":"/path/to/xxx"}
static int append_regular_file_attr(strbuf_t *attrs_buf, fd_info_t *fd_info, struct stats_fd_elem *fd_elem, bool first_flag)
{
    int ret;
    char *comma = first_flag ? "" : ",";

    ret = snprintf(attrs_buf->buf, attrs_buf->size, "%s{\"file.path\":\"%s\"}",
                   comma, fd_info->reg_info.name);
    if (ret < 0 || ret >= attrs_buf->size) {
        return -ERR_TP_NO_BUFF;
    }
    strbuf_update_offset(attrs_buf, ret);

    return 0;
}

// example: {"sock.conn": ""}
static int append_sock_attr(strbuf_t *attrs_buf, fd_info_t *fd_info, struct stats_fd_elem *fd_elem, bool first_flag)
{
    int ret;
    sock_info_t *si = &fd_info->sock_info;
    char *comma = first_flag ? "" : ",";

    switch (si->type) {
        case SOCK_TYPE_IPV4:
        case SOCK_TYPE_IPV6:
            ret = snprintf(attrs_buf->buf, attrs_buf->size, "%s{\"sock.conn\":\"%s\"}",
                           comma, si->ip_info.conn);
            if (ret < 0 || ret >= attrs_buf->size) {
                return -ERR_TP_NO_BUFF;
            }
            strbuf_update_offset(attrs_buf, ret);
            break;
        default:
            return append_empty_attr(attrs_buf, first_flag);
    }
    return 0;
}

// example: {"file.inode": 1}
static int append_inode_attr(strbuf_t *attrs_buf, struct stats_fd_elem *fd_elem, bool first_flag)
{
    int ret;
    char *comma = first_flag ? "" : ",";

    ret = snprintf(attrs_buf->buf, attrs_buf->size, "%s{\"file.inode\":%lu}", comma, fd_elem->ino);
    if (ret < 0 || ret >= attrs_buf->size) {
        return -ERR_TP_NO_BUFF;
    }
    strbuf_update_offset(attrs_buf, ret);

    return 0;
}

/*
 * 如果 inode 号未初始化，则只通过 fd 来获取文件或网络的属性信息；否则，以 inode 号为准
 */
static int append_fd_attr(strbuf_t *attrs_buf, proc_info_t *proc_info, struct stats_fd_elem *fd_elem,
    bool first_flag)
{
    fd_info_t *fi;

    fi = get_fd_info(proc_info, fd_elem->fd);
    if (fi == NULL) {
        if (fd_elem->ino != 0) {
            return append_inode_attr(attrs_buf, fd_elem, first_flag);
        } else {
            return append_empty_attr(attrs_buf, first_flag);
        }
    }
    if (fd_elem->ino != 0 && fi->ino != fd_elem->ino) {
        delete_fd_info(proc_info, fi);  // 缓存的 fd 信息失效
        return append_inode_attr(attrs_buf, fd_elem, first_flag);
    }

    switch (fi->type) {
        case FD_TYPE_REG:
            return append_regular_file_attr(attrs_buf, fi, fd_elem, first_flag);
        case FD_TYPE_SOCK:
            return append_sock_attr(attrs_buf, fi, fd_elem, first_flag);
        default:
            if (fd_elem->ino != 0) {
                return append_inode_attr(attrs_buf, fd_elem, first_flag);
            } else {
                return append_empty_attr(attrs_buf, first_flag);
            }
    }
}

static const char *get_fd_evt_type(event_elem_t *cached_evt)
{
    const char *dft_type = PROFILE_EVT_TYPE_IO;
    struct stats_fd_elem *fd_elem;
    fd_info_t *fi;

    fd_elem = &EVT_DATA_SC(cached_evt)->stats.stats_fd;
    if (fd_elem->fd <= 0) {
        return dft_type;
    }

    if (fd_elem->ino > 0) { // 优先使用 imode 来判断 fd 类型
        switch (fd_elem->imode & S_IFMT) {
            case S_IFDIR:
            case S_IFREG:
                return PROFILE_EVT_TYPE_FILE;
            case S_IFSOCK:
                return PROFILE_EVT_TYPE_NET;
            default:
                return dft_type;
        }
    }
    if (cached_evt->thrd_info != NULL && cached_evt->thrd_info->proc_info != NULL) {
        fi = HASH_find_fd_info(cached_evt->thrd_info->proc_info->fd_table, fd_elem->fd);
        if (fi != NULL) {
            switch (fi->type) {
                case FD_TYPE_REG:
                    return PROFILE_EVT_TYPE_FILE;
                case FD_TYPE_SOCK:
                    return PROFILE_EVT_TYPE_NET;
                default:
                    return dft_type;
            }
        }
    }

    return dft_type;
}

/*
 * 实际上最多只会保存一条 fd 数据
 * example: ,"io.info":{...}, "event.type": ""
 */
static int append_fd_attrs(strbuf_t *attrs_buf, event_elem_t *cached_evt, bool *typed)
{
    struct stats_fd_elem *fd_elem;
    proc_info_t *pi;
    const char *prefix = ",\"io.info\":";
    const char *evt_type;
    int ret;

    fd_elem = &EVT_DATA_SC(cached_evt)->stats.stats_fd;
    if (fd_elem->fd <= 0) {
        return 0;
    }

    pi = cached_evt->thrd_info->proc_info;
    if (pi == NULL) {
        return -1;
    }

    ret = strbuf_append_str_with_check(attrs_buf, prefix, strlen(prefix));
    if (ret) {
        return -ERR_TP_NO_BUFF;
    }
    ret = append_fd_attr(attrs_buf, pi, fd_elem, true);
    if (ret) {
        return ret;
    }

    evt_type = get_fd_evt_type(cached_evt);
    ret = snprintf(attrs_buf->buf, attrs_buf->size, ",\"event.type\":\"%s\"", evt_type);
    if (ret < 0 || ret >= attrs_buf->size) {
        return -ERR_TP_NO_BUFF;
    }
    strbuf_update_offset(attrs_buf, ret);
    *typed = true;

    return 0;
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

static const char *get_futex_op_name(int op)
{
    const char *op_name = "";

    if (is_futex_wait_op(op)) {
        op_name = "wait";
    } else if (is_futex_wake_op(op)) {
        op_name = "wake";
    }

    return op_name;
}

static int append_futex_attr(strbuf_t *attrs_buf, struct stats_futex_elem *futex_elem, bool first_flag)
{
    int ret;
    const char *futexOp = get_futex_op_name(futex_elem->op);
    char *comma = first_flag ? "" : ",";

    ret = snprintf(attrs_buf->buf, attrs_buf->size, "%s{\"futex.op\":\"%s\"}",
                   comma, futexOp);
    if (ret < 0 || ret >= attrs_buf->size) {
        return -ERR_TP_NO_BUFF;
    }
    strbuf_update_offset(attrs_buf, ret);

    return 0;
}

// example: ,"futex.info":{...}, "event.type": ""
static int append_futex_attrs(strbuf_t *attrs_buf, event_elem_t *cached_evt, bool *typed)
{
    struct stats_futex_elem *futex_elem;
    const char *prefix = ",\"futex.info\":";
    int ret;

    futex_elem = &EVT_DATA_SC(cached_evt)->stats.stats_futex;
    if (futex_elem->op < 0) {
        return 0;
    }

    ret = strbuf_append_str_with_check(attrs_buf, prefix, strlen(prefix));
    if (ret) {
        return -ERR_TP_NO_BUFF;
    }

    ret = append_futex_attr(attrs_buf, futex_elem, true);
    if (ret) {
        return ret;
    }

    ret = snprintf(attrs_buf->buf, attrs_buf->size, ",\"event.type\": \"%s\"", PROFILE_EVT_TYPE_LOCK);
    if (ret < 0 || ret >= attrs_buf->size) {
        return -ERR_TP_NO_BUFF;
    }
    strbuf_update_offset(attrs_buf, ret);
    *typed = true;

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

// output example: ,"io.info":{...}, "event.type": "read"
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
        ret = append_fd_attrs(attrs_buf, cached_evt, &typed);
        if (ret) {
            return ret;
        }
    }

    if (nr == SYSCALL_FUTEX_ID) {
        ret = append_futex_attrs(attrs_buf, cached_evt, &typed);
        if (ret) {
            return ret;
        }
    }

    if (tprofiler.output_chan == PROFILING_CHAN_KAFKA) {
        if (scm->flag & SYSCALL_FLAG_STACK) {
            // 获取函数调用栈
            ret = append_stack_attrs(attrs_buf, cached_evt);
            if (ret) {
                return ret;
            }
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
        TP_ERROR("Event start time large than end time\n");
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
    oncpu_data_t *oncpu_d = EVT_DATA_ONCPU(cached_evt);
    __u64 start_time, end_time;
    double duration;
    int ret;

    start_time = get_unix_time_from_uptime(oncpu_d->start_time) / NSEC_PER_MSEC;
    end_time = get_unix_time_from_uptime(oncpu_d->start_time + oncpu_d->duration) / NSEC_PER_MSEC;
    if (start_time > end_time) {
        TP_ERROR("Event start time large than end time.\n");
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

static int set_offcpu_evt_attrs(strbuf_t *attrs_buf, event_elem_t *cached_evt)
{
    offcpu_data_t *offcpu_d = EVT_DATA_OFFCPU(cached_evt);
    __u64 start_time, end_time;
    double duration;
    int ret;

    start_time = get_unix_time_from_uptime(offcpu_d->start_time) / NSEC_PER_MSEC;
    end_time = get_unix_time_from_uptime(offcpu_d->start_time + offcpu_d->duration) / NSEC_PER_MSEC;
    if (start_time > end_time) {
        TP_ERROR("Event start time large than end time.\n");
        return -1;
    }
    duration = (double)offcpu_d->duration / NSEC_PER_MSEC;

    ret = snprintf(attrs_buf->buf, attrs_buf->size,
                   "\"event.name\":\"%s\",\"start_time\":%llu,\"end_time\":%llu,\"duration\":%.3lf,"
                   "\"count\":%d,\"event.type\":\"%s\"",
                   "offcpu", start_time, end_time, duration, offcpu_d->count, PROFILE_EVT_TYPE_OFFCPU);
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
        case EVT_TYPE_OFFCPU:
            return set_offcpu_evt_attrs(attrs_buf, cached_evt);
        default:
            TP_ERROR("Unknown event type %d.\n", type);
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

        ret = set_evt_attrs_single(attrs_buf, cached_evt);
        if (ret) {
            memcpy(attrs_buf, &buf_back, sizeof(strbuf_t));
            if (ret == -ERR_TP_NO_BUFF) {
                break;
            }
        } else {
            succeed_num++;
            is_first = false;
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
    const size_t suffix_size = strlen(suffix) + 1;
    int ret;

    ret = strbuf_append_str_with_check(&sbuf, prefix, strlen(prefix));
    if (ret) {
        TP_ERROR("Attributes size not large enough.\n");
        return -1;
    }
    // reserve space for the suffix
    if (sbuf.size < suffix_size) {
        TP_ERROR("Attributes size not large enough.\n");
        return -1;
    }
    sbuf.size -= suffix_size;

    ret = append_evt_attrs_batch(&sbuf, thrd_info);
    if (ret) {
        if (ret == -ERR_TP_NO_BUFF) {
            TP_ERROR("Attributes size not large enough.\n");
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

int local_write_process_name_meta_event(struct local_store_s *local_storage, u32 pid, const char *comm)
{
    struct trace_event_fmt_s evt_fmt = {0};
    int ret;

    evt_fmt.pid = pid;
    evt_fmt.phase = EVENT_PHASE_META;
    (void)snprintf(evt_fmt.name, sizeof(evt_fmt.name), "%s", EVENT_META_PROC_NAME);
    (void)snprintf(evt_fmt.args, sizeof(evt_fmt.args), "\"%s\": \"%s\"", EVENT_META_ARG_PROC_NAME, comm);

    ret = trace_event_fmt_to_json_str(&evt_fmt, local_storage->buf, sizeof(local_storage->buf));
    if (ret) {
        return ret;
    }

    return trace_file_fill_event_from_buffer(local_storage);
}

void set_oncpu_event_args(struct trace_event_fmt_s *evt_fmt, event_elem_t *evt)
{
    oncpu_data_t *oncpu_d = EVT_DATA_ONCPU(evt);
    thrd_info_t *thrd_info = evt->thrd_info;
    int ret;

    ret = snprintf(evt_fmt->args, sizeof(evt_fmt->args),
        "\"count\": %d, \"event.type\": \"%s\", \"thread.name\": \"%s\"",
        oncpu_d->count, PROFILE_EVT_TYPE_ONCPU, thrd_info->comm);
    if (ret < 0 || ret >= sizeof(evt_fmt->args)) {
        TP_WARN("Failed to set args of oncpu event: no enough buffer\n");
        evt_fmt->args[0] = 0;
    }
}

int local_write_oncpu_event(struct local_store_s *local_storage, event_elem_t *evt)
{
    struct trace_event_fmt_s evt_fmt = {0};
    thrd_info_t *thrd_info = evt->thrd_info;
    proc_info_t *proc_info = thrd_info->proc_info;
    oncpu_data_t *oncpu_d = EVT_DATA_ONCPU(evt);
    __u64 start_time, end_time;
    int ret;

    start_time = get_unix_time_from_uptime(oncpu_d->start_time);
    end_time = get_unix_time_from_uptime(oncpu_d->start_time + oncpu_d->duration);

    evt_fmt.pid = proc_info->tgid;
    evt_fmt.tid = thrd_info->pid;
    evt_fmt.id = gen_async_event_id();
    // TODO: oncpu事件包含公共信息，可作为一个模版进行优化
    (void)snprintf(evt_fmt.category, sizeof(evt_fmt.category), EVENT_CATEGORY_ONCPU);
    (void)snprintf(evt_fmt.name, sizeof(evt_fmt.name), PROFILE_EVT_TYPE_ONCPU);
    (void)snprintf(evt_fmt.cname, sizeof(evt_fmt.cname), EVENT_CNAME_OF_ONCPU);

    // set async begin event
    evt_fmt.phase = EVENT_PHASE_ASYNC_START;
    evt_fmt.ts = start_time;
    ret = trace_event_fmt_to_json_str(&evt_fmt, local_storage->buf, sizeof(local_storage->buf));
    if (ret) {
        return ret;
    }

    ret = trace_file_fill_event_from_buffer(local_storage);
    if (ret < 0) {
        return -1;
    }

    // set async end event
    set_oncpu_event_args(&evt_fmt, evt);
    evt_fmt.phase = EVENT_PHASE_ASYNC_END;
    evt_fmt.ts = end_time;
    ret = trace_event_fmt_to_json_str(&evt_fmt, local_storage->buf, sizeof(local_storage->buf));
    if (ret) {
        return ret;
    }

    return trace_file_fill_event_from_buffer(local_storage);
}

int set_stack_sf(struct trace_event_fmt_s *evt_fmt, event_elem_t *evt, struct local_store_s *local_storage)
{
    char symbs_str[MAX_STACK_STR_LEN];
    struct stats_stack_elem *stack_elem;
    int ret;

    stack_elem = get_stack_elem(evt);
    if (!stack_elem) {
        return -1;
    }

    proc_info_t *pi = evt->thrd_info->proc_info;
    if (pi == NULL) {
        return -1;
    }

    ret = get_symb_stack(symbs_str, sizeof(symbs_str), &stack_elem->stack, pi);
    if (ret){
        return -1;
    }

    struct stack_node_s *leaf = stack_tree_add_stack(local_storage->stack_root, symbs_str, true);
    evt_fmt->sf = leaf == NULL ? 0 : leaf->id;
    return 0;
}

void set_offcpu_event_args(struct trace_event_fmt_s *evt_fmt, event_elem_t *evt)
{
    offcpu_data_t *offcpu_d = EVT_DATA_OFFCPU(evt);
    thrd_info_t *thrd_info = evt->thrd_info;
    int ret;

    ret = snprintf(evt_fmt->args, sizeof(evt_fmt->args),
        "\"count\": %d, \"event.type\": \"%s\", \"thread.name\": \"%s\"",
        offcpu_d->count, PROFILE_EVT_TYPE_OFFCPU, thrd_info->comm);
    if (ret < 0 || ret >= sizeof(evt_fmt->args)) {
        TP_WARN("Failed to set args of offcpu event: no enough buffer\n");
        evt_fmt->args[0] = 0;
    }
}

int local_write_offcpu_event(struct local_store_s *local_storage, event_elem_t *evt)
{
    struct trace_event_fmt_s evt_fmt = {0};
    thrd_info_t *thrd_info = evt->thrd_info;
    proc_info_t *proc_info = thrd_info->proc_info;
    offcpu_data_t *offcpu_d = EVT_DATA_OFFCPU(evt);
    __u64 start_time, end_time;
    int ret;

    start_time = get_unix_time_from_uptime(offcpu_d->start_time);
    end_time = get_unix_time_from_uptime(offcpu_d->start_time + offcpu_d->duration);

    evt_fmt.pid = proc_info->tgid;
    evt_fmt.tid = thrd_info->pid;
    evt_fmt.id = gen_async_event_id();
    // TODO: oncpu事件包含公共信息，可作为一个模版进行优化
    (void)snprintf(evt_fmt.category, sizeof(evt_fmt.category), EVENT_CATEGORY_OFFCPU);
    (void)snprintf(evt_fmt.name, sizeof(evt_fmt.name), PROFILE_EVT_TYPE_OFFCPU);
    (void)snprintf(evt_fmt.cname, sizeof(evt_fmt.cname), EVENT_CNAME_OF_OFFCPU);
    (void)set_stack_sf(&evt_fmt, evt, local_storage);

    // set async begin event
    evt_fmt.phase = EVENT_PHASE_ASYNC_START;
    evt_fmt.ts = start_time;
    ret = trace_event_fmt_to_json_str(&evt_fmt, local_storage->buf, sizeof(local_storage->buf));
    if (ret) {
        return ret;
    }

    ret = trace_file_fill_event_from_buffer(local_storage);
    if (ret < 0) {
        return -1;
    }

    // set async end event
    set_offcpu_event_args(&evt_fmt, evt);
    evt_fmt.phase = EVENT_PHASE_ASYNC_END;
    evt_fmt.ts = end_time;
    ret = trace_event_fmt_to_json_str(&evt_fmt, local_storage->buf, sizeof(local_storage->buf));
    if (ret) {
        return ret;
    }

    return trace_file_fill_event_from_buffer(local_storage);
}

void set_syscall_event_args(struct trace_event_fmt_s *evt_fmt, event_elem_t *evt)
{
    syscall_data_t *syscall_d = EVT_DATA_SC(evt);
    thrd_info_t *thrd_info = evt->thrd_info;
    strbuf_t strbuf = {
        .buf = evt_fmt->args,
        .size = sizeof(evt_fmt->args)
    };
    int ret;

    ret = snprintf(strbuf.buf, strbuf.size, "\"count\": %d, \"thread.name\": \"%s\"",
        syscall_d->count, thrd_info->comm);
    if (ret < 0 || ret >= strbuf.size) {
        TP_DEBUG("Failed to set args of syscall event: no enough buffer\n");
        evt_fmt->args[0] = 0;
        return;
    }
    strbuf_update_offset(&strbuf, ret);
    ret = append_syscall_attrs_by_nr(&strbuf, evt);
    if (ret) {
        TP_DEBUG("Failed to set args of syscall event: ret=%d\n", ret);
        evt_fmt->args[0] = 0;
        return;
    }
}

int set_syscall_evt_fmt(struct trace_event_fmt_s *evt_fmt, struct local_store_s *local_storage, event_elem_t *evt)
{
    syscall_data_t *syscall_d = EVT_DATA_SC(evt);
    syscall_meta_t *scm;

    evt_fmt->phase = EVENT_PHASE_COMPLETE;
    evt_fmt->ts = get_unix_time_from_uptime(syscall_d->start_time);
    evt_fmt->duration = syscall_d->duration;
    // TODO: add event type to category
    (void)snprintf(evt_fmt->category, sizeof(evt_fmt->category), EVENT_CATEGORY_SYSCALL);
    set_syscall_name(syscall_d->nr, evt_fmt->name);
    set_syscall_event_args(evt_fmt, evt);

    scm = get_syscall_meta(syscall_d->nr);
    if (scm == NULL) {
        return -1;
    }
    if (scm->flag & SYSCALL_FLAG_STACK) {
       (void)set_stack_sf(evt_fmt, evt, local_storage);
    }

    return 0;
}

int set_syscall_stuck_evt_fmt(struct trace_event_fmt_s *evt_fmt, struct local_store_s *local_storage, event_elem_t *evt);

void set_pthrd_event_args(struct trace_event_fmt_s *evt_fmt, event_elem_t *evt)
{
    pthrd_data_t *pthrd_d = EVT_DATA_PTHRD(evt);
    thrd_info_t *thrd_info = evt->thrd_info;
    int ret;

    ret = snprintf(evt_fmt->args, sizeof(evt_fmt->args),
        "\"count\": %d, \"thread.name\": \"%s\"",
        pthrd_d->count, thrd_info->comm);
    if (ret < 0 || ret >= sizeof(evt_fmt->args)) {
        TP_DEBUG("Failed to set args of pygc event: no enough buffer\n");
        evt_fmt->args[0] = 0;
    }
}

static void set_pthrd_event_name(char *name, int size, int id)
{
    name[0] = '\0';
    if (id <= 0 || id >= PTHREAD_MAX_ID) {
        return;
    }
    (void)snprintf(name, size, "%s", g_pthrd_name_tbl[id]);
}

int set_pthrd_evt_fmt(struct trace_event_fmt_s *evt_fmt, struct local_store_s *local_storage, event_elem_t *evt)
{
    pthrd_data_t *pthrd_d = EVT_DATA_PTHRD(evt);

    evt_fmt->phase = EVENT_PHASE_COMPLETE;
    evt_fmt->ts = get_unix_time_from_uptime(pthrd_d->start_time);
    evt_fmt->duration = pthrd_d->duration;
    (void)snprintf(evt_fmt->category, sizeof(evt_fmt->category), EVENT_CATEGORY_PTHRD_SYNC);
    (void)snprintf(evt_fmt->name, sizeof(evt_fmt->name), PROFILE_EVT_TYPE_PYGC);
    set_pthrd_event_name(evt_fmt->name, sizeof(evt_fmt->name), pthrd_d->id);
    set_pthrd_event_args(evt_fmt, evt);
    (void)set_stack_sf(evt_fmt, evt, local_storage);

    return 0;
}

void set_pygc_event_args(struct trace_event_fmt_s *evt_fmt, event_elem_t *evt)
{
    pygc_data_t *pygc_d = EVT_DATA_PYGC(evt);
    thrd_info_t *thrd_info = evt->thrd_info;
    int ret;

    ret = snprintf(evt_fmt->args, sizeof(evt_fmt->args),
        "\"count\": %d, \"event.type\": \"%s\", \"thread.name\": \"%s\"",
        pygc_d->count, PROFILE_EVT_TYPE_PYGC, thrd_info->comm);
    if (ret < 0 || ret >= sizeof(evt_fmt->args)) {
        TP_WARN("Failed to set args of pygc event: no enough buffer\n");
        evt_fmt->args[0] = 0;
    }
}

int set_pygc_evt_fmt(struct trace_event_fmt_s *evt_fmt, struct local_store_s *local_storage, event_elem_t *evt)
{
    pygc_data_t *pygc_d = EVT_DATA_PYGC(evt);

    evt_fmt->phase = EVENT_PHASE_COMPLETE;
    evt_fmt->ts = get_unix_time_from_uptime(pygc_d->start_time);
    evt_fmt->duration = pygc_d->duration;
    (void)snprintf(evt_fmt->category, sizeof(evt_fmt->category), EVENT_CATEGORY_PYGC);
    (void)snprintf(evt_fmt->name, sizeof(evt_fmt->name), PROFILE_EVT_TYPE_PYGC);
    set_pygc_event_args(evt_fmt, evt);
    (void)set_stack_sf(evt_fmt, evt, local_storage);

    return 0;
}

void set_oncpu_sample_event_args(struct trace_event_fmt_s *evt_fmt, event_elem_t *evt)
{
    oncpu_sample_data_t *sample_d = EVT_DATA_CPU_SAMPLE(evt);
    int ret;

    ret = snprintf(evt_fmt->args, sizeof(evt_fmt->args), "\"cpu\": %u", sample_d->cpu);
    if (ret < 0 || ret >= sizeof(evt_fmt->args)) {
        TP_WARN("Failed to set args of oncpu_sample event: no enough buffer\n");
        evt_fmt->args[0] = 0;
    }
}

int set_oncpu_sample_evt_fmt(struct trace_event_fmt_s *evt_fmt, struct local_store_s *local_storage, event_elem_t *evt)
{
    oncpu_sample_data_t *sample_d = EVT_DATA_CPU_SAMPLE(evt);

    evt_fmt->phase = EVENT_PHASE_SAMPLE;
    evt_fmt->ts = get_unix_time_from_uptime(sample_d->time);
    (void)snprintf(evt_fmt->category, sizeof(evt_fmt->category), EVENT_CATEGORY_SAMPLE);
    (void)snprintf(evt_fmt->name, sizeof(evt_fmt->name), PROFILE_EVT_TYPE_SAMPLE);
    set_oncpu_sample_event_args(evt_fmt, evt);
    (void)set_stack_sf(evt_fmt, evt, local_storage);

    return 0;
}

int local_write_general_event(struct local_store_s *local_storage, event_elem_t *evt, func_set_evt_fmt callback)
{
    struct trace_event_fmt_s evt_fmt = {0};
    int ret;

    if (evt->thrd_info == NULL || evt->thrd_info->proc_info == NULL) {
        return -1;
    }

    evt_fmt.pid = evt->thrd_info->proc_info->tgid;
    evt_fmt.tid = evt->thrd_info->pid;

    ret = callback(&evt_fmt, local_storage, evt);
    if (ret < 0) {
        return -1;
    }

    ret = trace_event_fmt_to_json_str(&evt_fmt, local_storage->buf, sizeof(local_storage->buf));
    if (ret) {
        return ret;
    }

    return trace_file_fill_event_from_buffer(local_storage);
}

int local_write_event(struct local_store_s *local_storage, event_elem_t *evt)
{
    trace_event_type_t typ = EVT_DATA_TYPE(evt);
    int ret;

    if (local_storage->is_write == 0) {
        ret = trace_file_fill_head(local_storage->fp);
        if (ret) {
            return -1;
        }
        local_storage->is_write = 1;
    }

    switch (typ) {
        case EVT_TYPE_ONCPU:
            return local_write_oncpu_event(local_storage, evt);
        case EVT_TYPE_OFFCPU:
            return local_write_offcpu_event(local_storage, evt);
        case EVT_TYPE_SYSCALL:
            return local_write_general_event(local_storage, evt, set_syscall_evt_fmt);
        case EVT_TYPE_SYSCALL_STUCK:
            return local_write_general_event(local_storage, evt, set_syscall_stuck_evt_fmt);
        case EVT_TYPE_PTHREAD:
            return local_write_general_event(local_storage, evt, set_pthrd_evt_fmt);
        case EVT_TYPE_PYGC:
            return local_write_general_event(local_storage, evt, set_pygc_evt_fmt);
        case EVT_TYPE_ONCPU_PERF:
            return local_write_general_event(local_storage, evt, set_oncpu_sample_evt_fmt);
        default:
            TP_WARN("Unknown event type %d\n", typ);
            return -1;
    }
}

void report_thrd_events_local(thrd_info_t *thrd_info)
{
    event_elem_t *evt = NULL;
    int ret;

    if (thrd_info->cached_evts == NULL) {
        return;
    }

    DL_FOREACH(thrd_info->cached_evts, evt) {
        ret = local_write_event(&tprofiler.localStorage, evt);
        if (ret) {
            TP_WARN("Failed to write event locally\n");
        }
    }

    delete_first_k_events(thrd_info, thrd_info->evt_num);
}

void report_all_cached_thrd_events_local()
{
    proc_info_t *pi, *pi_tmp;
    thrd_info_t *ti, *ti_tmp;

    if (tprofiler.procTable != NULL) {
        HASH_ITER(hh, tprofiler.procTable, pi, pi_tmp) {
            if (pi->thrd_table == NULL || *pi->thrd_table == NULL) {
                continue;
            }
            HASH_ITER(hh, *pi->thrd_table, ti, ti_tmp) {
                report_thrd_events_local(ti);
            }
        }
    }
}

int report_all_cached_events_local(struct local_store_s *local_storage)
{
    int ret;

    if (local_storage->fp == NULL) {
        return 0;
    }

    if (local_storage->is_write == 0) {
        ret = trace_file_fill_head(local_storage->fp);
        if (ret) {
            return -1;
        }
        local_storage->is_write = 1;
    }

    report_all_cached_thrd_events_local();

    ret = fprintf(local_storage->fp, "],\n");
    if (ret < 0) {
        return -1;
    }

    ret = trace_file_fill_stack_from_file(local_storage->fp, local_storage->stack_fp);
    if (ret) {
        return -1;
    }

    ret = trace_file_fill_tail(local_storage->fp);
    if (ret) {
        return -1;
    }
    (void)fflush(local_storage->fp);

    ret = rename(local_storage->trace_path_tmp, local_storage->trace_path);
    if (ret < 0) {
        TP_ERROR("Failed to rename trace file %s to %s\n",
            local_storage->trace_path_tmp, local_storage->trace_path);
        return -1;
    }
    (void)fclose(local_storage->fp);
    local_storage->fp = NULL;

    // 清理stack临时文件
    (void)fclose(local_storage->stack_fp);
    local_storage->stack_fp = NULL;
    if (remove(local_storage->stack_path_tmp)) {
        TP_DEBUG("Cannot remove stack tmp file: %s, err=%s\n", local_storage->stack_path_tmp, strerror(errno));
    }

    return 0;
}

/* begin: stuck event related */

#define SYSCALL_STUCK_EVT_DESC "The event is not finished"

void set_syscall_stuck_event_args(struct trace_event_fmt_s *evt_fmt, event_elem_t *evt)
{
    syscall_data_t *syscall_d = EVT_DATA_SC(evt);
    thrd_info_t *thrd_info = evt->thrd_info;
    strbuf_t strbuf = {
        .buf = evt_fmt->args,
        .size = sizeof(evt_fmt->args)
    };
    u64 start_time;
    int ret;

    start_time = get_unix_time_from_uptime(syscall_d->start_time);
    ret = snprintf(strbuf.buf, strbuf.size,
        "\"desc\": \"%s\", \"thread.name\": \"%s\", \"start_time\": %llu, \"duration\": \"%llu s\"",
        SYSCALL_STUCK_EVT_DESC, thrd_info->comm, start_time / NSEC_PER_USEC, (evt_fmt->ts - start_time) / NSEC_PER_SEC);
    if (ret < 0 || ret >= strbuf.size) {
        TP_DEBUG("Failed to set args of syscall stuck event: no enough buffer\n");
        evt_fmt->args[0] = 0;
        return;
    }
    strbuf_update_offset(&strbuf, ret);

    ret = append_syscall_attrs_by_nr(&strbuf, evt);
    if (ret) {
        TP_DEBUG("Failed to set args of syscall stuck event: ret=%d\n", ret);
        evt_fmt->args[0] = 0;
        return;
    }
}

int set_syscall_stuck_evt_fmt(struct trace_event_fmt_s *evt_fmt, struct local_store_s *local_storage,
    event_elem_t *evt)
{
    syscall_data_t *syscall_d = EVT_DATA_SC(evt);

    evt_fmt->phase = EVENT_PHASE_INSTANT;
    evt_fmt->ts = NS(time(NULL));
    evt_fmt->scope = EVENT_INSTANT_SCOPE_THREAD;
    (void)snprintf(evt_fmt->category, sizeof(evt_fmt->category), "%s,%s",
        EVENT_CATEGORY_SYSCALL, EVENT_CATEGORY_STUCK);
    set_syscall_name(syscall_d->nr, evt_fmt->name);
    set_syscall_stuck_event_args(evt_fmt, evt);

    return 0;
}

thrd_info_t *cache_thrd_info(syscall_m_enter_t *sce)
{
    proc_info_t *pi;
    thrd_info_t *ti;

    pi = get_proc_info(&tprofiler.procTable, PTID_GET_PID(sce->ptid));
    if (pi == NULL) {
        return NULL;
    }
    ti = get_thrd_info(pi, PTID_GET_TID(sce->ptid));
    if (ti == NULL) {
        return NULL;
    }

    return ti;
}

void parse_syscall_stat_info(stats_syscall_t *sc_stats, syscall_m_enter_t *sce)
{
    syscall_meta_t *scm;
    unsigned long nr = sce->nr;

    scm = get_syscall_meta(nr);
    if (!scm) {
        return;
    }
    if (nr == SYSCALL_FUTEX_ID) {
        sc_stats->stats_futex.op = sce->ext_info.futex_info.op;
    } else if (scm->flag & SYSCALL_FLAG_FD) {
        sc_stats->stats_fd.fd = sce->ext_info.fd_info.fd;
    }
}

event_elem_t *parse_stuck_event_elem(syscall_m_enter_t *sce, thrd_info_t *thrd_info)
{
    event_elem_t *stuck_evt;
    event_data_t *data;
    syscall_data_t *scd;

    stuck_evt = create_event_elem(sizeof(event_data_t));
    if (stuck_evt == NULL) {
        return NULL;
    }
    stuck_evt->thrd_info = thrd_info;

    data = EVT_DATA(stuck_evt);
    data->type = EVT_TYPE_SYSCALL_STUCK;

    scd = &data->syscall_d;
    scd->nr = sce->nr;
    scd->start_time = sce->start_time;
    parse_syscall_stat_info(&scd->stats, sce);

    return stuck_evt;
}

void do_report_syscall_stuck_event(syscall_m_enter_t *sce)
{
    event_elem_t *stuck_evt;
    thrd_info_t *ti;
    int ret;

    ti = cache_thrd_info(sce);
    if (ti == NULL) {
        TP_DEBUG("Failed to get thread info\n");
        return;
    }
    stuck_evt = parse_stuck_event_elem(sce, ti);
    if (stuck_evt == NULL) {
        return;
    }

    ret = local_write_event(&tprofiler.localStorage, stuck_evt);
    if (ret) {
        TP_WARN("Failed to write stuck event locally\n");
        return;
    }
}

void report_syscall_stuck_event(void)
{
    int scEnterMapFd = tprofiler.scEnterMapFd;
    u64 cur_key = 0, next_key = 0;
    syscall_m_enter_t sce;
    time_t now = time(NULL);
    int ret;

    if (scEnterMapFd <= 0) {
        return;
    }

    while (bpf_map_get_next_key(scEnterMapFd, &cur_key, &next_key) == 0) {
        ret = bpf_map_lookup_elem(scEnterMapFd, &next_key, &sce);
        cur_key = next_key;
        if (ret != 0) {
            continue;
        }
        /* 超过一定时间阈值，说明该事件所在的线程可能卡死，上报该事件 */
        if (now < get_unix_time_from_uptime(sce.start_time) / NSEC_PER_SEC + STUCK_EVT_REPORT_THRD) {
            continue;
        }
        do_report_syscall_stuck_event(&sce);
    }
}

void report_stuck_event(struct ipc_body_s *ipc_body)
{
    time_t now = time(NULL);

    if (tprofiler.stuck_evt_timer + STUCK_EVT_REPORT_DURATION > now) {
        return;
    }
    tprofiler.stuck_evt_timer = now;

    if (is_load_probe_ipc(ipc_body, TPROFILING_PROBE_SYSCALL_ALL)) {
        report_syscall_stuck_event();
    }
}

/* end: stuck event related */

/* start: mem snapshot event related */

void add_alloc_event_to_mem_stack_tree(trace_event_data_t *evt_data, proc_info_t *proc_info)
{
    struct mem_alloc_s *mem_alloc;
    char symbs_str[MAX_STACK_STR_LEN];
    mem_glibc_data_t *mem_glibc_d = &evt_data->mem_glibc_d;
    stack_trace_t *stack;
    int ret;

    mem_alloc = mem_alloc_tbl_find_item(&tprofiler.mem_alloc_tbl, proc_info->tgid, mem_glibc_d->addr, mem_glibc_d->ts);
    if (mem_alloc != NULL) {
        if (mem_alloc->symb_addr == NULL) { // 内存释放事件
            mem_alloc_tbl_delete_item(&tprofiler.mem_alloc_tbl, mem_alloc);
        }
        return;
    }

    stack = &mem_glibc_d->stats_stack.stack;
    if (stack->uid <= 0) {
        return;
    }

    symbs_str[0] = 0;
    ret = get_symb_stack(symbs_str, sizeof(symbs_str), stack, proc_info);
    if (ret){
        TP_WARN("Failed to get symbol stack\n");
        return;
    }

    // 1. 加入到进程的内存堆栈树里面
    struct stack_node_s *leaf = stack_tree_add_stack(proc_info->mem_glibc_tree, symbs_str, false);
    if (leaf == NULL) {
        TP_ERROR("Failed to add malloc stack to mem tree\n");
        return;
    }
    leaf->count += mem_glibc_d->size;
    // 2. 更新进程的内存使用量
    proc_info->alloc_mem_sz += mem_glibc_d->size;
    // 3. 保存内存地址到堆栈的映射关系
    (void)mem_alloc_tbl_add_item(&tprofiler.mem_alloc_tbl, proc_info->tgid, mem_glibc_d->addr, mem_glibc_d->ts,
        (void *)leaf, mem_glibc_d->size);
}

void add_free_event_to_mem_stack_tree(trace_event_data_t *evt_data, proc_info_t *proc_info)
{
    struct mem_alloc_s *mem_alloc;

    mem_alloc = mem_alloc_tbl_find_item(&tprofiler.mem_alloc_tbl, proc_info->tgid, evt_data->mem_glibc_d.addr, evt_data->mem_glibc_d.ts);
    if (mem_alloc == NULL) {
        (void)mem_alloc_tbl_add_item(&tprofiler.mem_alloc_tbl, proc_info->tgid, evt_data->mem_glibc_d.addr, evt_data->mem_glibc_d.ts,
            NULL, evt_data->mem_glibc_d.size);
        return;
    }
    if (mem_alloc->symb_addr == NULL) { // 不是内存申请事件
        return;
    }

    // 1. 更新内存堆栈的大小，更新内存使用量大小
    struct stack_node_s *leaf = (struct stack_node_s *)mem_alloc->symb_addr;
    leaf->count -= mem_alloc->size;
    proc_info->alloc_mem_sz -= mem_alloc->size;

    // 2. 删除内存地址映射
    mem_alloc_tbl_delete_item(&tprofiler.mem_alloc_tbl, mem_alloc);
}

void output_mem_glibc_event(trace_event_data_t *evt_data)
{
    proc_info_t *pi;
    mem_glibc_data_t *mem_glibc_d = &evt_data->mem_glibc_d;
    
    pi = get_proc_info(&tprofiler.procTable, evt_data->tgid);
    if (pi == NULL) {
        return;
    }

    if (mem_glibc_d->size > 0) {    // 内存申请事件
        add_alloc_event_to_mem_stack_tree(evt_data, pi);
    } else if (mem_glibc_d->size < 0) {
        add_free_event_to_mem_stack_tree(evt_data, pi);
    }
}

int local_write_mem_snap_metric_event(proc_info_t *pi, u64 ts)
{
    struct local_store_s *local_storage = &tprofiler.localStorage;
    struct trace_event_fmt_s evt_fmt = {0};
    int ret;

    evt_fmt.phase = EVENT_PHASE_COUNTER;
    evt_fmt.pid = pi->tgid;
    evt_fmt.ts = ts;
    (void)snprintf(evt_fmt.name, sizeof(evt_fmt.name), "memory::Allocs");
    (void)snprintf(evt_fmt.category, sizeof(evt_fmt.category), "memory");
    (void)snprintf(evt_fmt.args, sizeof(evt_fmt.args), "\"current_allocs\": %llu", pi->alloc_mem_sz);

    ret = trace_event_fmt_to_json_str(&evt_fmt, local_storage->buf, sizeof(local_storage->buf));
    if (ret) {
        return ret;
    }

    return trace_file_fill_event_from_buffer(local_storage);
}

int dfs_mem_stack_tree(heap_mem_elem_t **leafs_p, struct stack_node_s *cur_node)
{
    struct stack_node_s *child, *tmp;

    if (cur_node->childs == NULL) {
        // 叶子节点
        heap_mem_elem_t *leaf = (heap_mem_elem_t *)calloc(1, sizeof(heap_mem_elem_t));
        if (leaf == NULL) {
            return -1;
        }
        leaf->leaf = cur_node;
        LL_APPEND(*leafs_p, leaf);
        return 0;
    }

    HASH_ITER(hh, cur_node->childs, child, tmp) {
        if (dfs_mem_stack_tree(leafs_p, child)) {
            return -1;
        }
    }
    return 0;
}

int mem_stack_get_all_leafs(heap_mem_elem_t **leafs_p, struct stack_node_s *mem_glibc_tree)
{
    struct stack_node_s *child, *tmp;

    HASH_ITER(hh, mem_glibc_tree->childs, child, tmp) {
        if (dfs_mem_stack_tree(leafs_p, child)) {
            return -1;
        }
    }
    return 0;
}

void clean_released_stacks(heap_mem_elem_t *leafs)
{
    heap_mem_elem_t *leaf;

    LL_FOREACH(leafs, leaf) {
        if (leaf->leaf->count == 0) {
            stack_tree_remove_leaf(leaf->leaf);
            leaf->leaf = NULL;
        }
    }
}

void empty_leafs(heap_mem_elem_t **leafs_p)
{
    heap_mem_elem_t *leaf, *tmp;

    LL_FOREACH_SAFE(*leafs_p, leaf, tmp) {
        LL_DELETE(*leafs_p, leaf);
    }
}

int get_proc_mem_snap(proc_info_t *pi, char *buf, int buf_sz)
{
    heap_mem_elem_t *leafs = NULL;
    struct stack_node_s **top_stacks = NULL;
    int top_num = 0;
    char symbs_str[MAX_STACK_STR_LEN];
    char *comma;
    int ret;

    symbs_str[0] = 0;
    ret = mem_stack_get_all_leafs(&leafs, pi->mem_glibc_tree);
    if (ret) {
        empty_leafs(&leafs);
        return -1;
    }
    clean_released_stacks(leafs);
    top_stacks = get_topk_mem_stack(leafs, MEM_SNAP_TOP_STACK_NUM, &top_num);
    if (top_stacks == NULL) {
        empty_leafs(&leafs);
        return -1;
    }

    for (int i = 0; i < top_num; ++i) {
        comma = (i == 0) ? "" : ",";
        ret = stack_tree_get_stack_str(top_stacks[i], symbs_str, sizeof(symbs_str));
        if (ret) {
            empty_leafs(&leafs);
            free(top_stacks);
            return -1;
        }
        ret = snprintf(buf, buf_sz, "%s{\"trace\": \"%s\", \"current_allocs\": %llu}", comma, symbs_str, top_stacks[i]->count);
        if (ret < 0 || ret >= buf_sz) {
            TP_ERROR("Failed to write proc memory snapshot, ret=%d\n", ret);
            empty_leafs(&leafs);
            free(top_stacks);
            return -1;
        }
        buf_sz -= ret;
        buf += ret;
    }

    empty_leafs(&leafs);
    free(top_stacks);
    return 0;
}

int local_write_mem_snap_event(proc_info_t *pi, u64 ts)
{
    struct local_store_s *local_storage = &tprofiler.localStorage;
    char mem_snap[MAX_STACK_STR_LEN + 128];
    int ret;

    mem_snap[0] = 0;
    ret = get_proc_mem_snap(pi, mem_snap, sizeof(mem_snap));
    if (ret) {
        TP_ERROR("Failed to get proc memory snapshot, ret=%d\n", ret);
        return -1;
    }

    // 考虑到内存快照事件的 args 字段内容比较大，这里直接写文件，减少通过 trace_event_fmt_to_json_str 的二次内存拷贝开销
    ret = fprintf(local_storage->fp, ",\n{\"cat\": \"memory\", \"pid\": %u, \"ts\": %llu, "
        "\"ph\": \"O\", \"name\": \"memory::Heap\", \"id\": \"%u\", \"args\": {\"snapshot\": [%s]}}",
        pi->tgid, ts / NSEC_PER_USEC, pi->tgid, mem_snap);
    if  (ret < 0) {
        TP_ERROR("Failed to write local file, ret=%d\n", ret);
        return -1;
    }

    return 0;
}

int report_proc_mem_snap_event(proc_info_t *pi)
{
    struct local_store_s *local_storage = &tprofiler.localStorage;
    u64 ts = (u64)time(NULL) * NSEC_PER_SEC;
    int ret;

    if (local_storage->fp == NULL) {
        return -1;
    }

    if (local_storage->is_write == 0) {
        ret = trace_file_fill_head(local_storage->fp);
        if (ret) {
            TP_ERROR("Failed to fill trace file head\n");
            return -1;
        }
        local_storage->is_write = 1;
    }

    ret = local_write_mem_snap_metric_event(pi, ts);
    if (ret) {
        TP_ERROR("Failed to write memory snapshot metric event\n");
        return -1;
    }

    ret = local_write_mem_snap_event(pi, ts);
    if (ret) {
        TP_ERROR("Failed to write memory snapshot event\n");
        return -1;
    }
    return 0;
}

int report_mem_snap_event(struct ipc_body_s *ipc_body)
{
    time_t now = time(NULL);

    if (!is_load_probe_ipc(ipc_body, PROBE_RANGE_TPROFILING_MEM_GLIBC)) {
        return 0;
    }

    if (tprofiler.mem_snap_timer + MEM_SNAP_EVT_REPORT_THRD > now) {
        return 0;
    }
    tprofiler.mem_snap_timer = now;

    proc_info_t *pi, *pi_tmp;
    HASH_ITER(hh, tprofiler.procTable, pi, pi_tmp) {
        if (report_proc_mem_snap_event(pi)) {
            return -1;
        }
    }
    return 0;
}

/* end: mem snapshot event related */

/* start: mem usage probe related */

int gen_oom_trace_file(char *file_path, int size)
{
    size_t sz;
    int ret;

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    file_path[0] = 0;

    char timestamp[MAX_PROCESS_NAME_LEN];
    sz = strftime(timestamp, sizeof(timestamp), "oom-trace-%Y%m%d%H%M.json", tm);
    if (sz == 0) {
        TP_ERROR("Failed to set oom trace file path\n");
        return -1;
    }

    ret = snprintf(file_path, size, "%s%s", tprofiler.output_dir, timestamp);
    if (ret < 0) {
        TP_ERROR("Failed to snprintf file path\n");
        return -1;
    }

    if (access(tprofiler.output_dir, F_OK)) {
        ret = mkdir(tprofiler.output_dir, 0700);
        if (ret) {
            TP_ERROR("Failed to create trace dir:%s, ret=%d\n", tprofiler.output_dir, ret);
            return -1;
        }
        TP_INFO("Succeed to create trace dir:%s\n", tprofiler.output_dir);
    }

    return 0;
}

static int get_proc_container_id(int pid, char *container_id, int size)
{
    char pid_str[INT_LEN];

    pid_str[0] = 0;
    (void)snprintf(pid_str, sizeof(pid_str), "%d", pid);
    return get_container_id_by_pid_cpuset(pid_str, container_id, size);
}

// example: {"pid": 100, "comm": "python3", "cmdline": "python3 xxx.py", "container_id": "abcd"}
int local_write_oom_proc(FILE *fp, struct proc_mem_usage *proc_item, bool is_first)
{
    char *comma = is_first ? "" : ",";
    char cmd[LINE_BUF_LEN];
    char container_id[CONTAINER_ABBR_ID_LEN + 1];
    int ret;

    cmd[0] = 0;
    if (get_proc_cmdline(proc_item->pid, cmd, sizeof(cmd))) {
        cmd[0] = 0;
    }
    container_id[0] = 0;
    if (get_proc_container_id(proc_item->pid, container_id, sizeof(container_id))) {
        container_id[0] = 0;
    }

    ret = fprintf(fp, "%s\n{\"pid\": %u, \"comm\": \"%s\", \"cmdline\": \"%s\"",
        comma, proc_item->pid, proc_item->comm, cmd);
    if (ret < 0) {
        return -1;
    }
    if (container_id[0] != 0) {
        ret = fprintf(fp, ", \"container_id\": \"%s\"", container_id);
        if (ret < 0) {
            return -1;
        }
    }
    ret = fprintf(fp, "}");
    if (ret < 0) {
        return -1;
    }

    return 0;
}

int local_write_all_oom_procs(FILE *fp)
{
    struct proc_mem_usage **mem_usage_tbl = get_mem_usage_tbl();
    struct proc_mem_usage *proc_item, *tmp;
    char is_grow = 0;
    bool is_first = true;

    HASH_ITER(hh, *mem_usage_tbl, proc_item, tmp) {
        if (mem_usage_detect_oom(proc_item, &is_grow) == 0) {
            if (is_grow) {
                if (local_write_oom_proc(fp, proc_item, is_first)) {
                    TP_ERROR("Failed to write oom proc\n");
                    return -1;
                }
                is_first = false;
            }
        } else {
            TP_ERROR("Failed to detect oom proc\n");
            return -1;
        }
    }

    return 0;
}

int report_oom_procs_local(void)
{
    char file_path[PATH_LEN];
    FILE *fp = NULL;
    int ret;

    ret = gen_oom_trace_file(file_path, sizeof(file_path));
    if (ret) {
        TP_ERROR("Failed to get oom trace file\n");
        return -1;
    }
    fp = fopen(file_path, "w");
    if (fp == NULL) {
        TP_ERROR("Failed to open oom trace file\n");
        return -1;
    }

    ret = fprintf(fp, "{\n\"oom_procs\": [");
    if (ret < 0) {
        TP_ERROR("Failed to write oom trace file, ret=%d\n", ret);
        goto err;
    }

    ret = local_write_all_oom_procs(fp);
    if (ret) {
        TP_ERROR("Failed to write all oom procs\n");
        goto err;
    }

    ret = fprintf(fp, "\n]}");
    if (ret < 0) {
        TP_ERROR("Failed to write oom trace file, ret=%d\n", ret);
        goto err;
    }

    fclose(fp);
    return 0;
err:
    fclose(fp);
    remove(file_path);
    return -1;
}

/* end: mem usage probe related */