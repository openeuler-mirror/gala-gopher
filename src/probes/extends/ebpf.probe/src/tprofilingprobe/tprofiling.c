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
 * Create: 2023-04-03
 * Description: the user-side program of thread profiling probe
 ******************************************************************************/
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>
#include <linux/limits.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "args.h"
#include "ipc.h"
#include "profiling_event.h"
#include "java_support.h"
#include "bpf_prog.h"
#include "tprofiling.h"
#include "syscall.h"
#include "mem_usage.h"
Tprofiler tprofiler;

#define TP_WAIT_DURATION 5  /* 设置一个小的值，避免长时间等待导致无法接收ipc消息 */

static volatile sig_atomic_t stop = 0;

static struct ipc_body_s g_ipc_body = {0};

static syscall_meta_t g_syscall_metas[] = {
    // file
    {SYSCALL_READ_ID, SYSCALL_READ_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_FILE},
    {SYSCALL_WRITE_ID, SYSCALL_WRITE_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_FILE},
    {SYSCALL_READV_ID, SYSCALL_READV_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_FILE},
    {SYSCALL_WRITEV_ID, SYSCALL_WRITE_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_FILE},
    {SYSCALL_PREADV_ID, SYSCALL_PREADV_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_FILE},
    {SYSCALL_PWRITEV_ID, SYSCALL_PWRITEV_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_FILE},
    {SYSCALL_SYNC_ID, SYSCALL_SYNC_NAME, SYSCALL_FLAG_STACK, PROFILE_EVT_TYPE_FILE},
    {SYSCALL_FSYNC_ID, SYSCALL_FSYNC_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_FILE},
    {SYSCALL_FDATASYNC_ID, SYSCALL_FDATASYNC_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_FILE},
    // process schedule
    {SYSCALL_SCHED_YIELD_ID, SYSCALL_SCHED_YIELD_NAME, SYSCALL_FLAG_STACK, PROFILE_EVT_TYPE_SCHED},
    {SYSCALL_NANOSLEEP_ID, SYSCALL_NANOSLEEP_NAME, SYSCALL_FLAG_STACK, PROFILE_EVT_TYPE_SCHED},
    {SYSCALL_CLOCK_NANOSLEEP_ID, SYSCALL_CLOCK_NANOSLEEP_NAME, SYSCALL_FLAG_STACK, PROFILE_EVT_TYPE_SCHED},
    {SYSCALL_WAIT4_ID, SYSCALL_WAIT4_NAME, SYSCALL_FLAG_STACK, PROFILE_EVT_TYPE_SCHED},
#if defined(__TARGET_ARCH_x86)
    {SYSCALL_WAITPID_ID, SYSCALL_WAITPID_NAME, SYSCALL_FLAG_STACK, PROFILE_EVT_TYPE_SCHED},
#endif
    {SYSCALL_SELECT_ID, SYSCALL_SELECT_NAME, SYSCALL_FLAG_STACK, PROFILE_EVT_TYPE_SCHED},
    {SYSCALL_PSELECT6_ID, SYSCALL_PSELECT6_NAME, SYSCALL_FLAG_STACK, PROFILE_EVT_TYPE_SCHED},
    {SYSCALL_POLL_ID, SYSCALL_POLL_NAME, SYSCALL_FLAG_STACK, PROFILE_EVT_TYPE_SCHED},
    {SYSCALL_PPOLL_ID, SYSCALL_PPOLL_NAME, SYSCALL_FLAG_STACK, PROFILE_EVT_TYPE_SCHED},
    {SYSCALL_EPOLL_WAIT_ID, SYSCALL_EPOLL_WAIT_NAME, SYSCALL_FLAG_STACK, PROFILE_EVT_TYPE_SCHED},
    // network
    {SYSCALL_SENDTO_ID, SYSCALL_SENDTO_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_NET},
    {SYSCALL_RECVFROM_ID, SYSCALL_RECVFROM_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_NET},
    {SYSCALL_SENDMSG_ID, SYSCALL_SENDMSG_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_NET},
    {SYSCALL_RECVMSG_ID, SYSCALL_RECVMSG_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_NET},
    {SYSCALL_SENDMMSG_ID, SYSCALL_SENDMMSG_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_NET},
    {SYSCALL_RECVMMSG_ID, SYSCALL_RECVMMSG_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_NET},
    // lock
    {SYSCALL_FUTEX_ID, SYSCALL_FUTEX_NAME, SYSCALL_FLAG_STACK, PROFILE_EVT_TYPE_LOCK},
    // ioctl
    {SYSCALL_IOCTL_ID, SYSCALL_IOCTL_NAME, SYSCALL_FLAG_STACK, PROFILE_EVT_TYPE_IO},
};

static void sig_handling(int signal);
static int init_tprofiler(void);
static int init_tprofiler_map_fds(struct ipc_body_s *ipc_body);
static int init_syscall_metas(void);
static void java_symb_mgmt(int proc_filter_map_fd);
static void clean_map_files(void);
static void clean_tprofiler(void);
static int refresh_tprofiler(struct ipc_body_s *ipc_body);
static void refresh_proc_filter_map(struct ipc_body_s *ipc_body);
int init_local_storage(struct local_store_s *local_storage);
void init_pb_mgmt(PerfBufferMgmt *pbMgmt);
void clean_local_storage(struct local_store_s *local_storage);

static int setting_map_update_pb(char is_pb_a)
{
    int map_fd = tprofiler.settingMapFd;
    trace_setting_t setting = {0};
    u32 zero = 0;
    int ret;

    ret = bpf_map_lookup_elem(map_fd, &zero, &setting);
    if (ret != 0) {
        TP_ERROR("Failed to lookup setting map\n");
        return -1;
    }

    setting.is_pb_a = is_pb_a;
    ret = bpf_map_update_elem(map_fd, &zero, &setting, BPF_ANY);
    if (ret != 0) {
        TP_ERROR("Failed to update pb config to setting map\n");
        return -1;
    }

    return 0;
}

static void clear_current_stack_map()
{
    int stackMapFd = get_current_stack_map();
    u32 stack_id = 0, next_id;

    while (bpf_map_get_next_key(stackMapFd, &stack_id, &next_id) == 0) {
        bpf_map_delete_elem(stackMapFd, &next_id);
        stack_id = next_id;
    }
}

static void clear_current_py_stack_map()
{
    int fd = get_current_py_stack_map();
    u32 stack_id = 0, next_id;

    while (bpf_map_get_next_key(fd, &stack_id, &next_id) == 0) {
        bpf_map_delete_elem(fd, &next_id);
        stack_id = next_id;
    }
}

static int __poll_pb(struct bpf_prog_s *prog, PerfBufferMgmt *pbMgmt)
{
    struct bpf_buffer *cur_perf_buffer;
    time_t now = time(NULL);
    bool switch_on = false;
    int ret;

    if (prog == NULL) {
        return 0;
    }

    // 1. 若超时触发perf buffer切换，首先通知bpf程序不再向当前perf buffer写事件
    if (pbMgmt->pb_switch_timer + PERF_BUFFER_SWITCH_DURATION < now) {
        switch_on = true;
        ret = setting_map_update_pb(!pbMgmt->is_pb_a);
        if (ret) {
            return -1;
        }
        pbMgmt->pb_switch_timer = now;
        sleep(1);   // 延迟一小段时间，确保历史的事件都已经写入当前perf buffer
    }

    // 2. 从当前perf buffer读取所有的剩余事件并进行处理
    cur_perf_buffer = get_current_perf_buffer(pbMgmt);
    if (cur_perf_buffer != NULL) {
        ret = bpf_buffer__poll(cur_perf_buffer, THOUSAND);
        if (ret < 0 && ret != -EINTR) {
            return ret;
        }
    }

    if (switch_on) {
        // 3. 清理当前perf buffer的上下文信息（标记，堆栈map，缓存的事件等），切换到另一个perf buffer的上下文
        report_all_cached_thrd_events_local();
        clear_current_stack_map();  // 必须在 is_pb_a 切换之前执行
        clear_current_py_stack_map();
        pbMgmt->is_pb_a = !pbMgmt->is_pb_a;
    }

    return 0;
}

static int init_setting_map(int map_fd, struct ipc_body_s *ipc_body)
{
    trace_setting_t setting = {0};
    u32 zero = 0;
    int ret;

    tprofiler.pbMgmt.is_pb_a = 1;
    (void)time(&tprofiler.pbMgmt.pb_switch_timer);
    setting.is_pb_a = 1;

    setting.min_exec_dur = (u64)ipc_body->probe_param.min_exec_dur * NSEC_PER_USEC;
    setting.min_aggr_dur = (u64)ipc_body->probe_param.min_aggr_dur * NSEC_PER_MSEC;
    ret = bpf_map_update_elem(map_fd, &zero, &setting, BPF_ANY);
    if (ret) {
        return -1;
    }
    TP_INFO("setting.min_exec_dur=%u us, setting.min_aggr_dur=%u ms\n",
        ipc_body->probe_param.min_exec_dur, ipc_body->probe_param.min_aggr_dur);
    return 0;
}

static int init_py_sample_heap(int map_fd)
{
    int nr_cpus = NR_CPUS;
    struct py_sample *samples;
    u32 zero = 0;
    int i;
    int ret;

    samples = (struct py_sample *)calloc(nr_cpus, sizeof(struct py_sample));
    if (!samples) {
        return -1;
    }
    for (i = 0; i < nr_cpus; i++) {
        samples[i].nr_cpus = nr_cpus;
    }
    ret = bpf_map_update_elem(map_fd, &zero, samples, BPF_ANY);
    free(samples);
    return ret;
}

static char exist_profiling_task(struct ipc_body_s *ipc_body)
{
    if (is_load_probe_ipc(ipc_body, TPROFILING_PROBE_ALL)) {
        return 1;
    }
    return 0;
}

static int register_signal_handler(void)
{
    if (signal(SIGINT, sig_handling) == SIG_ERR) {
        TP_ERROR("Can't set signal handler: %s\n", strerror(errno));
        return -1;
    }
    if (signal(SIGTERM, sig_handling) == SIG_ERR) {
        TP_ERROR("Can't set signal handler: %s\n", strerror(errno));
        return -1;
    }
    /* gopher框架关闭探针时会关闭标准输出重定向的管道，导致探针后续日志打印操作会接收pipe信号 */
    if (signal(SIGPIPE, sig_handling) == SIG_ERR) {
        TP_ERROR("Can't set signal handler: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    int err = -1;
    int msq_id;
    struct ipc_body_s ipc_body = {0};

    if (register_signal_handler()) {
        return -1;
    }

    msq_id = create_ipc_msg_queue(IPC_EXCL);
    if (msq_id < 0) {
        return -1;
    }

    if (init_tprofiler()) {
        return -1;
    }

    INIT_BPF_APP(tprofiling, EBPF_RLIM_LIMITED);

    TP_INFO("Tprofiling probe start successfully.\n");

    while (!stop) {
        err = recv_ipc_msg(msq_id, (long)PROBE_TP, &ipc_body);
        if (err == 0) {
            if (ipc_body.probe_flags & IPC_FLAGS_PARAMS_CHG || ipc_body.probe_flags == 0) {
                unload_profiling_bpf_prog();
                err = load_profiling_bpf_progs(&ipc_body);
                if (err) {
                    TP_ERROR("Failed to load profiling bpf progs\n");
                    goto cleanup;
                }
                clean_mem_usage_probe();
            }

            if (refresh_tprofiler(&ipc_body)) {
                TP_ERROR("Failed to refresh tprofiler\n");
                goto cleanup;
            }
            destroy_ipc_body(&g_ipc_body);
            (void)memcpy(&g_ipc_body, &ipc_body, sizeof(g_ipc_body));
        }

        if (!exist_profiling_task(&g_ipc_body)) {
            TP_WARN("No profiling task is started, do nothing\n");
            sleep(TP_WAIT_DURATION);
            continue;
        }

        if (__poll_pb(tprofiler.bpf_progs, &tprofiler.pbMgmt)) {
            TP_ERROR("Failed to poll perf buffer from bpf progs\n");
            goto cleanup;
        }
        if (is_load_probe_ipc(&g_ipc_body, PROBE_RANGE_TPROFILING_MEM_USAGE)) {
            if (mem_usage_probe()) {
                TP_ERROR("Failed to run mem_usage probe\n");
                goto cleanup;
            }
            /* 对于只开启 mem_usage 探针的情况，添加 sleep 操作防止 mem_usage_probe 函数空转 */
            if (!is_load_probe_ipc(&g_ipc_body, TPROFILING_EBPF_PROBE_ALL)) {
                sleep(TP_WAIT_DURATION);
            }
        }

        report_stuck_event(&g_ipc_body);
        if (report_mem_snap_event(&g_ipc_body)) {
            goto cleanup;
        }

        if (tprofiler.localStorage.stack_node_num > MAX_STACK_NODE_NUM) {
            report_all_cached_events_local(&tprofiler.localStorage);
            clean_local_storage(&tprofiler.localStorage);
            init_local_storage(&tprofiler.localStorage);
        }
    }

    report_all_cached_events_local(&tprofiler.localStorage);
    if (is_load_probe_ipc(&g_ipc_body, PROBE_RANGE_TPROFILING_MEM_USAGE)) {
        if (report_oom_procs_local()) {
            TP_ERROR("Failed to report oom procs locally.\n");
            goto cleanup;
        }
    }

    TP_INFO("Tprofiling probe closed.\n");
cleanup:
    clean_tprofiler();
    clean_mem_usage_probe();
    destroy_ipc_body(&g_ipc_body);
    return -err;
}

static void sig_handling(int signal)
{
    stop = 1;
}

static int init_tprofiler(void)
{
    // 清理 tprofiling 探针异常情况下退出产生的残留文件
    clean_map_files();

    // only support local storage now
    tprofiler.output_chan = PROFILING_CHAN_LOCAL;
    tprofiler.stuck_evt_timer = time(NULL);

    if (initThreadBlacklist(&tprofiler.thrdBl)) {
        TP_ERROR("Failed to init thread blacklist.\n");
        return -1;
    }

    if (init_sys_boot_time(&tprofiler.sysBootTime)) {
        TP_ERROR("Failed to get system boot time.\n");
        return -1;
    }

    if (init_syscall_metas()) {
        TP_ERROR("Failed to init syscall meta info.\n");
        return -1;
    }

    init_pb_mgmt(&tprofiler.pbMgmt);

    return 0;
}

static int init_tprofiler_map_fds(struct ipc_body_s *ipc_body)
{
    int ret;

    if (tprofiler.settingMapFd <= 0) {
        tprofiler.settingMapFd = bpf_obj_get(SETTING_MAP_PATH);
        if (tprofiler.settingMapFd < 0) {
            TP_ERROR("Failed to get bpf prog setting map.\n");
            return -1;
        }
    }
    ret = init_setting_map(tprofiler.settingMapFd, ipc_body);
    if (ret) {
        TP_ERROR("Failed to init setting map.\n");
        return -1;
    }

    if (tprofiler.procFilterMapFd <= 0) {
        tprofiler.procFilterMapFd = bpf_obj_get(PROC_FILTER_MAP_PATH);
        if (tprofiler.procFilterMapFd < 0) {
            TP_ERROR("Failed to get bpf prog process filter map.\n");
            return -1;
        }
    }

    if (tprofiler.threadBlMapFd <= 0) {
        tprofiler.threadBlMapFd = bpf_obj_get(THRD_BL_MAP_PATH);
        if (tprofiler.threadBlMapFd < 0) {
            TP_ERROR("Failed to get bpf prog thread blacklist map.\n");
            return -1;
        }
    }

    if (is_load_probe_ipc(ipc_body, TPROFILING_PROBES_WITH_STACK)) {
        if (tprofiler.stackMapAFd <= 0) {
            tprofiler.stackMapAFd = bpf_obj_get(STACK_MAP_A_PATH);
            if (tprofiler.stackMapAFd < 0) {
                TP_ERROR("Failed to get bpf prog stack map.\n");
                return -1;
            }
        }
        if (tprofiler.stackMapBFd <= 0) {
            tprofiler.stackMapBFd = bpf_obj_get(STACK_MAP_B_PATH);
            if (tprofiler.stackMapBFd < 0) {
                TP_ERROR("Failed to get bpf prog stack map b.\n");
                return -1;
            }
        }
        if (tprofiler.pyProcMapFd <= 0) {
            tprofiler.pyProcMapFd = bpf_obj_get(PY_PROC_MAP_PATH);
            if (tprofiler.pyProcMapFd < 0) {
                TP_ERROR("Failed to get bpf prog py_proc map.\n");
                return -1;
            }
        }
        if (tprofiler.pyStackMapAFd <= 0) {
            tprofiler.pyStackMapAFd = bpf_obj_get(PY_STACK_MAP_A_PATH);
            if (tprofiler.pyStackMapAFd < 0) {
                TP_ERROR("Failed to get bpf prog py_stack map a.\n");
                return -1;
            }
        }
        if (tprofiler.pyStackMapBFd <= 0) {
            tprofiler.pyStackMapBFd = bpf_obj_get(PY_STACK_MAP_B_PATH);
            if (tprofiler.pyStackMapBFd < 0) {
                TP_ERROR("Failed to get bpf prog py_stack map b.\n");
                return -1;
            }
        }
	    if (tprofiler.pyHeapMapFd <= 0) {
            tprofiler.pyHeapMapFd = bpf_obj_get(STACK_PY_SAMPLE_HEAP_MAP_PATH);
            if (tprofiler.pyHeapMapFd < 0) {
                TP_ERROR("Failed to get bpf prog py_heap map.\n");
                return -1;
            }
            ret = init_py_sample_heap(tprofiler.pyHeapMapFd);
            if (ret){
                TP_ERROR("Failed to init python sample heap map.\n");
                return -1;
            }
        }
        if (tprofiler.pySymbMapFd <= 0) {
            tprofiler.pySymbMapFd = bpf_obj_get(STACK_PY_SYMBOL_IDS_MAP_PATH);
            if (tprofiler.pySymbMapFd < 0) {
                TP_ERROR("Failed to get bpf prog py_symb map.\n");
                return -1;
            }
        }
    }

    if (is_load_probe_ipc(ipc_body, TPROFILING_PROBE_SYSCALL_ALL)) {
        if (tprofiler.scEnterMapFd <= 0) {
            tprofiler.scEnterMapFd = bpf_obj_get(SYSCALL_ENTER_MAP_PATH);
            if (tprofiler.scEnterMapFd < 0) {
                TP_ERROR("Failed to get bpf prog syscall enter map.\n");
                return -1;
            }
        }
    }

    return 0;
}

// 初始化需要观测的系统调用
static int init_syscall_metas(void)
{
    syscall_meta_t *scm = NULL;

    for (int i = 0; i < sizeof(g_syscall_metas) / sizeof(syscall_meta_t); i++) {
        scm = (syscall_meta_t *)calloc(1, sizeof(syscall_meta_t));
        if (scm == NULL) {
            return -1;
        }
        scm->nr = g_syscall_metas[i].nr;
        scm->flag = g_syscall_metas[i].flag;
        strcpy(scm->name, g_syscall_metas[i].name);
        strcpy(scm->default_type, g_syscall_metas[i].default_type);
        HASH_ADD(hh, tprofiler.scmTable, nr, sizeof(unsigned long), scm);
    }

    return 0;
}

// 针对 Java 程序，加载一个 java agent 用于获取它的符号表
static void java_symb_mgmt(int proc_filter_map_fd)
{
    struct java_attach_args args = {0};
    struct proc_s key = {0};
    struct proc_s next_key = {0};
    char comm[TASK_COMM_LEN];

    if (tprofiler.stackMapAFd <= 0 || tprofiler.stackMapBFd <= 0) {
        return;
    }

    (void)snprintf(args.agent_file_name, FILENAME_LEN, JAVA_SYM_AGENT_FILE);
    (void)snprintf(args.tmp_file_name, FILENAME_LEN, JAVA_SYM_FILE);

    while (bpf_map_get_next_key(proc_filter_map_fd, &key, &next_key) == 0) {
        comm[0] = 0;
        if (!detect_proc_is_java(next_key.proc_id, comm, TASK_COMM_LEN)) {
            key = next_key;
            continue;
        }
        java_offload_jvm_agent(next_key.proc_id);
        if (java_load(next_key.proc_id, &args)) {
            TP_WARN("Failed to load java agent to proc %u\n", next_key.proc_id);
        }
        TP_INFO("Succeed to load java agent to proc %u\n", next_key.proc_id);

        key = next_key;
    }
}

static void clean_map_files(void)
{
    FILE *fp = NULL;

    fp = popen(RM_TPROFILING_MAP_PATH, "r");
    if (fp != NULL) {
        (void)pclose(fp);
    }
}

static void clean_syscall_meta_table(syscall_meta_t **scmTable)
{
    syscall_meta_t *scm;
    syscall_meta_t *tmp;

    HASH_ITER(hh, *scmTable, scm, tmp) {
        HASH_DEL(*scmTable, scm);
        free(scm);
    }

    *scmTable = NULL;
}

static void clean_tprofiler(void)
{
    unload_profiling_bpf_prog();

    if (tprofiler.scmTable) {
        clean_syscall_meta_table(&tprofiler.scmTable);
    }

    if (tprofiler.procTable) {
        free_proc_table(&tprofiler.procTable);
    }

    destroyThreadBlacklist(&tprofiler.thrdBl);

    clean_local_storage(&tprofiler.localStorage);
    clean_proc_link_tbl();

    clean_map_files();
}

static int set_output_dir(char *output_dir)
{
    size_t len;

    if (output_dir == NULL || output_dir[0] == 0) {
        output_dir = DEFAULT_OUTPUT_DIR;
    }

    len = strlen(output_dir);
    if (len <= 1 || len + 48 >= PATH_LEN) { // 48 means the size of file name : "timeline-trace-%s-stack.json.tmp"
        output_dir = DEFAULT_OUTPUT_DIR;
    }

    if (output_dir[len - 1] == '/') {
        (void)snprintf(tprofiler.output_dir, PATH_LEN, "%s", output_dir);
    } else {
        (void)snprintf(tprofiler.output_dir, PATH_LEN, "%s/", output_dir);
    }
    
    if (init_local_storage(&tprofiler.localStorage)) {
        return -1;
    }

    return 0;
}

static int refresh_tprofiler(struct ipc_body_s *ipc_body)
{
    tprofiler.report_period = ipc_body->probe_param.period;

    if (!is_load_probe_ipc(ipc_body, TPROFILING_EBPF_PROBE_ALL)) {
        return 0;
    }

    if (ipc_body->probe_flags & IPC_FLAGS_PARAMS_CHG || ipc_body->probe_flags == 0) {
        if (init_tprofiler_map_fds(ipc_body)) {
            return -1;
        }
        if (set_output_dir(ipc_body->probe_param.output_dir)) {
            return -1;
        }
    }

    if ((ipc_body->probe_flags & IPC_FLAGS_PARAMS_CHG) || (ipc_body->probe_flags & IPC_FLAGS_SNOOPER_CHG) || \
        ipc_body->probe_flags == 0) {
        refresh_proc_filter_map(ipc_body);
        java_symb_mgmt(tprofiler.procFilterMapFd);
    }

    reattach_uprobes(ipc_body);

    return 0;
}

struct _proc_item {
    int pid;
    UT_hash_handle hh;
};

static void add_proc_items(struct _proc_item **proc_tbl, struct ipc_body_s *ipc_body)
{
    struct _proc_item *item;
    int pid;
    int i;

    for (i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        if (ipc_body->snooper_objs[i].type != SNOOPER_OBJ_PROC) {
            continue;
        }
        pid = ipc_body->snooper_objs[i].obj.proc.proc_id;
        HASH_FIND_INT(*proc_tbl, &pid, item);
        if (item == NULL) {
            item = (struct _proc_item *)malloc(sizeof(struct _proc_item));
            if (item == NULL) {
                TP_DEBUG("Failed to add process range, alloc memory failed\n");
                continue;
            }
            item->pid = pid;
            HASH_ADD_INT(*proc_tbl, pid, item);
        }
    }
}

static void clear_proc_items(struct _proc_item **proc_tbl)
{
    struct _proc_item *cur, *tmp;

    HASH_ITER(hh, *proc_tbl, cur, tmp) {
        HASH_DEL(*proc_tbl, cur);
        free(cur);
    }
}

static void refresh_proc_filter_map(struct ipc_body_s *ipc_body)
{
    struct proc_s key = {0};
    struct proc_s next_key = {0};
    struct obj_ref_s val;
    struct obj_ref_s dft_val = {.count = 0};
    struct py_proc_data py_proc_data;
    struct _proc_item *proc_tbl = NULL;
    struct _proc_item *item, *tmp;
    int ret;

    add_proc_items(&proc_tbl, ipc_body);
    while (bpf_map_get_next_key(tprofiler.procFilterMapFd, &key, &next_key) == 0) {
        HASH_FIND_INT(proc_tbl, &next_key.proc_id, item);
        if (item == NULL) {
            (void)bpf_map_delete_elem(tprofiler.procFilterMapFd, &next_key);
            (void)bpf_map_delete_elem(tprofiler.pyProcMapFd, &next_key.proc_id);
        }
        key = next_key;
    }

    item = NULL;
    HASH_ITER(hh, proc_tbl, item, tmp) {
        key.proc_id = item->pid;
        if (bpf_map_lookup_elem(tprofiler.procFilterMapFd, &key, &val) == 0) {
            continue;
        }
        // new process to observe
        ret = bpf_map_update_elem(tprofiler.procFilterMapFd, &key, &dft_val, BPF_ANY);
        if (ret != 0) {
            TP_DEBUG("Failed to add new process to proc filter map(pid=%u)\n", key.proc_id);
            continue;
        }

        if(try_init_py_proc_data(key.proc_id, &py_proc_data)){
            continue;
        }
        ret = bpf_map_update_elem(tprofiler.pyProcMapFd, &key.proc_id, &py_proc_data, BPF_ANY);
        if (ret != 0) {
            TP_DEBUG("Failed to add new python process to python proc filter map(pid=%u)\n", key.proc_id);
            continue;
        }
    }

    clear_proc_items(&proc_tbl);
}

static int gen_trace_path(struct local_store_s *local_storage)
{
    time_t now;
    struct tm *tm;
    size_t sz;
    int ret;
    char timestamp[TASK_COMM_LEN];

    now = time(NULL);
    tm = localtime(&now);
    sz = strftime(timestamp, sizeof(timestamp), "%Y%m%d%H%M", tm);
    if (sz == 0) {
        return -1;
    }

    ret = snprintf(local_storage->trace_path, sizeof(local_storage->trace_path), "%stimeline-trace-%s.json", tprofiler.output_dir, timestamp);
    if (ret < 0 || ret >= sizeof(local_storage->trace_path)) {
        return -1;
    }

    ret = snprintf(local_storage->trace_path_tmp, sizeof(local_storage->trace_path_tmp),
        "%s.tmp", local_storage->trace_path);
    if (ret < 0 || ret >= sizeof(local_storage->trace_path_tmp)) {
        return -1;
    }

    ret = snprintf(local_storage->stack_path_tmp, sizeof(local_storage->stack_path_tmp), "%stimeline-trace-%s-stack.json.tmp", tprofiler.output_dir, timestamp);
    if (ret < 0 || ret >= sizeof(local_storage->stack_path_tmp)) {
        return -1;
    }

    return 0;
}

void clean_local_storage(struct local_store_s *local_storage);

int init_local_storage(struct local_store_s *local_storage)
{
    int ret;

    (void)memset(local_storage, 0, sizeof(*local_storage));
    local_storage->stack_root = (struct stack_node_s *)calloc(1, sizeof(struct stack_node_s));
    if (local_storage->stack_root == NULL) {
        TP_ERROR("Failed to allocate stack root\n");
        return -1;
    }

    if (gen_trace_path(local_storage)) {
        TP_ERROR("Failed to gen_trace_path\n");
        goto err;
    }
    if (access(tprofiler.output_dir, F_OK)) {
        ret = mkdir(tprofiler.output_dir, 0700);
        if (ret) {
            TP_ERROR("Failed to create trace dir:%s, ret=%d\n", tprofiler.output_dir, ret);
            goto err;
        }
        TP_INFO("Succeed to create trace dir:%s\n", tprofiler.output_dir);
    }

    local_storage->fp = fopen(local_storage->trace_path_tmp, "w+");
    if (local_storage->fp == NULL) {
        TP_ERROR("Failed to create tmp trace file:%s\n", local_storage->trace_path_tmp);
        goto err;
    }
    local_storage->stack_fp = fopen(local_storage->stack_path_tmp, "w+");
    if (local_storage->stack_fp == NULL) {
        TP_ERROR("Failed to create tmp stack trace file:%s\n", local_storage->stack_path_tmp);
        goto err;
    }

    TP_INFO("Succeed to create tmp trace file:%s\n", local_storage->trace_path_tmp);
    return 0;
err:
    clean_local_storage(local_storage);
    return -1;
}

void init_pb_mgmt(PerfBufferMgmt *pbMgmt)
{
    pbMgmt->is_pb_a = 1;
    pbMgmt->perf_buffer_a = NULL;
    pbMgmt->perf_buffer_b = NULL;
    (void)time(&pbMgmt->pb_switch_timer);
}

void clean_local_storage(struct local_store_s *local_storage)
{
    if (local_storage->fp != NULL) {
        fclose(local_storage->fp);
        local_storage->fp = NULL;
    }
    if (local_storage->stack_fp != NULL) {
        fclose(local_storage->stack_fp);
        local_storage->stack_fp = NULL;
    }
    if (local_storage->stack_root) {
        cleanup_stack_tree(local_storage->stack_root);
        local_storage->stack_root = NULL;
        local_storage->stack_node_num = 0;
    }
    if (local_storage->proc_meta_written) {
        cleanup_proc_meta(local_storage->proc_meta_written);
        local_storage->proc_meta_written = NULL;
    }
    if (local_storage->trace_path_tmp[0] != '\0') {
        (void)remove(local_storage->trace_path_tmp);
        local_storage->trace_path_tmp[0] = '\0';
    }
    if (local_storage->stack_path_tmp[0] != '\0') {
        (void)remove(local_storage->stack_path_tmp);
        local_storage->stack_path_tmp[0] = '\0';
    }
    (void)memset(local_storage, 0, sizeof(*local_storage));
}
