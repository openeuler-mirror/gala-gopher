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
#include "syscall.h"
#include "tprofiling.h"
Tprofiler tprofiler;

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

static int __poll_pb(struct bpf_prog_s* prog)
{
    int ret;

    for (int i = 0; i < prog->num && i < SKEL_MAX_NUM; i++) {
        if (prog->buffers[i]) {
            ret = bpf_buffer__poll(prog->buffers[i], THOUSAND);
            if (ret < 0 && ret != -EINTR) {
                return ret;
            }
        }
    }

    return 0;
}
static int init_py_sample_heap(int map_fd)
{
    u32 nr_cpus = NR_CPUS;
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
int main(int argc, char **argv)
{
    int err = -1;
    struct bpf_prog_s *syscall_bpf_progs = NULL;
    struct bpf_prog_s *oncpu_bpf_progs = NULL;
    struct ipc_body_s ipc_body;
    int msq_id;

    if (signal(SIGINT, sig_handling) == SIG_ERR) {
        TP_ERROR("Can't set signal handler: %s\n", strerror(errno));
        return -1;
    }
    if (signal(SIGTERM, sig_handling) == SIG_ERR) {
        TP_ERROR("Can't set signal handler: %s\n", strerror(errno));
        return -1;
    }

    msq_id = create_ipc_msg_queue(IPC_EXCL);
    if (msq_id < 0) {
        return -1;
    }

    if (init_tprofiler()) {
        return -1;
    }

    clean_map_files();

    INIT_BPF_APP(tprofiling, EBPF_RLIM_LIMITED);

    TP_INFO("Tprofiling probe start successfully.\n");

    while (!stop) {
        err = recv_ipc_msg(msq_id, (long)PROBE_TP, &ipc_body);
        if (err == 0) {
            if (ipc_body.probe_flags & IPC_FLAGS_PARAMS_CHG || ipc_body.probe_flags == 0) {
                unload_bpf_prog(&syscall_bpf_progs);
                unload_bpf_prog(&oncpu_bpf_progs);

                syscall_bpf_progs = load_syscall_bpf_prog(&ipc_body);
                if (syscall_bpf_progs == NULL) {
                    goto cleanup;
                }
                oncpu_bpf_progs = load_oncpu_bpf_prog(&ipc_body);
                if (oncpu_bpf_progs == NULL) {
                    goto cleanup;
                }
            }

            if (refresh_tprofiler(&ipc_body)) {
                goto cleanup;
            }
            destroy_ipc_body(&g_ipc_body);
            (void)memcpy(&g_ipc_body, &ipc_body, sizeof(g_ipc_body));
        }

        if (syscall_bpf_progs == NULL && oncpu_bpf_progs == NULL) {
            sleep(DEFAULT_PERIOD);
            continue;
        }
        if (__poll_pb(syscall_bpf_progs)) {
            goto cleanup;
        }

        if (__poll_pb(oncpu_bpf_progs)) {
            goto cleanup;
        }
    }

    TP_INFO("Tprofiling probe closed.\n");
cleanup:
    unload_bpf_prog(&syscall_bpf_progs);
    unload_bpf_prog(&oncpu_bpf_progs);
    clean_tprofiler();
    clean_map_files();
    destroy_ipc_body(&g_ipc_body);
    return -err;
}

static void sig_handling(int signal)
{
    stop = 1;
}

static int init_tprofiler(void)
{
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

    return 0;
}

static int init_tprofiler_map_fds(struct ipc_body_s *ipc_body)
{
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

    if ((ipc_body->probe_range_flags & TPROFILING_PROBE_SYSCALL_ALL)) {
        if (tprofiler.stackMapFd <= 0) {
            tprofiler.stackMapFd = bpf_obj_get(STACK_MAP_PATH);
            if (tprofiler.stackMapFd < 0) {
                TP_ERROR("Failed to get bpf prog stack map.\n");
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
        if (tprofiler.pyStackMapFd <= 0) {
            tprofiler.pyStackMapFd = bpf_obj_get(PY_STACK_MAP_PATH);
            if (tprofiler.pyStackMapFd < 0) {
                TP_ERROR("Failed to get bpf prog py_stack map.\n");
                return -1;
            }
        }
	    if (tprofiler.pyHeapMapFd <= 0) {
            tprofiler.pyHeapMapFd = bpf_obj_get(STACK_PY_SAMPLE_HEAP_MAP_PATH);
            if (tprofiler.pyHeapMapFd < 0) {
                TP_ERROR("Failed to get bpf prog py_heap map.\n");
                return -1;
            }
            int ret = init_py_sample_heap(tprofiler.pyHeapMapFd);
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
    } else {
        tprofiler.stackMapFd = 0;
        tprofiler.pyProcMapFd = 0;
        tprofiler.pyStackMapFd = 0;
        tprofiler.pySymbMapFd = 0;
        tprofiler.pyHeapMapFd = 0;
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

    if (tprofiler.stackMapFd <= 0) {
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
    if (tprofiler.scmTable) {
        clean_syscall_meta_table(&tprofiler.scmTable);
    }

    if (tprofiler.procTable) {
        free_proc_table(&tprofiler.procTable);
    }

    destroyThreadBlacklist(&tprofiler.thrdBl);
}

static int refresh_tprofiler(struct ipc_body_s *ipc_body)
{
    tprofiler.report_period = ipc_body->probe_param.period;

    if (ipc_body->probe_flags & IPC_FLAGS_PARAMS_CHG || ipc_body->probe_flags == 0) {
        if (init_tprofiler_map_fds(ipc_body)) {
            return -1;
        }
    }

    if (ipc_body->probe_flags & IPC_FLAGS_SNOOPER_CHG || ipc_body->probe_flags == 0) {
        refresh_proc_filter_map(ipc_body);
        java_symb_mgmt(tprofiler.procFilterMapFd);
    }

    return 0;
}

static void refresh_proc_filter_map(struct ipc_body_s *ipc_body)
{
    struct proc_s key = {0};
    struct proc_s next_key = {0};
    struct obj_ref_s val = {.count = 0};
    struct py_proc_data py_proc_data;
    u32 i;

    while (bpf_map_get_next_key(tprofiler.procFilterMapFd, &key, &next_key) == 0) {
        (void)bpf_map_delete_elem(tprofiler.procFilterMapFd, &next_key);
        key = next_key;
    }

    for (i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        if (ipc_body->snooper_objs[i].type != SNOOPER_OBJ_PROC) {
            continue;
        }
        key.proc_id = ipc_body->snooper_objs[i].obj.proc.proc_id;
        (void)bpf_map_update_elem(tprofiler.procFilterMapFd, &key, &val, BPF_ANY);

        if(try_init_py_proc_data(key.proc_id, &py_proc_data)){
            continue;
        }
        (void)bpf_map_update_elem(tprofiler.pyProcMapFd, &key.proc_id, &py_proc_data, BPF_ANY);
    }
}