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
#include <linux/limits.h>
#include <pthread.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "syscall.skel.h"
#include "args.h"
#include "profiling_event.h"
#include "java_support.h"
#include "tprofiling.h"

#define SYSCALL_FLAG_FD_STACK (0 | SYSCALL_FLAG_FD | SYSCALL_FLAG_STACK)

syscall_meta_t *g_syscall_meta_table = NULL;
int g_stackmap_fd = 0;

static int g_filter_local = 0;

static struct probe_params g_params = {
    .period = DEFAULT_PERIOD
};

static syscall_meta_t g_syscall_metas[] = {
    // file
    {SYSCALL_READ_ID, SYSCALL_READ_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_FILE},
    {SYSCALL_WRITE_ID, SYSCALL_WRITE_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_FILE},
    {SYSCALL_READV_ID, SYSCALL_READV_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_FILE},
    {SYSCALL_WRITEV_ID, SYSCALL_WRITE_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_FILE},
    {SYSCALL_PREADV_ID, SYSCALL_PREADV_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_FILE},
    {SYSCALL_PWRITEV_ID, SYSCALL_PWRITEV_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_FILE},
    {SYSCALL_PREADV2_ID, SYSCALL_PREADV2_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_FILE},
    {SYSCALL_PWRITEV2_ID, SYSCALL_PWRITEV2_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_FILE},
    {SYSCALL_SYNC_ID, SYSCALL_SYNC_NAME, 0, PROFILE_EVT_TYPE_OTHER},
    {SYSCALL_FSYNC_ID, SYSCALL_FSYNC_NAME, SYSCALL_FLAG_FD, PROFILE_EVT_TYPE_FILE},
    {SYSCALL_FDATASYNC_ID, SYSCALL_FDATASYNC_NAME, SYSCALL_FLAG_FD, PROFILE_EVT_TYPE_FILE},
    {SYSCALL_SYNCFS_ID, SYSCALL_SYNCFS_NAME, SYSCALL_FLAG_FD, PROFILE_EVT_TYPE_FILE},
    {SYSCALL_MSYNC_ID, SYSCALL_MSYNC_NAME, 0, PROFILE_EVT_TYPE_OTHER},
    // process
    {SYSCALL_SCHED_YIELD_ID, SYSCALL_SCHED_YIELD_NAME, 0, PROFILE_EVT_TYPE_PROC},
    {SYSCALL_PAUSE_ID, SYSCALL_PAUSE_NAME, 0, PROFILE_EVT_TYPE_PROC},
    {SYSCALL_NANOSLEEP_ID, SYSCALL_NANOSLEEP_NAME, 0, PROFILE_EVT_TYPE_PROC},
    {SYSCALL_CLOCK_NANOSLEEP_ID, SYSCALL_CLOCK_NANOSLEEP_NAME, 0, PROFILE_EVT_TYPE_PROC},
    {SYSCALL_WAIT4_ID, SYSCALL_WAIT4_NAME, 0, PROFILE_EVT_TYPE_PROC},
    {SYSCALL_WAITPID_ID, SYSCALL_WAITPID_NAME, 0, PROFILE_EVT_TYPE_PROC},
    // network
    {SYSCALL_SENDTO_ID, SYSCALL_SENDTO_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_NET},
    {SYSCALL_RECVFROM_ID, SYSCALL_RECVFROM_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_NET},
    {SYSCALL_SENDMSG_ID, SYSCALL_SENDMSG_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_NET},
    {SYSCALL_RECVMSG_ID, SYSCALL_RECVMSG_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_NET},
    {SYSCALL_SENDMMSG_ID, SYSCALL_SENDMMSG_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_NET},
    {SYSCALL_RECVMMSG_ID, SYSCALL_RECVMMSG_NAME, SYSCALL_FLAG_FD_STACK, PROFILE_EVT_TYPE_NET},
    {SYSCALL_SENDFILE_ID, SYSCALL_SENDFILE_NAME, 0, PROFILE_EVT_TYPE_NET},
    {SYSCALL_SELECT_ID, SYSCALL_SELECT_NAME, 0, PROFILE_EVT_TYPE_OTHER},
    {SYSCALL_PSELECT6_ID, SYSCALL_PSELECT6_NAME, 0, PROFILE_EVT_TYPE_OTHER},
    {SYSCALL_POLL_ID, SYSCALL_POLL_NAME, 0, PROFILE_EVT_TYPE_OTHER},
    {SYSCALL_PPOLL_ID, SYSCALL_PPOLL_NAME, 0, PROFILE_EVT_TYPE_OTHER},
    {SYSCALL_EPOLL_WAIT_ID, SYSCALL_EPOLL_WAIT_NAME, 0, PROFILE_EVT_TYPE_OTHER},
    {SYSCALL_EPOLL_CTL_ID, SYSCALL_EPOLL_CTL_NAME, 0, PROFILE_EVT_TYPE_OTHER},
    // IPC
    {SYSCALL_SEMOP_ID, SYSCALL_SEMOP_NAME, 0, PROFILE_EVT_TYPE_IPC},
    {SYSCALL_MSGSND_ID, SYSCALL_MSGSND_NAME, 0, PROFILE_EVT_TYPE_IPC},
    {SYSCALL_MSGRCV_ID, SYSCALL_MSGRCV_NAME, 0, PROFILE_EVT_TYPE_IPC},
    {SYSCALL_RT_SIGTIMEDWAIT_ID, SYSCALL_RT_SIGTIMEDWAIT_NAME, 0, PROFILE_EVT_TYPE_IPC},
    {SYSCALL_RT_SIGSUSPEND_ID, SYSCALL_RT_SIGSUSPEND_NAME, 0, PROFILE_EVT_TYPE_IPC},
    {SYSCALL_MQ_TIMEDSEND_ID, SYSCALL_MQ_TIMEDSEND_NAME, 0, PROFILE_EVT_TYPE_IPC},
    {SYSCALL_MQ_TIMEDRECEIVE_ID, SYSCALL_MQ_TIMEDRECEIVE_NAME, 0, PROFILE_EVT_TYPE_IPC},
    {SYSCALL_FUTEX_ID, SYSCALL_FUTEX_NAME, SYSCALL_FLAG_STACK, PROFILE_EVT_TYPE_FUTEX},
    // log
    {SYSCALL_SYSLOG_ID, SYSCALL_SYSLOG_NAME, 0, PROFILE_EVT_TYPE_OTHER}
};

static int init_setting_map(int setting_map_fd);
static int init_proc_filter_map(int proc_filter_map_fd);
static int init_syscall_table_map(int syscall_table_fd);
static void init_java_symb_mgmt(int proc_filter_map_fd);
static void perf_event_handler(void *ctx, int cpu, void *data, __u32 size);
static void clean_syscall_meta_table();

int main(int argc, char **argv)
{
    int err = -1;
    int evt_map_fd = 0;
    int proc_filter_map_fd = 0;
    struct perf_buffer *pb = NULL;

    err = args_parse(argc, argv, &g_params);
    if (err != 0) {
        return -1;
    }

    if (g_params.tgids != NULL && g_params.tgids[0] != '\0') {
        g_filter_local = 1;
    }

    if (init_sys_boot_time()) {
        fprintf(stderr, "ERROR: get system boot time failed.\n");
        return -1;
    }

    INIT_BPF_APP(tprofiling, EBPF_RLIM_LIMITED);
    LOAD(syscall, cleanup);

    err = init_setting_map(GET_MAP_FD(syscall, setting_map));
    if (err) {
        fprintf(stderr, "ERROR: init bpf prog setting failed.\n");
        goto cleanup;
    }

    // 如果本地指定了进程过滤参数，则使用本地 map 进行过滤；否则使用全局共享的进程 map 过滤
    if (g_filter_local) {
        err = init_proc_filter_map(GET_MAP_FD(syscall, proc_filter_map));
        if (err) {
            fprintf(stderr, "ERROR: init bpf process filter failed.\n");
            goto cleanup;
        }
        proc_filter_map_fd = GET_MAP_FD(syscall, proc_filter_map);
    } else {
        proc_filter_map_fd = GET_MAP_FD(syscall, proc_obj_map);
    }

    init_java_symb_mgmt(proc_filter_map_fd);

    err = init_syscall_table_map(GET_MAP_FD(syscall, syscall_table_map));
    if (err) {
        fprintf(stderr, "ERROR: init bpf syscall table failed.\n");
        goto cleanup;
    }

    g_stackmap_fd = GET_MAP_FD(syscall, stack_map);

    evt_map_fd = GET_MAP_FD(syscall, event_map);
    pb = create_pref_buffer(evt_map_fd, perf_event_handler);
    if (pb == NULL) {
        fprintf(stderr, "ERROR: create perf buffer failed.\n");
        goto cleanup;
    }
    poll_pb(pb, g_params.period * THOUSAND);

cleanup:
    UNLOAD(syscall);
    if (pb) {
        perf_buffer__free(pb);
    }
    if (g_syscall_meta_table) {
        clean_syscall_meta_table();
    }
    return -err;
}

// 初始化 bpf 程序的全局配置项
static int init_setting_map(int setting_map_fd)
{
    __u32 key = 0;
    profiling_setting_t ps = {0};
    long ret;

    ps.filter_local = g_filter_local;

    ret = bpf_map_update_elem(setting_map_fd, &key, &ps, BPF_ANY);
    if (ret) {
        return -1;
    }

    return 0;
}

// 从探针命令行参数 `-f tgid1,tgid2,tgid3` 中解析需要观测的进程范围
static int init_proc_filter_map(int proc_filter_map_fd)
{
    char *token;
    int tgid;
    struct proc_s key = {0};
    struct obj_ref_s val = {.count = 0};
    int ret;

    if (g_params.tgids == NULL || g_params.tgids[0] == '\0') {
        return 0;
    }

    token = strtok(g_params.tgids, ",");
    while (token != NULL) {
        tgid = atoi(token);
        if (tgid <= 0) {
            fprintf(stderr, "ERROR: invalid process filter parameter: %s.\n", g_params.tgids);
            return -1;
        }

        key.proc_id = tgid;
        ret = bpf_map_update_elem(proc_filter_map_fd, &key, &val, BPF_ANY);
        if (ret) {
            fprintf(stderr, "ERROR: add tgid %d to process filter map failed.\n", tgid);
            return -1;
        }

        token = strtok(NULL, ",");
    }

    return 0;
}

// 初始化需要观测的系统调用
static int init_syscall_table_map(int syscall_table_fd)
{
    syscall_m_meta_t scm = {0};
    syscall_meta_t *scm_ptr = NULL;
    long ret;

    for (int i = 0; i < sizeof(g_syscall_metas) / sizeof(syscall_meta_t); i++) {
        scm.nr = g_syscall_metas[i].nr;
        scm.flag = g_syscall_metas[i].flag;

        ret = bpf_map_update_elem(syscall_table_fd, &scm.nr, &scm, BPF_ANY);
        if (ret) {
            return -1;
        }

        scm_ptr = (syscall_meta_t *)calloc(1, sizeof(syscall_meta_t));
        if (scm_ptr == NULL) {
            return -1;
        }
        scm_ptr->nr = g_syscall_metas[i].nr;
        scm_ptr->flag = g_syscall_metas[i].flag;
        strcpy(scm_ptr->name, g_syscall_metas[i].name);
        strcpy(scm_ptr->default_type, g_syscall_metas[i].default_type);
        HASH_ADD(hh, g_syscall_meta_table, nr, sizeof(unsigned long), scm_ptr);
    }

    return 0;
}

// 创建一个子线程，针对 Java 程序，定期更新它的符号表
static void init_java_symb_mgmt(int proc_filter_map_fd)
{
    int ret;
    pthread_t thd;

    ret = pthread_create(&thd, NULL, java_support, (void *)&proc_filter_map_fd);
    if (ret) {
        fprintf(stderr, "ERROR: Failed to create java support thread.\n");
        return;
    }
    printf("INFO: java support thread sucessfully started.\n");
}

static void perf_event_handler(void *ctx, int cpu, void *data, __u32 size)
{
    output_profiling_event((trace_event_data_t *)data);
}

static void clean_syscall_meta_table()
{
    syscall_meta_t *scm;
    syscall_meta_t *tmp;

    HASH_ITER(hh, g_syscall_meta_table, scm, tmp) {
        HASH_DEL(g_syscall_meta_table, scm);
        free(scm);
    }
}