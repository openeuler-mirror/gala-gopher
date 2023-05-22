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
#include "args.h"
#include "profiling_event.h"
#include "java_support.h"
#include "bpf_prog.h"
#include "tprofiling.h"

Tprofiler tprofiler;

static struct probe_params g_params;
static volatile sig_atomic_t stop = 0;

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
    {SYSCALL_WAITPID_ID, SYSCALL_WAITPID_NAME, SYSCALL_FLAG_STACK, PROFILE_EVT_TYPE_SCHED},
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

static void sig_int(int signal);
static int init_tprofiler();
static int init_tprofiler_map_fds();
static int init_setting_map(int setting_map_fd);
static int init_proc_thrd_filter();
static int init_proc_filter_map(int proc_filter_map_fd);
static int init_syscall_metas();
static void init_java_symb_mgmt(int proc_filter_map_fd);
static void unload_java_symb_mgmt(int proc_filter_map_fd);
static void clean_map_files();
static void clean_tprofiler();

int main(int argc, char **argv)
{
    int err = -1;
    struct bpf_prog_s *syscall_bpf_progs = NULL;
    struct bpf_prog_s *oncpu_bpf_progs = NULL;

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        return -1;
    }

    err = args_parse(argc, argv, &g_params);
    if (err != 0) {
        return -1;
    }

    if (init_tprofiler()) {
        return -1;
    }

    clean_map_files();

    INIT_BPF_APP(tprofiling, EBPF_RLIM_LIMITED);

    syscall_bpf_progs = load_syscall_bpf_prog(&g_params);
    if (syscall_bpf_progs == NULL) {
        goto cleanup;
    }

    oncpu_bpf_progs = load_oncpu_bpf_prog(&g_params);
    if (oncpu_bpf_progs == NULL) {
        goto cleanup;
    }

    if (init_tprofiler_map_fds()) {
        goto cleanup;
    }

    err = init_setting_map(tprofiler.settingMapFd);
    if (err) {
        fprintf(stderr, "ERROR: init bpf prog setting failed.\n");
        goto cleanup;
    }

    // 如果本地指定了进程过滤参数，则使用本地 map 进行过滤；否则使用全局共享的进程 map 过滤
    if (tprofiler.filterLocal) {
        err = init_proc_filter_map(tprofiler.procFilterMapFd);
        if (err) {
            fprintf(stderr, "ERROR: init bpf process filter failed.\n");
            goto cleanup;
        }
    }

    if (tprofiler.stackMapFd > 0) {
        init_java_symb_mgmt(tprofiler.procFilterMapFd);
    }

    while (!stop) {
        if (syscall_bpf_progs->pb != NULL) {
            if (perf_buffer__poll(syscall_bpf_progs->pb, THOUSAND) < 0) {
                goto cleanup;
            }
        }
        if (oncpu_bpf_progs->pb != NULL) {
            if (perf_buffer__poll(oncpu_bpf_progs->pb, THOUSAND) < 0) {
                goto cleanup;
            }
        }
    }

cleanup:
    unload_bpf_prog(&syscall_bpf_progs);
    unload_bpf_prog(&oncpu_bpf_progs);
    clean_tprofiler();
    clean_map_files();
    if (tprofiler.stackMapFd > 0) {
        unload_java_symb_mgmt(tprofiler.procFilterMapFd);
    }
    return -err;
}

static void sig_int(int signal)
{
    stop = 1;
}

static int init_tprofiler()
{
    if (init_proc_thrd_filter()) {
        fprintf(stderr, "ERROR: init process/thread filter failed.\n");
        return -1;
    }

    if (init_sys_boot_time(&tprofiler.sysBootTime)) {
        fprintf(stderr, "ERROR: get system boot time failed.\n");
        return -1;
    }

    if (init_syscall_metas()) {
        fprintf(stderr, "ERROR: init syscall meta info failed.\n");
        return -1;
    }

    return 0;
}

static int init_tprofiler_map_fds()
{
    tprofiler.settingMapFd = bpf_obj_get(SETTING_MAP_PATH);
    if (tprofiler.settingMapFd < 0) {
        fprintf(stderr, "ERROR: get bpf prog setting map failed.\n");
        return -1;
    }

    tprofiler.procFilterMapFd = bpf_obj_get(PROC_MAP_PATH);
    if (tprofiler.filterLocal) {
        tprofiler.procFilterMapFd = bpf_obj_get(PROC_FILTER_MAP_PATH);
    }
    if (tprofiler.procFilterMapFd < 0) {
        fprintf(stderr, "ERROR: get bpf prog process filter map failed.\n");
        return -1;
    }

    tprofiler.threadBlMapFd = bpf_obj_get(THRD_BL_MAP_PATH);
    if (tprofiler.threadBlMapFd < 0) {
        fprintf(stderr, "ERROR: get bpf prog thread blacklist map failed.\n");
        return -1;
    }

    if ((g_params.load_probe & TPROFILING_PROBE_SYSCALL_ALL)) {
        tprofiler.stackMapFd = bpf_obj_get(STACK_MAP_PATH);
        if (tprofiler.stackMapFd < 0) {
            fprintf(stderr, "ERROR: get bpf prog stack map failed.\n");
            return -1;
        }
    }

    return 0;
}

// 初始化 bpf 程序的全局配置项
static int init_setting_map(int setting_map_fd)
{
    __u32 key = 0;
    profiling_setting_t ps = {0};
    long ret;

    ps.inited = 1;
    ps.filter_local = tprofiler.filterLocal;

    ret = bpf_map_update_elem(setting_map_fd, &key, &ps, BPF_ANY);
    if (ret) {
        return -1;
    }

    return 0;
}

// 初始化进程/线程过滤参数
static int init_proc_thrd_filter()
{
    int ret;

    if (g_params.tgids != NULL && g_params.tgids[0] != '\0') {
        tprofiler.filterLocal = 1;
    }

    ret = initThreadBlacklist(&tprofiler.thrdBl);
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
static int init_syscall_metas()
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

// 创建一个子线程，针对 Java 程序，定期更新它的符号表
static void init_java_symb_mgmt(int proc_filter_map_fd)
{
    int ret;
    pthread_t thd;
    struct java_attach_args args = {0};

    args.proc_obj_map_fd = proc_filter_map_fd;
    args.is_only_attach_once = 1;
    args.loop_period = DEFAULT_PERIOD;
    (void)snprintf(args.agent_file_name, FILENAME_LEN, JAVA_SYM_AGENT_FILE);
    (void)snprintf(args.tmp_file_name, FILENAME_LEN, JAVA_SYM_FILE);

    ret = pthread_create(&thd, NULL, java_support, (void *)&args);
    if (ret) {
        fprintf(stderr, "ERROR: Failed to create java support thread.\n");
        return;
    }
    (void)pthread_detach(thd);
    printf("INFO: java support thread sucessfully started.\n");
}

static void unload_java_symb_mgmt(int proc_filter_map_fd)
{
    struct java_attach_args args = {0};
    args.proc_obj_map_fd = proc_filter_map_fd;
    (void)snprintf(args.agent_file_name, FILENAME_LEN, JAVA_SYM_AGENT_FILE);
    (void)snprintf(args.tmp_file_name, FILENAME_LEN, JAVA_SYM_FILE);

    java_unload(&args);
    printf("INFO: unload java agent sucessfully!\n");
}

static void clean_map_files()
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

static void clean_tprofiler()
{
    if (tprofiler.scmTable) {
        clean_syscall_meta_table(&tprofiler.scmTable);
    }

    if (tprofiler.procTable) {
        free_proc_table(&tprofiler.procTable);
    }

    destroyThreadBlacklist(&tprofiler.thrdBl);
}