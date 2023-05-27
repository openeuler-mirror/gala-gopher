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
#include "ipc.h"
#include "profiling_event.h"
#include "java_support.h"
#include "bpf_prog.h"
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

static void sig_handling(int signal);
static int init_tprofiler();
static int init_tprofiler_map_fds(struct ipc_body_s *ipc_body);
static int init_syscall_metas();
static void init_java_symb_mgmt(int proc_filter_map_fd);
static void unload_java_symb_mgmt(int proc_filter_map_fd);
static void clean_java_symb_mgmt();
static void clean_map_files();
static void clean_tprofiler();
static int refresh_tprofiler(struct ipc_body_s *ipc_body);
static void refresh_proc_filter_map(struct ipc_body_s *ipc_body);

int main(int argc, char **argv)
{
    int err = -1;
    struct bpf_prog_s *syscall_bpf_progs = NULL;
    struct bpf_prog_s *oncpu_bpf_progs = NULL;
    struct ipc_body_s ipc_body;
    int msq_id;

    if (signal(SIGINT, sig_handling) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        return -1;
    }
    if (signal(SIGTERM, sig_handling) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
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

    while (!stop) {
        err = recv_ipc_msg(msq_id, (long)PROBE_TP, &ipc_body);
        if (err == 0) {
            clean_java_symb_mgmt();
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

            destroy_ipc_body(&g_ipc_body);
            (void)memcpy(&g_ipc_body, &ipc_body, sizeof(g_ipc_body));

            if (refresh_tprofiler(&g_ipc_body)) {
                goto cleanup;
            }
        }

        if (syscall_bpf_progs == NULL && oncpu_bpf_progs == NULL) {
            sleep(DEFAULT_PERIOD);
            continue;
        }

        if (syscall_bpf_progs && syscall_bpf_progs->pb != NULL) {
            if (perf_buffer__poll(syscall_bpf_progs->pb, THOUSAND) < 0) {
                goto cleanup;
            }
        }
        if (oncpu_bpf_progs && oncpu_bpf_progs->pb != NULL) {
            if (perf_buffer__poll(oncpu_bpf_progs->pb, THOUSAND) < 0) {
                goto cleanup;
            }
        }
    }

cleanup:
    clean_java_symb_mgmt();
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

static int init_tprofiler()
{
    if (initThreadBlacklist(&tprofiler.thrdBl)) {
        fprintf(stderr, "ERROR: init thread blacklist failed.\n");
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

static int init_tprofiler_map_fds(struct ipc_body_s *ipc_body)
{
    if (tprofiler.procFilterMapFd <= 0) {
        tprofiler.procFilterMapFd = bpf_obj_get(PROC_FILTER_MAP_PATH);
        if (tprofiler.procFilterMapFd < 0) {
            fprintf(stderr, "ERROR: get bpf prog process filter map failed.\n");
            return -1;
        }
    }

    if (tprofiler.threadBlMapFd <= 0) {
        tprofiler.threadBlMapFd = bpf_obj_get(THRD_BL_MAP_PATH);
        if (tprofiler.threadBlMapFd < 0) {
            fprintf(stderr, "ERROR: get bpf prog thread blacklist map failed.\n");
            return -1;
        }
    }

    if ((ipc_body->probe_range_flags & TPROFILING_PROBE_SYSCALL_ALL)) {
        if (tprofiler.stackMapFd <= 0) {
            tprofiler.stackMapFd = bpf_obj_get(STACK_MAP_PATH);
            if (tprofiler.stackMapFd < 0) {
                fprintf(stderr, "ERROR: get bpf prog stack map failed.\n");
                return -1;
            }
        }
    } else {
        tprofiler.stackMapFd = 0;
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
    tprofiler.javaSymbThrd = thd;
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

static int refresh_tprofiler(struct ipc_body_s *ipc_body)
{
    if (init_tprofiler_map_fds(ipc_body)) {
        return -1;
    }

    refresh_proc_filter_map(ipc_body);

    if (tprofiler.stackMapFd > 0) {
        init_java_symb_mgmt(tprofiler.procFilterMapFd);
    }

    return 0;
}

static void clean_java_symb_mgmt()
{
    if (tprofiler.javaSymbThrd > 0) {
        unload_java_symb_mgmt(tprofiler.procFilterMapFd);
        if (pthread_cancel(tprofiler.javaSymbThrd)) {
            fprintf(stderr, "ERROR: failed to cancel java symbol management thread\n");
        } else {
            pthread_join(tprofiler.javaSymbThrd, NULL);
            printf("INFO: succeed to close java symbol management thread\n");
        }
        tprofiler.javaSymbThrd = 0;
    }
}

static void refresh_proc_filter_map(struct ipc_body_s *ipc_body)
{
    struct proc_s key = {0};
    struct proc_s next_key = {0};
    struct obj_ref_s val = {.count = 0};
    int i;

    while (bpf_map_get_next_key(tprofiler.procFilterMapFd, &key, &next_key) != -1) {
        (void)bpf_map_delete_elem(tprofiler.procFilterMapFd, &next_key);
        key = next_key;
    }

    for (i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        if (ipc_body->snooper_objs[i].type != SNOOPER_OBJ_PROC) {
            continue;
        }

        key.proc_id = ipc_body->snooper_objs[i].obj.proc.proc_id;
        (void)bpf_map_update_elem(tprofiler.procFilterMapFd, &key, &val, BPF_ANY);
    }
}