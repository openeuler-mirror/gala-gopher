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
 * Author: sinever
 * Create: 2021-10-25
 * Description: task_probe user prog
 ******************************************************************************/
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/resource.h>
#include <dirent.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "args.h"
#include "ipc.h"
#include "bpf_prog.h"
#include "proc.h"
#include "thread.h"
#include "task_args.h"

#define RM_TASK_MAP_PATH "/usr/bin/rm -rf /sys/fs/bpf/gala-gopher/__taskprobe*"

static struct task_probe_s g_task_probe;
static volatile sig_atomic_t stop = 0;

static void sig_int(int signal)
{
    stop = 1;
}

static void load_task_args(int fd, struct probe_params *params)
{
    u32 key = 0;
    struct task_args_s args = {0};

    args.report_period = NS(params->period);
    args.offline_thr = (u64)params->offline_thr * 1000 * 1000;
    (void)bpf_map_update_elem(fd, &key, &args, BPF_ANY);
}

static void load_task_snoopers(int fd, struct ipc_body_s *ipc_body)
{
    u32 key = 0;
    struct proc_data_s proc = {0};

    if (fd <= 0) {
        return;
    }

    for (int i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        if (ipc_body->snooper_objs[i].type == SNOOPER_OBJ_PROC) {
            key = ipc_body->snooper_objs[i].obj.proc.proc_id;
            proc.proc_id = key;
            (void)bpf_map_update_elem(fd, &key, &proc, BPF_ANY);
        }
    }
}

static void unload_task_snoopers(int fd, struct ipc_body_s *ipc_body)
{
    u32 key = 0;

    if (fd <= 0) {
        return;
    }

    for (int i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        if (ipc_body->snooper_objs[i].type == SNOOPER_OBJ_PROC) {
            key = ipc_body->snooper_objs[i].obj.proc.proc_id;
            (void)bpf_map_delete_elem(fd, &key);
        }
    }
}

static void taskprobe_unload_bpf(void)
{
    unload_bpf_prog(&(g_task_probe.thread_bpf_progs));
    unload_bpf_prog(&(g_task_probe.proc_bpf_progs));

    for (int i = 0; i < GLIBC_EBPF_PROG_MAX; i++) {
        if (g_task_probe.glibc_bpf_progs[i].prog) {
            unload_bpf_prog(&(g_task_probe.glibc_bpf_progs[i].prog));
        }
        if (g_task_probe.glibc_bpf_progs[i].glibc_path) {
            (void)free(g_task_probe.glibc_bpf_progs[i].glibc_path);
            g_task_probe.glibc_bpf_progs[i].glibc_path = NULL;
        }
    }
}

static char __is_exist_glibc_ebpf(struct task_probe_s *task_probe, const char *glibc)
{
    for (int i = 0; i < GLIBC_EBPF_PROG_MAX; i++) {
        if (task_probe->glibc_bpf_progs[i].glibc_path
            && !strcmp(glibc, task_probe->glibc_bpf_progs[i].glibc_path)) {
            return 1;
        }
    }
    return 0;
}

static int __add_glibc_ebpf(struct task_probe_s *task_probe, struct bpf_prog_s *ebpf_prog, const char *glibc)
{
    for (int i = 0; i < GLIBC_EBPF_PROG_MAX; i++) {
        if (task_probe->glibc_bpf_progs[i].prog == NULL) {
            task_probe->glibc_bpf_progs[i].prog = ebpf_prog;
            task_probe->glibc_bpf_progs[i].glibc_path = strdup(glibc);
            return 0;
        }
    }
    return -1;
}

static int taskprobe_load_glibc_bpf(struct task_probe_s *task_probe, struct ipc_body_s *ipc_body)
{
    int ret;
    char *glibc;
    struct bpf_prog_s *new_prog = NULL;
    char host_glibc[PATH_LEN];

    if (!(ipc_body->probe_range_flags & PROBE_RANGE_PROC_DNS)) {
        return 0;
    }

    host_glibc[0] = 0;
    (void)get_glibc_path(NULL, host_glibc, PATH_LEN);

    // Default: load 'glibc of host' ebpf prog
    ret = load_glibc_bpf_prog(task_probe, host_glibc, &new_prog);
    if (ret) {
        goto err;
    }
    ret = __add_glibc_ebpf(task_probe, new_prog, (const char *)host_glibc);
    if (ret) {
        unload_bpf_prog(&new_prog);
        goto err;
    }

    for (int i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        if (ipc_body->snooper_objs[i].type != SNOOPER_OBJ_CON) {
            continue;
        }
        glibc = ipc_body->snooper_objs[i].obj.con_info.libc_path;
        if (glibc == NULL) {
            continue;
        }
        if (__is_exist_glibc_ebpf(task_probe, (const char *)glibc)) {
            continue;
        }
        new_prog = NULL;
        ret = load_glibc_bpf_prog(task_probe, glibc, &new_prog);
        if (ret) {
            goto err;
        }
        ret = __add_glibc_ebpf(task_probe, new_prog, (const char *)glibc);
        if (ret) {
            unload_bpf_prog(&new_prog);
            goto err;
        }
    }

    return 0;
err:
    return -1;
}

static int taskprobe_load_bpf(struct ipc_body_s *ipc_body)
{
    int ret;
    struct bpf_prog_s *new_prog = NULL;

    ret = taskprobe_load_glibc_bpf(&g_task_probe, ipc_body);
    if (ret) {
        goto err;
    }

    ret = load_thread_bpf_prog(&g_task_probe, ipc_body, &new_prog);
    if (ret) {
        goto err;
    }
    g_task_probe.thread_bpf_progs = new_prog;

    ret = load_proc_bpf_prog(&g_task_probe, ipc_body, &new_prog);
    if (ret) {
        goto err;
    }
    g_task_probe.proc_bpf_progs = new_prog;
    return 0;
err:
    fprintf(stderr, "[TASKPROBE] load prog failed.\n");
    return ret;
}

static int perf_poll(struct task_probe_s *task_probe)
{
    int err = 0, ret;
    int ebpf_installed = 0;

    if (task_probe->thread_bpf_progs && task_probe->thread_bpf_progs->pb != NULL) {
        ebpf_installed = 1;
        if ((ret = perf_buffer__poll(task_probe->thread_bpf_progs->pb, THOUSAND)) < 0) {
            err = -1;
            goto end;
        }
    }

    if (task_probe->proc_bpf_progs && task_probe->proc_bpf_progs->pb != NULL) {
        ebpf_installed = 1;
        if ((ret = perf_buffer__poll(task_probe->proc_bpf_progs->pb, THOUSAND)) < 0) {
            err = -1;
            goto end;
        }
    }

    for (int i = 0; i < GLIBC_EBPF_PROG_MAX; i++) {
        if (task_probe->glibc_bpf_progs[i].prog == NULL) {
            break;
        }

        if (task_probe->glibc_bpf_progs[i].prog->pb == NULL) {
            break;
        }
        ebpf_installed = 1;
        if ((ret = perf_buffer__poll(task_probe->glibc_bpf_progs[i].prog->pb, THOUSAND)) < 0) {
            err = -1;
            goto end;
        }
    }
    if (!ebpf_installed) {
        sleep(1);
    }
end:
    return err;
}

int main(int argc, char **argv)
{
    int ret = -1;
    FILE *fp = NULL;
    struct ipc_body_s ipc_body;

    fp = popen(RM_TASK_MAP_PATH, "r");
    if (fp != NULL) {
        (void)pclose(fp);
        fp = NULL;
    }

    (void)memset(&g_task_probe, 0, sizeof(g_task_probe));

    int msq_id = create_ipc_msg_queue(IPC_EXCL);
    if (msq_id < 0) {
        goto err;
    }

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        goto err;
    }

    printf("Successfully started!\n");
    INIT_BPF_APP(taskprobe, EBPF_RLIM_LIMITED);

    while (!stop) {
        ret = recv_ipc_msg(msq_id, (long)PROBE_PROC, &ipc_body);
        if (ret == 0) {
            // Probe range changed, reload bpf prog.
            if (ipc_body.probe_range_flags != g_task_probe.ipc_body.probe_range_flags) {
                taskprobe_unload_bpf();
                if (taskprobe_load_bpf(&ipc_body)) {
                    break;
                }
            }

            // Reload snooper range and params.
            unload_task_snoopers(g_task_probe.proc_map_fd, &(g_task_probe.ipc_body));

            destroy_ipc_body(&(g_task_probe.ipc_body));
            (void)memcpy(&(g_task_probe.ipc_body), &ipc_body, sizeof(g_task_probe.ipc_body));
            load_task_snoopers(g_task_probe.proc_map_fd, &(g_task_probe.ipc_body));
            load_task_args(g_task_probe.args_fd, &(g_task_probe.ipc_body.probe_param));
        }

        ret = perf_poll(&g_task_probe);
        if (ret) {
            break;
        }
        scan_dns_entrys(&g_task_probe);
    }

err:
    taskprobe_unload_bpf();
    destroy_ipc_body(&(g_task_probe.ipc_body));
    destroy_dns_entrys(&g_task_probe);
    return ret;
}

