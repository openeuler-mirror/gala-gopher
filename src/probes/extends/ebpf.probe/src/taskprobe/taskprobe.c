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
#include "taskprobe.skel.h"
#include "taskprobe.h"
#include "bpf_prog.h"
#include "proc.h"
#include "thread.h"
#include "task_args.h"
#include "whitelist_config.h"

#define RM_TASK_MAP_PATH "/usr/bin/rm -rf /sys/fs/bpf/probe/__taskprobe*"
#define TASK_CMDLINE_PATH "/proc/%d/cmdline"

#define LOAD_TASK_PROBE(probe_name, end, load) \
    OPEN(probe_name, end, load); \
    MAP_SET_PIN_PATH(probe_name, args_map, ARGS_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, g_thread_map, THREAD_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, g_proc_map, PROC_PATH, load); \
    LOAD_ATTACH(probe_name, end, load)

static struct task_probe_s probe = {0};

static volatile sig_atomic_t stop = 0;

static void sig_int(int signal)
{
    stop = 1;
}

static void add_proc_item(u32 proc_id, const char *comm, struct task_probe_s* probep)
{
    struct proc_id_s *proc = malloc(sizeof(struct proc_id_s));
    if (proc == NULL) {
        return;
    }

    proc->id = proc_id;
    memcpy(proc->comm, comm, TASK_COMM_LEN);
    H_ADD_I(probep->procs, id, proc);
}

static char is_wl_range(const char *comm, const char* cmdline, ApplicationsConfig *conf)
{
    ApplicationConfig *appc;
    if (conf == NULL) {
        return 0;
    }

    for (int i = 0; i < conf->apps_num; i++) {
        appc = conf->apps[i];
        if (appc) {
            // only match comm
            if ((appc->comm[0] != 0) && (appc->cmd_line[0] == 0)) {
                if (((comm[0] != 0) && strstr(comm, appc->comm))) {
                    return 1;
                }
            }
            // match comm and cmdline
            if ((appc->comm[0] != 0) && (appc->cmd_line[0] != 0)) {
                if (((comm[0] != 0) && strstr(comm, appc->comm)) &&
                    ((cmdline[0] != 0) && strstr(cmdline, appc->cmd_line))) {
                    return 1;
                }
            }
        }
    }
    return 0;
}

static void get_wl_proc(struct task_probe_s* probep)
{
    u32 proc_id;
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    char comm[TASK_COMM_LEN];
    char cmdline[PROC_CMDLINE_LEN];
    char command[COMMAND_LEN];
    const char *get_comm_fmt = "/usr/bin/cat /proc/%u/comm";
    const char *get_cmdline_fmt = "/usr/bin/cat /proc/%u/cmdline";

    dir = opendir("/proc");
    if (dir == NULL) {
        return;
    }

    do {
        entry = readdir(dir);
        if (entry == NULL) {
            break;
        }
        if (!is_digit_str(entry->d_name)) {
            continue;
        }

        proc_id = (u32)atoi(entry->d_name);

        comm[0] = 0;
        command[0] = 0;
        (void)snprintf(command, COMMAND_LEN, get_comm_fmt, proc_id);
        if (exec_cmd((const char *)command, comm, TASK_COMM_LEN)) {
            continue;
        }

        cmdline[0] = 0;
        command[0] = 0;
        (void)snprintf(command, COMMAND_LEN, get_cmdline_fmt, proc_id);
        if (exec_cmd((const char *)command, cmdline, PROC_CMDLINE_LEN)) {
            continue;
        }

        if (!is_wl_range((const char *)comm, (const char *)command, probep->conf)) {
            continue;
        }

        add_proc_item(proc_id, (const char *)comm, probep);
    } while (1);

    closedir(dir);

    return;
}

static void load_task_args(int fd, struct probe_params *params)
{
    u32 key = 0;
    struct task_args_s args = {0};

    args.report_period = NS(params->period);
    args.offline_thr = (u64)params->offline_thr * 1000 * 1000;
    (void)bpf_map_update_elem(fd, &key, &args, BPF_ANY);
}

static void load_wl2bpf(struct task_probe_s* probep)
{
    struct proc_id_s *item, *tmp;
    if (probep->procs) {
        H_ITER(probep->procs, item, tmp) {
            load_proc2bpf(item->id, (const char *)(item->comm), probep->proc_map_fd);
            load_thread2bpf(item->id, probep->thread_map_fd);
        }
    }
}

static void __deinit_probe(struct task_probe_s *probep)
{
    struct proc_id_s *item, *tmp;

    if (probep->procs) {
        H_ITER(probep->procs, item, tmp) {
            H_DEL(probep->procs, item);
            (void)free(item);
        }
    }
    probep->procs = NULL;

    if (probep->conf != NULL) {
        whitelist_config_destroy(probep->conf);
    }
    probep->conf = NULL;

    return;
}

int main(int argc, char **argv)
{
    int ret = -1;
    FILE *fp = NULL;
    struct bpf_prog_s* thread_bpf_progs = NULL;
    struct bpf_prog_s* proc_bpf_progs = NULL;
    struct bpf_prog_s* glibc_bpf_progs = NULL;

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        return -1;
    }

    ret = args_parse(argc, argv, &probe.params);
    if (ret != 0) {
        return ret;
    }

    if (strlen(probe.params.task_whitelist) == 0) {
        fprintf(stderr, "***task_whitelist_path is null, please check param : -c xx/xxx *** \n");
        return -1;
    }

    if (parse_whitelist_config(&(probe.conf), probe.params.task_whitelist) < 0) {
        return -1;
    }

    fp = popen(RM_TASK_MAP_PATH, "r");
    if (fp != NULL) {
        (void)pclose(fp);
        fp = NULL;
    }

    INIT_BPF_APP(taskprobe, EBPF_RLIM_LIMITED);

    // load task probe bpf prog
    LOAD_TASK_PROBE(taskprobe, err, 1);

    probe.args_fd = GET_MAP_FD(taskprobe, args_map);
    probe.thread_map_fd = GET_MAP_FD(taskprobe, g_thread_map);
    probe.proc_map_fd = GET_MAP_FD(taskprobe, g_proc_map);

    // Set task probe collection period
    load_task_args(probe.args_fd, &(probe.params));

    // load wl proc
    get_wl_proc(&probe);

    // load daemon thread and proc
    load_wl2bpf(&probe);

    // Load thread bpf prog
    thread_bpf_progs = load_thread_bpf_prog(&(probe.params));
    if (thread_bpf_progs == NULL) {
        goto err;
    }

    // Load proc bpf prog
    proc_bpf_progs = load_proc_bpf_prog(&probe);
    if (proc_bpf_progs == NULL) {
        goto err;
    }

    // Load glibc bpf prog
    glibc_bpf_progs = load_glibc_bpf_prog(&(probe.params));

    printf("Successfully started!\n");

    while (!stop) {
        if (thread_bpf_progs->pb != NULL) {
            if ((ret = perf_buffer__poll(thread_bpf_progs->pb, THOUSAND)) < 0) {
                break;
            }
        }
        if (proc_bpf_progs->pb != NULL) {
            if ((ret = perf_buffer__poll(proc_bpf_progs->pb, THOUSAND)) < 0) {
                break;
            }
        }
        for (int i = 0; i < proc_bpf_progs->num; i++) {
            if (proc_bpf_progs->pbs[i] != NULL) {
                if ((ret = perf_buffer__poll(proc_bpf_progs->pbs[i], THOUSAND)) < 0) {
                    break;
                }
            }
        }
    }

err:
    unload_bpf_prog(&glibc_bpf_progs);
    unload_bpf_prog(&proc_bpf_progs);
    unload_bpf_prog(&thread_bpf_progs);
    UNLOAD(taskprobe);

    __deinit_probe(&probe);

    return ret;
}

