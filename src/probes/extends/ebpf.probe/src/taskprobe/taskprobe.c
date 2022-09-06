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

#define RM_TASK_MAP_PATH "/usr/bin/rm -rf /sys/fs/bpf/probe/__taskprobe*"

#define LOAD_TASK_PROBE(probe_name, end, load) \
    OPEN(probe_name, end, load); \
    MAP_SET_PIN_PATH(probe_name, period_map, PERIOD_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, g_task_map, TASK_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, g_proc_map, PROC_PATH, load); \
    LOAD_ATTACH(probe_name, end, load)

static volatile sig_atomic_t stop = 0;
static struct probe_params tp_params = {.period = DEFAULT_PERIOD,
                                        .task_whitelist = {0}};

static struct task_name_t task_range[] = {
    {"go",              TASK_TYPE_APP},
    {"java",            TASK_TYPE_APP},
    {"python",          TASK_TYPE_APP},
    {"python3",         TASK_TYPE_APP}
};

static void sig_int(int signal)
{
    stop = 1;
}

static void load_daemon_proc(int task_map_fd, int proc_map_fd)
{
    int ret;
    int ckey = 0, nkey = 0;
    u32 proc_id;
    struct task_data task_data = {0};
    struct proc_data_s proc_data = {0};

    while (bpf_map_get_next_key(task_map_fd, &ckey, &nkey) != -1) {
        ret = bpf_map_lookup_elem(task_map_fd, &nkey, &task_data);
        if (ret == 0) {
            if (task_data.id.tgid == task_data.id.pid) {
                proc_id = task_data.id.tgid;
                proc_data.proc_id = proc_id;
                (void)memcpy(proc_data.comm, task_data.id.comm, TASK_COMM_LEN);
                (void)bpf_map_update_elem(proc_map_fd, &proc_id, &proc_data, BPF_ANY);
            }
        }
        ckey = nkey;
    }
}

static void load_daemon_task(int app_fd, int task_map_fd)
{
    struct probe_process ckey = {0};
    struct probe_process nkey = {0};
    int flag;
    int ret = -1;

    while (bpf_map_get_next_key(app_fd, &ckey, &nkey) != -1) {
        ret = bpf_map_lookup_elem(app_fd, &nkey, &flag);
        if (ret == 0) {
            load_daemon_task_by_name(task_map_fd, (const char *)nkey.name, 1);
            DEBUG("[TASKPROBE]: load daemon process '%s'.\n", nkey.name);
        }
        ckey = nkey;
    }

    uint32_t index, size = sizeof(task_range) / sizeof(task_range[0]);
    for (index = 0; index < size; index++) {
        if (task_range[index].type != TASK_TYPE_APP) {

            load_daemon_task_by_name(task_map_fd, (const char *)task_range[index].name, 0);
            DEBUG("[TASKPROBE]: load daemon process '%s'.\n", task_range[index].name);
        }
    }

    return;
}

static void load_task_range(int fd)
{
    int flag = 1;
    struct probe_process pname;
    uint32_t index = 0;
    uint32_t size = sizeof(task_range) / sizeof(task_range[0]);

    for (index = 0; index < size; index++) {
        if (task_range[index].type == TASK_TYPE_APP || task_range[index].type == TASK_TYPE_OS) {
            (void)memset(pname.name, 0, TASK_COMM_LEN);
            (void)strncpy(pname.name, task_range[index].name, TASK_COMM_LEN - 1);

            /* update probe_proc_map */
            (void)bpf_map_update_elem(fd, &pname, &flag, BPF_ANY);

            DEBUG("[TASKPROBE]: load probe process name '%s'.\n", pname.name);
        }
    }
}

static void load_task_wl(int fd)
{
    FILE *f = NULL;
    char line[TASK_COMM_LEN];
    struct probe_process pname;
    int flag = 1;

    f = fopen(tp_params.task_whitelist, "r");
    if (f == NULL) {
        return;
    }
    while (!feof(f)) {
        (void)memset(line, 0, TASK_COMM_LEN);
        if (fgets(line, TASK_COMM_LEN, f) == NULL) {
            goto out;
        }
        SPLIT_NEWLINE_SYMBOL(line);
        if (strlen(line) == 0) {
            continue;
        }
        (void)memset(pname.name, 0, TASK_COMM_LEN);
        (void)strncpy(pname.name, line, TASK_COMM_LEN - 1);

        /* update probe_proc_map */
        (void)bpf_map_update_elem(fd, &pname, &flag, BPF_ANY);

        DEBUG("[TASKPROBE]: load probe process name '%s'.\n", pname.name);
    }
out:
    fclose(f);
    return;
}

static void load_period(int period_fd, __u32 value)
{
    __u32 key = 0;
    __u64 period = NS(value);
    (void)bpf_map_update_elem(period_fd, &key, &period, BPF_ANY);
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

    ret = args_parse(argc, argv, &tp_params);
    if (ret != 0) {
        return ret;
    }

    if (strlen(tp_params.task_whitelist) == 0) {
        fprintf(stderr, "***task_whitelist_path is null, please check param : -c xx/xxx *** \n");
    }

    fp = popen(RM_TASK_MAP_PATH, "r");
    if (fp != NULL) {
        (void)pclose(fp);
        fp = NULL;
    }

    INIT_BPF_APP(taskprobe, EBPF_RLIM_LIMITED);

    // load task probe bpf prog
    LOAD_TASK_PROBE(taskprobe, err, 1);

    int pmap_fd = GET_MAP_FD(taskprobe, probe_proc_map);
    int task_map_fd = GET_MAP_FD(taskprobe, g_task_map);
    int period_fd = GET_MAP_FD(taskprobe, period_map);
    int proc_map_fd = GET_MAP_FD(taskprobe, g_proc_map);

    // Set task probe collection period
    load_period(period_fd, tp_params.period);

    // Set task probe observation range based on 'task->comm'
    load_task_range(pmap_fd);

    // Set task probe whitelist.
    load_task_wl(pmap_fd);

    // Load task instances based on the whitelist.
    load_daemon_task(pmap_fd, task_map_fd);

    // Load proc instances from thread table.
    load_daemon_proc(task_map_fd, proc_map_fd);

    // Load thread bpf prog
    thread_bpf_progs = load_task_bpf_prog(&tp_params);
    if (thread_bpf_progs == NULL) {
        goto err;
    }

    // Load proc bpf prog
    proc_bpf_progs = load_proc_bpf_prog(&tp_params);
    if (proc_bpf_progs == NULL) {
        goto err;
    }

    // Load glibc bpf prog
    glibc_bpf_progs = load_glibc_bpf_prog(&tp_params);

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
    }

err:
    unload_bpf_prog(&glibc_bpf_progs);
    unload_bpf_prog(&proc_bpf_progs);
    unload_bpf_prog(&thread_bpf_progs);
    UNLOAD(taskprobe);

    return ret;
}
