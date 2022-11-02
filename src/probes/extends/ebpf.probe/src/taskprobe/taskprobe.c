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
#include "whitelist_config.h"

#define RM_TASK_MAP_PATH "/usr/bin/rm -rf /sys/fs/bpf/probe/__taskprobe*"
#define TASK_CMDLINE_PATH "/proc/%d/cmdline"

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
    // eg: {"go", "",              TASK_TYPE_APP},
};

static void sig_int(int signal)
{
    stop = 1;
}

static char *get_task_cmdline(int tgid, int buf_len)
{
    FILE *f = NULL;
    char path[LINE_BUF_LEN];
    char *line = NULL;
    int index = 0;

    line = malloc(sizeof(char) * buf_len);
    if (line == NULL) {
        ERROR("[TASKPROBE] get cmdline failed, malloc failed.\n");
        return NULL;
    }
    (void)memset(line, 0, sizeof(char) * buf_len);

    path[0] = 0;
    (void)snprintf(path, LINE_BUF_LEN, TASK_CMDLINE_PATH, tgid);
    f = fopen(path, "r");
    if (f == NULL) {
        (void)free(line);
        return NULL;
    }
    /* parse line */
    while (!feof(f)) {
        if (index >= buf_len - 1) {
            line[index] = '\0';
            break;
        }
        line[index] = fgetc(f);
        if (line[index] == '\0') {
            line[index] = ' ';
        } else if (line[index] == -1 && line[index - 1] == ' ') {
            line[index - 1] = '\0';
        }
        index++;
    }

    (void)fclose(f);
    return line;
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
    struct probe_proc_info pinfo;
    int ret = -1;

    while (bpf_map_get_next_key(app_fd, &ckey, &nkey) != -1) {
        ret = bpf_map_lookup_elem(app_fd, &nkey, &pinfo);
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
    struct probe_proc_info pinfo;
    struct probe_process pname;
    uint32_t index = 0;
    uint32_t size = sizeof(task_range) / sizeof(task_range[0]);

    for (index = 0; index < size; index++) {
        if (task_range[index].type == TASK_TYPE_APP || task_range[index].type == TASK_TYPE_OS) {
            (void)memset(pname.name, 0, TASK_COMM_LEN);
            (void)strncpy(pname.name, task_range[index].name, TASK_COMM_LEN - 1);

            pinfo.flag = 1;
            (void)memset(pinfo.cmd_line, 0, TASK_CMD_LINE_LEN);
            (void)strncpy(pinfo.cmd_line, task_range[index].cmd_line, TASK_CMD_LINE_LEN - 1);
            /* update probe_proc_map */
            (void)bpf_map_update_elem(fd, &pname, &pinfo, BPF_ANY);

            DEBUG("[TASKPROBE]: load probe process name '%s'.\n", pname.name);
        }
    }
}

static void load_task_wl(int fd)
{
    struct probe_process pname;
    struct probe_proc_info pinfo;
    ApplicationsConfig *conf;

    if (parse_whitelist_config(&conf, tp_params.task_whitelist) < 0) {
        ERROR("[TASKPROBE] parse whitelist failed.\n");
        return;
    }

    for (int i = 0; i < conf->apps_num; i++) {
        ApplicationConfig *_app = conf->apps[i];
        (void)memset(pname.name, 0, TASK_COMM_LEN);
        (void)strncpy(pname.name, _app->comm, TASK_COMM_LEN - 1);
        (void)memset(pinfo.cmd_line, 0, TASK_CMD_LINE_LEN);
        (void)strncpy(pinfo.cmd_line, _app->cmd_line, TASK_CMD_LINE_LEN - 1);
        pinfo.flag = 1;
        /* update probe_proc_map */
        (void)bpf_map_update_elem(fd, &pname, &pinfo, BPF_ANY);

        DEBUG("[TASKPROBE]: load probe process name '%s'.\n", pname.name);
    }

    whitelist_config_destroy(conf);

    return;
}

static void load_period(int period_fd, __u32 value)
{
    __u32 key = 0;
    __u64 period = NS(value);
    (void)bpf_map_update_elem(period_fd, &key, &period, BPF_ANY);
}

static int g_pmap_fd = -1;
int is_task_cmdline_match(int tgid, const char *comm)
{
    int ret;
    struct probe_proc_info pinfo = {0};
    struct probe_process pname = {0};

    strncpy(pname.name, comm, TASK_COMM_LEN - 1);
    ret = bpf_map_lookup_elem(g_pmap_fd, &pname, &pinfo);
    if (ret == 0) {
        if (pinfo.cmd_line == NULL) {
            // 表示不需要匹配cmdline
            return 1;
        }
        char *cmdline = get_task_cmdline(tgid, TASK_CMDLINE_MAX_LEN);
        if (cmdline == NULL) {
            return 0;
        }
        if (strstr(cmdline, pinfo.cmd_line) == NULL) {
            (void)free(cmdline);
            return 0;
        } else {
            (void)free(cmdline);
            return 1;
        }
    }

    return 0;
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

    g_pmap_fd = GET_MAP_FD(taskprobe, probe_proc_map);
    int task_map_fd = GET_MAP_FD(taskprobe, g_task_map);
    int period_fd = GET_MAP_FD(taskprobe, period_map);
    int proc_map_fd = GET_MAP_FD(taskprobe, g_proc_map);

    // Set task probe collection period
    load_period(period_fd, tp_params.period);

    // Set task probe observation range based on 'task->comm'
    load_task_range(g_pmap_fd);

    // Set task probe whitelist.
    load_task_wl(g_pmap_fd);

    // Load task instances based on the whitelist.
    load_daemon_task(g_pmap_fd, task_map_fd);

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
