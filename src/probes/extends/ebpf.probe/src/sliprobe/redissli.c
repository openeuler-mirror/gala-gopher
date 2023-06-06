
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
 * Create: 2022-3-8
 * Description: redis SLI probe user prog
 ******************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "args.h"
#include "redissli.h"
#include "redissli.skel.h"

#define OO_NAME "redissli"

static volatile sig_atomic_t stop;
static struct probe_params params = {.period = DEFAULT_PERIOD, .elf_path = {0}};

#define MAX_RDS_SEARCH_NUMS 1
#define MAX_RDS_VER_LEN 10

static const char *rds_search_paths[MAX_RDS_SEARCH_NUMS] = {"/usr/bin/redis-server",};
static char rds_elf_path[MAX_PATH_LEN] = {0};
static char rds_ver[MAX_RDS_VER_LEN] = {0};

static void sig_int(int signo)
{
    stop = 1;
}

static int init_rds_elf_path(char *rds_elf_path, unsigned int size, const char *elf_path)
{
    snprintf(rds_elf_path, MAX_PATH_LEN, "%s", params.elf_path);
    if (rds_elf_path[0] != '\0') {
        if (access(rds_elf_path, 1) != 0) {
            fprintf(stderr, "File %s not exist or not executable!\n", rds_elf_path);
            return -1;
        }
        return 0;
    }

    for (int i = 0; i < MAX_RDS_SEARCH_NUMS; i++) {
        if (rds_search_paths[i][0] == '\0' || access(rds_search_paths[i], 1) != 0) {
            continue;
        }
        snprintf(rds_elf_path, MAX_PATH_LEN, "%s", rds_search_paths[i]);
        break;
    }

    if (rds_elf_path[0] == '\0') {
        fprintf(stderr, "Cann't search a redis executable file of 'redis-server'!\n");
        return -1;
    }

    printf("Redis executable file of 'redis-server' not specified, use default file [%s] instead.\n", rds_elf_path);
    return 0;
}

static void load_period(int period_fd, __u32 value)
{
    __u32 key = 0;
    __u64 period = (__u64)value * 1000000000;
    (void)bpf_map_update_elem(period_fd, &key, &period, BPF_ANY);
}

static void conn_cmd_evt_handler(void *ctx, int cpu, void *data, unsigned int size)
{
    struct cmd_event_data_t *cmd_data = (struct cmd_event_data_t *)data;

    fprintf(stdout,
            "|%s|%u|%u|%s|%s|%s|%llu|\n",
            OO_NAME,
            cmd_data->conn_id.tgid,
            cmd_data->conn_id.fd,
            rds_elf_path,
            rds_ver,
            cmd_data->name,
            cmd_data->timeout_nsec);
    (void)fflush(stdout);

    return;
}

static void *conn_cmd_evt_receiver(void *arg)
{
    int fd = *(int *)arg;
    struct perf_buffer *pb;

    pb = create_pref_buffer(fd, conn_cmd_evt_handler);
    if (pb == NULL) {
        fprintf(stderr, "Failed to create perf buffer.\n");
        stop = 1;
        return NULL;
    }

    poll_pb(pb, params.period * 1000);

    stop = 1;
    return NULL;
}

static int init_conn_mgt_process(int cmd_evt_map_fd)
{
    int err;
    pthread_t cmd_evt_hdl_thd;

    // 启动连接请求事件处理程序
    err = pthread_create(&cmd_evt_hdl_thd, NULL, conn_cmd_evt_receiver, (void *)&cmd_evt_map_fd);
    if (err != 0) {
        fprintf(stderr, "Failed to create connection command event handler thread.\n");
        return -1;
    }
    (void)pthread_detach(cmd_evt_hdl_thd);
    printf("Connection command event handler thread successfully started!\n");

    return 0;
}

int main(int argc, char **argv)
{
    int err;
    int ret;

    err = args_parse(argc, argv, &params);
    if (err != 0) {
        return -1;
    }
    printf("arg parse interval time:%us, elf's path:%s\n", params.period, params.elf_path);

    err = init_rds_elf_path(rds_elf_path, MAX_PATH_LEN, params.elf_path);
    if (err < 0) {
        return -1;
    }
    snprintf(rds_ver, MAX_RDS_VER_LEN, "%u.%u.%u", RDS_VER_MAJOR, RDS_VER_MINOR, RDS_VER_PATCH);

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "Can't set signal handler: %d\n", errno);
        return -1;
    }

    INIT_BPF_APP(redissli, EBPF_RLIM_LIMITED);
    LOAD(redissli, redissli, err);

    load_period(GET_MAP_FD(redissli, period_map), params.period);

    UBPF_ATTACH(redissli, readQueryFromClient, params.elf_path, readQueryFromClient, ret);
    if (ret <= 0) {
        fprintf(stderr, "Can't attach function readQueryFromClient.\n");
        goto err;
    }
    UBPF_ATTACH(redissli, processCommand, params.elf_path, processCommand, ret);
    if (ret <= 0) {
        fprintf(stderr, "Can't attach function processCommand.\n");
        goto err;
    }
    UBPF_RET_ATTACH(redissli, processCommand, params.elf_path, processCommand, ret);
    if (ret <= 0) {
        fprintf(stderr, "Can't attach function processCommand return.\n");
        goto err;
    }
    UBPF_ATTACH(redissli, writeToClient, params.elf_path, writeToClient, ret);
    if (ret <= 0) {
        fprintf(stderr, "Can't attach function writeToClient.\n");
        goto err;
    }
    UBPF_RET_ATTACH(redissli, writeToClient, params.elf_path, writeToClient, ret);
    if (ret <= 0) {
        fprintf(stderr, "Can't attach function writeToClient return.\n");
        goto err;
    }
    UBPF_ATTACH(redissli, freeClient, params.elf_path, freeClient, ret);
    if (ret <= 0) {
        fprintf(stderr, "Can't attach function freeClient.\n");
        goto err;
    }

    printf("Redis SLI probe successfully started!\n");

    err = init_conn_mgt_process(GET_MAP_FD(redissli, conn_cmd_evt_map));
    if (err != 0) {
        fprintf(stderr, "Init connection management process failed.\n");
        goto err;
    }

    while (!stop) {
        sleep(params.period);
    }

err:
    UNLOAD(redissli);
    return -err;
}
