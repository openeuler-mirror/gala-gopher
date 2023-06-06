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
 * Author: wo_cow
 * Create: 2022-4-14
 * Description: KSLI probe user prog
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
#include "event.h"
#include "ksliprobe.skel.h"
#include "tc_loader.h"
#include "ksliprobe.h"

#define OO_NAME "sli"
#define DEFAULT_REDIS_PROC_NAME "redis"
#define SLI_TBL_NAME "redis_sli"
#define MAX_SLI_TBL_NAME "redis_max_sli"

static volatile sig_atomic_t stop;
static struct probe_params params = {.period = DEFAULT_PERIOD, .continuous_sampling_flag = 0};

static void sig_int(int signo)
{
    stop = 1;
}

#define MS2NS(ms)   ((u64)(ms) * 1000000)
#define __ENTITY_ID_LEN 128

static void report_sli_event(struct msg_event_data_t *msg_evt_data)
{
    char entityId[__ENTITY_ID_LEN];
    u64 latency_thr_ns = MS2NS(params.latency_thr);
    unsigned char ser_ip_str[INET6_ADDRSTRLEN];
    unsigned char cli_ip_str[INET6_ADDRSTRLEN];

    if (params.logs == 0) {
        return;
    }

    entityId[0] = 0;
    (void)snprintf(entityId, __ENTITY_ID_LEN, "%d_%d",
        msg_evt_data->conn_id.tgid,
        msg_evt_data->conn_id.fd);

    if ((latency_thr_ns > 0) && (latency_thr_ns < msg_evt_data->latency.rtt_nsec)) {
        ip_str(msg_evt_data->server_ip_info.family, (unsigned char *)&(msg_evt_data->server_ip_info.ipaddr),
            ser_ip_str, INET6_ADDRSTRLEN);
        ip_str(msg_evt_data->client_ip_info.family, (unsigned char *)&(msg_evt_data->client_ip_info.ipaddr),
            cli_ip_str, INET6_ADDRSTRLEN);

        report_logs(OO_NAME,
                    entityId,
                    "rtt_nsec",
                    EVT_SEC_WARN,
                    "Process(TID:%d, CIP(%s:%u), SIP(%s:%u)) SLI(%s:%llu) exceed the threshold.",
                    msg_evt_data->conn_id.tgid,
                    cli_ip_str,
                    ntohs(msg_evt_data->client_ip_info.port),
                    ser_ip_str,
                    msg_evt_data->server_ip_info.port,
                    msg_evt_data->latency.command,
                    msg_evt_data->latency.rtt_nsec);
    }
}

static void msg_event_handler(void *ctx, int cpu, void *data, unsigned int size)
{
    struct msg_event_data_t *msg_evt_data = (struct msg_event_data_t *)data;
    unsigned char ser_ip_str[INET6_ADDRSTRLEN];
    unsigned char cli_ip_str[INET6_ADDRSTRLEN];
    //const char *protocol;

    report_sli_event(msg_evt_data);

    ip_str(msg_evt_data->server_ip_info.family, (unsigned char *)&(msg_evt_data->server_ip_info.ipaddr),
        ser_ip_str, INET6_ADDRSTRLEN);
    ip_str(msg_evt_data->client_ip_info.family, (unsigned char *)&(msg_evt_data->client_ip_info.ipaddr),
        cli_ip_str, INET6_ADDRSTRLEN);

    fprintf(stdout,
            "|%s|%d|%d|%s|%s|%s|%u|%s|%u|%llu|\n",
            SLI_TBL_NAME,
            msg_evt_data->conn_id.tgid,
            msg_evt_data->conn_id.fd,
            "REDIS",
            msg_evt_data->latency.command,
            ser_ip_str,
            msg_evt_data->server_ip_info.port,
            cli_ip_str,
            ntohs(msg_evt_data->client_ip_info.port),
            msg_evt_data->latency.rtt_nsec);
    if (params.continuous_sampling_flag) {
        fprintf(stdout,
            "|%s|%d|%d|%s|%s|%s|%u|%s|%u|%llu|\n",
            MAX_SLI_TBL_NAME,
            msg_evt_data->conn_id.tgid,
            msg_evt_data->conn_id.fd,
            "REDIS",
            msg_evt_data->max.command,
            ser_ip_str,
            msg_evt_data->server_ip_info.port,
            cli_ip_str,
            ntohs(msg_evt_data->client_ip_info.port),
            msg_evt_data->max.rtt_nsec);
    }

    (void)fflush(stdout);

    return;
}

static void *msg_event_receiver(void *arg)
{
    int fd = *(int *)arg;
    struct perf_buffer *pb;

    pb = create_pref_buffer(fd, msg_event_handler);
    if (pb == NULL) {
        fprintf(stderr, "Failed to create perf buffer.\n");
        stop = 1;
        return NULL;
    }

    poll_pb(pb, params.period * 1000);

    stop = 1;
    return NULL;
}

static int init_conn_mgt_process(int msg_evt_map_fd)
{
    int err;
    pthread_t msg_evt_hdl_thd;

    // 启动读写消息事件处理程序
    err = pthread_create(&msg_evt_hdl_thd, NULL, msg_event_receiver, (void *)&msg_evt_map_fd);
    if (err != 0) {
        fprintf(stderr, "Failed to create connection read/write message event handler thread.\n");
        return -1;
    }
    (void)pthread_detach(msg_evt_hdl_thd);
    printf("Connection read/write message event handler thread successfully started!\n");

    return 0;
}

static void load_args(int args_fd, struct probe_params* params)
{
    __u32 key = 0;
    struct ksli_args_s args = {0};

    args.period = NS(params->period);
    args.continuous_sampling_flag = params->continuous_sampling_flag;

    (void)bpf_map_update_elem(args_fd, &key, &args, BPF_ANY);
}

int main(int argc, char **argv)
{
    int err;

    err = args_parse(argc, argv, &params);
    if (err != 0) {
        return -1;
    }
    printf("arg parse interval time:%us\n", params.period);
    printf("arg parse if cycle sampling:%s\n", params.continuous_sampling_flag ? "true": "false");

#ifdef KERNEL_SUPPORT_TSTAMP
    load_tc_bpf(params.netcard_list, TC_PROG, TC_TYPE_INGRESS);
#else
    printf("The kernel version does not support loading the tc tstamp program\n");
#endif

    INIT_BPF_APP(ksliprobe, EBPF_RLIM_LIMITED);
    LOAD(ksliprobe, ksliprobe, err);
    load_args(GET_MAP_FD(ksliprobe, args_map), &params);
    
    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "Can't set signal handler: %d\n", errno);
        goto err;
    }

    // 初始化连接管理程序
    err = init_conn_mgt_process(GET_MAP_FD(ksliprobe, msg_event_map));
    if (err != 0) {
        fprintf(stderr, "Init connection management process failed.\n");
        goto err;
    }

    printf("SLI probe successfully started!\n");

    while (!stop) {
        sleep(params.period);
    }

err:
    UNLOAD(ksliprobe);
#ifdef KERNEL_SUPPORT_TSTAMP
    offload_tc_bpf(TC_TYPE_INGRESS);
#endif
    return -err;
}
