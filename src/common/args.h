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
 * Author: Mr.lu
 * Create: 2021-10-18
 * Description: probe's arg header
 ******************************************************************************/
#ifndef __GOPHER_ARGS_H__
#define __GOPHER_ARGS_H__

#pragma once

#define DEFAULT_LOAD_PROBE  (0xFFFFFFFF)
#define DEFAULT_PERIOD      5
#define DEFAULT_SAMPLE_PERIOD      100
#define MAX_PATH_LEN        512
#define MAX_COMM_LEN        17
#define MAX_PROC_NAME_LEN   8
#define DEV_NAME            32
#define DEFAULT_KAFKA_PORT    9092
#define MAX_IP_LEN          20	// xxx.xxx.xxx.xxx/xx
#define MAX_IP_NUM          8

#define SUPPORT_NODE_ENV        0x01
#define SUPPORT_CONTAINER_ENV   0x02
#define SUPPORT_K8S_ENV         0x04

#define SUPPORT_METRICS_RAW     0x01
#define SUPPORT_METRICS_TELEM   0x02

#define MAX_TGIDS_LEN       64

#define __OPT_S "t:s:T:J:O:D:F:lU:L:c:p:w:d:P:Ck:i:m:e:f:"
struct probe_params {
    unsigned int period;          // [-t <>] Report period, unit second, default is 5 seconds
    unsigned int sample_period;   // [-s <>] Sampling period, unit milliseconds, default is 100 milliseconds
    unsigned int latency_thr;     // [-T <>] Threshold of latency time, unit ms, default is 0 milliseconds
    unsigned int jitter_thr;      // [-J <>] Threshold of jitter time, unit ms, default is 0 milliseconds
    unsigned int offline_thr;     // [-O <>] Threshold of offline time, unit ms, default is 0 milliseconds
    unsigned int drops_count_thr; // [-D <>] Threshold of the number of drop packets, default is 0
    unsigned int filter_pid;      // [-F <>] Filtering PID monitoring ranges by specific pid, default is 0 (no filter)
    unsigned int load_probe;      // [-P <>] Specifies the range of probe programs to be loaded, default is 0xFFFFFFFF (Load all probes)
    unsigned int kafka_port;      // [-k <>] the port to which kafka server attach.
    char logs;                    // [-l <warn>] Enable the logs function
    char metrics_flags;           // [-m <>] Support for report metrics flags(0x01(raw metrics), 0x02(openTelemetry metrics, eg.. P50/P90/P99) );
    char env_flags;               // [-e <>] Support for env flags(default 0x01(node), 0x02(container), 0x04(K8S));
    char pad;                     // Reserved fields;
    char filter_task_probe;       // [-F <>] Filtering PID monitoring ranges by task probe, default is 0 (no filter)
    char res_percent_upper;       // [-U <>] Upper limit of resource percentage, default is 0%
    char res_percent_lower;       // [-L <>] Lower limit of resource percentage, default is 0%
    unsigned char cport_flag;     // [-c <>] Indicates whether the probes(such as tcp) identifies the client port, default is 0 (no identify)
    char continuous_sampling_flag;     // [-C <>] Enables the continuous sampling, default is 0
    char target_dev[DEV_NAME];    // [-d <>] Device name, default is null 
    char elf_path[MAX_PATH_LEN];  // [-p <>] Set ELF file path of the monitored software, default is null 
    char task_whitelist[MAX_PATH_LEN]; // [-w <>] Filtering app monitoring ranges, default is null
    char netcard_list[MAX_PATH_LEN]; // [-d <>] Device name, default is null
    char target_comm[MAX_COMM_LEN]; // [-F <>] Process comm name, default is null
    char host_ip_list[MAX_IP_NUM][MAX_IP_LEN]; // [-i <>] Host ip fields list, default is null
    char tgids[MAX_TGIDS_LEN];    // [-f <>] Filter tgids, default is null
    /*
        [-P <>]
        L7 probe monitoring protocol flags, Refer to the below definitions(default is 0):
        0x0001  HTTP
        0x0002  DNS
        0x0004  REDIS
        0x0008  MYSQL
        0x0010  PGSQL
        0x0012  KAFKA
        0x0014  MONGODB
        0x0018  Cassandra
        0x0020  NATS
    */
    unsigned int l7_probe_proto_flags;
};
int args_parse(int argc, char **argv, struct probe_params* params);
int params_parse(char *s, struct probe_params *params);

#endif
