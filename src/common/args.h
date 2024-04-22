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

#define DEFAULT_PERIOD      60
#define DEFAULT_SAMPLE_PERIOD      5000
#define MAX_PATH_LEN        512
#define MAX_COMM_LEN        17
#define MAX_PROC_NAME_LEN   8
#define DEV_NAME            32
#define DEFAULT_KAFKA_PORT    9092
#define MAX_IP_LEN          20	// xxx.xxx.xxx.xxx/xx
#define MAX_IP_NUM          8
#define MAX_TGIDS_LEN       64
#define DEFAULT_CADVISOR_PORT    8080

#define PYSCOPE_SERVER_URL_LEN  64  // compat for [domainName]:4040 for most of domains and xxx.xxx.xxx.xxx:4040
#ifndef PATH_LEN
#define PATH_LEN            256
#endif

#define SUPPORT_NODE_ENV        0x01
#define SUPPORT_CONTAINER_ENV   0x02
#define SUPPORT_K8S_ENV         0x04

#define SUPPORT_METRICS_RAW     0x01
#define SUPPORT_METRICS_TELEM   0x02


#define L7PROBE_TRACING_HTTP    0x0001
#define L7PROBE_TRACING_DNS     0x0002
#define L7PROBE_TRACING_REDIS   0x0004
#define L7PROBE_TRACING_MYSQL   0x0008
#define L7PROBE_TRACING_PGSQL   0x0010
#define L7PROBE_TRACING_KAFKA   0x0020
#define L7PROBE_TRACING_MONGO   0x0040
#define L7PROBE_TRACING_CQL     0x0080
#define L7PROBE_TRACING_NATS    0x0100

/*
    copy struct probe_params code to python.probe/ipc.py.
    if modify struct probe_params, please sync change to the class ProbeParams in ipc.py
*/
struct probe_params {
    unsigned int period;               // Report period, unit second, default is 5 seconds
    unsigned int sample_period;        // Sampling period, unit milliseconds, default is 100 milliseconds
    unsigned int latency_thr;          // Threshold of latency time, unit ms, default is 0 milliseconds
    unsigned int offline_thr;          // Threshold of offline time, unit ms, default is 0 milliseconds
    unsigned int drops_count_thr;      // Threshold of the number of drop packets, default is 0
    unsigned int kafka_port;           // the port to which kafka server attach.
    char logs;                         // Enable the logs function
    char metrics_flags;                // Support for report metrics flags(0x01(raw metrics), 0x02(openTelemetry metrics, eg.. P50/P90/P99) );
    char env_flags;                    // Support for env flags(default 0x01(node), 0x02(container), 0x04(K8S));
    char support_ssl;                  // Support for SSL probe;
    char res_percent_upper;            //  Upper limit of resource percentage, default is 0%
    char res_percent_lower;            //  Lower limit of resource percentage, default is 0%
    char continuous_sampling_flag;     //  Enables the continuous sampling, default is 0
    char multi_instance_flag;            //  Enables output of individual flame graphs for each process, default is 0
    char native_stack_flag;            //  Enables output of native language call stack (only for java process), default is 0
    char cluster_ip_backend;           // [-n <>] Indicates whether transform cluster IP address to backend, default is 0 (no transform)
    char target_dev[DEV_NAME];         //  Device name, default is null
    char elf_path[MAX_PATH_LEN];       //  Set ELF file path of the monitored software, default is null
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
    unsigned int svg_period;
    unsigned int perf_sample_period;
    char pyroscope_server[PYSCOPE_SERVER_URL_LEN];
    char svg_dir[PATH_LEN];
    char flame_dir[PATH_LEN];
    unsigned int cadvisor_port;         // the port which cadvisor start.
};


#endif
