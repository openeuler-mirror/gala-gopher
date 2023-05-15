/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: luzhihao
 * Create: 2023-04-06
 * Description: probe managment
 ******************************************************************************/
#ifndef __PROBE_MNG_H__
#define __PROBE_MNG_H__

#pragma once
#include <stdint.h>
#include <pthread.h>

#include "base.h"
#include "fifo.h"
#include "args.h"


/* FlameGraph subprobe define */
#define PROBE_RANGE_ONCPU       0x00000001
#define PROBE_RANGE_OFFCPU      0x00000002
#define PROBE_RANGE_MEM         0x00000004


/* L7 subprobe define */
#define PROBE_RANGE_L7BYTES_METRICS 0x00000001
#define PROBE_RANGE_L7RPC_METRICS   0x00000002
#define PROBE_RANGE_L7RPC_TRACE     0x00000004

/* tcp subprobe define */
#define PROBE_RANGE_TCP_ABNORMAL    0x00000001
#define PROBE_RANGE_TCP_WINDOWS     0x00000002
#define PROBE_RANGE_TCP_RTT         0x00000004
#define PROBE_RANGE_TCP_STATS       0x00000008
#define PROBE_RANGE_TCP_SOCKBUF     0x00000010
#define PROBE_RANGE_TCP_RATE        0x00000020
#define PROBE_RANGE_TCP_SRTT        0x00000040

/* socket subprobe define */
#define PROBE_RANGE_SOCKET_TCP      0x00000001
#define PROBE_RANGE_SOCKET_UDP      0x00000002

/* io subprobe define */
#define PROBE_RANGE_IO_TRACE        0x00000001
#define PROBE_RANGE_IO_ERR          0x00000002
#define PROBE_RANGE_IO_COUNT        0x00000004
#define PROBE_RANGE_IO_PAGECACHE    0x00000008

/* proc subprobe define */
#define PROBE_RANGE_PROC_SYSCALL    0x00000001
#define PROBE_RANGE_PROC_FS         0x00000002
#define PROBE_RANGE_PROC_DNS        0x00000004
#define PROBE_RANGE_PROC_IO         0x00000008
#define PROBE_RANGE_PROC_PAGECACHE  0x00000010
#define PROBE_RANGE_PROC_BASIC      0x00000020

#define PROBE_FLAGS_STARTED         0x00000001    // probe has been tried to start by user
#define PROBE_FLAGS_STOPPED         0x00000002    // probe is in stopped state
#define PROBE_FLAGS_STOPPING        0x00000004    // probe has been tried to stop by user
#define PROBE_FLAGS_RUNNING         0x00000008    // probe is in running state

#define SNOOPER_MAX    100

enum probe_type_e {
    PROBE_BASEINFO = 0,
    PROBE_VIRT,

    /* The following are extended probes. */
    PROBE_FG,
    PROBE_L7,
    PROBE_TCP,
    PROBE_SOCKET,
    PROBE_IO,
    PROBE_PROC,
    PROBE_JVM,
    PROBE_REDIS_SLI,
    PROBE_POSTGRE_SLI,
    PROBE_GAUSS_SLI,
    PROBE_DNSMASQ,
    PROBE_LVS,
    PROBE_NGINX,
    PROBE_HAPROXY,
    PROBE_KAFKA,

    PROBE_TYPE_MAX
};

struct probe_define_s {
    char *desc;
    enum probe_type_e type;
};

typedef int (*ParseParam)(const char*, struct probe_params *);
struct param_define_s {
    char *desc;
    ParseParam parser;
};

struct probe_status_s {
    u64 last_starting_timestamp;
    u32 status_flags;                                   // Refer to flags defined [PROBE_FLAGS_XXX]
};

typedef int (*ProbeMain)(struct probe_params *);
typedef void *(*ProbeCB)(void *);
struct probe_s {
    char *name;                                         // Name for probe
    char *bin;                                          // Execute bin file for probe
    char *chk_cmd;                                      // Startup precondition for probe
    int is_extend_probe;                                // 0: Native probe, otherwise extend probe
    enum probe_type_e probe_type;
    u32 probe_range_flags;                              // Refer to flags defined [PROBE_RANGE_XX_XX]
    ProbeMain probe_entry;                              // Main function for native probe
    ProbeCB cb;                                         // Thread cb for probe
    Fifo *fifo;                                         // Data channel for probe, !!!NOTICE: context in probe-thread
    pthread_t tid;                                      // Thread for admin probe

    int pid;                                            // PID of extend probe process(Invalid value -1), wr&rd by rest/probe/probe-mng thread
    struct probe_status_s probe_status;                 // Status of probe, wr&rd by rest/probe/probe-mng thread
    pthread_rwlock_t rwlock;                            // Used to exclusive operations between multi-thread.

    u32 snooper_conf_num;
    struct snooper_conf_s *snooper_confs[SNOOPER_MAX];  // snooper config, wr&rd by rest/probe-mng thread
    struct snooper_obj_s *snooper_objs[SNOOPER_MAX];    // snooper object, wr&rd by rest/probe-mng thread

    struct probe_params probe_param;                    // params for probe
};

struct probe_mng_s {
    int msq_id;                                         // ipc control msg channnel
    struct probe_s *probes[PROBE_TYPE_MAX];
    void *snooper_skel;
    void *snooper_proc_pb;                              // context in perf event
    void *snooper_cgrp_pb;                              // context in perf event
    int ingress_epoll_fd;                               // !!!NOTICE: NO NEED FREE.
    pthread_t tid;                                      // probe mng thread, used to poll perf event
    time_t keeplive_ts;                                 // Used to keeplive probe

    pthread_rwlock_t rwlock;                            // Exclusive operations between rest-api event and perf event.

};

#define IS_EXTEND_PROBE(probe)  (probe->is_extend_probe)
#define IS_NATIVE_PROBE(probe)  (!probe->is_extend_probe)

void *extend_probe_thread_cb(void *arg);
void *native_probe_thread_cb(void *arg);

void run_probe_mng_daemon(struct probe_mng_s*);
int parse_probe_json(const char *probe_name, const char *probe_content);
char *get_probe_json(const char *probe_name);
struct probe_mng_s *create_probe_mng(void);
void destroy_probe_mng(void);

u32 get_probe_status_flags(struct probe_s* probe);
void set_probe_status_flags(struct probe_s* probe, u32 flags);
void unset_probe_status_flags(struct probe_s* probe, u32 flags);

#define IS_STOPPED_PROBE(probe)      (get_probe_status_flags(probe) & PROBE_FLAGS_STOPPED)
#define IS_STARTED_PROBE(probe)      (get_probe_status_flags(probe) & PROBE_FLAGS_STARTED)
#define IS_STOPPING_PROBE(probe)     (get_probe_status_flags(probe) & PROBE_FLAGS_STOPPING)
#define IS_RUNNING_PROBE(probe)      (get_probe_status_flags(probe) & PROBE_FLAGS_RUNNING)

#define SET_PROBE_FLAGS(probe, flags)       set_probe_status_flags(probe, flags)
#define UNSET_PROBE_FLAGS(probe, flags)     unset_probe_status_flags(probe, flags)

#endif