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
 * Author: Vchanger
 * Create: 2023-04-30
 * Description: ipc api
 ******************************************************************************/
#ifndef __IPC_H__
#define __IPC_H__

#include <sys/ipc.h>
#include <sys/msg.h>

#include "common.h"
#include "args.h"
#include "object.h"

#define SNOOPER_MAX    100

/* FlameGraph subprobe define */
#define PROBE_RANGE_ONCPU       0x00000001
#define PROBE_RANGE_OFFCPU      0x00000002
#define PROBE_RANGE_MEM         0x00000004
#define PROBE_RANGE_IO          0x00000008

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
#define PROBE_RANGE_TCP_DELAY       0x00000080

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
#define PROBE_RANGE_PROC_NET        0x00000020
#define PROBE_RANGE_PROC_OFFCPU     0x00000040

/* system_infos subprobe define */
#define PROBE_RANGE_SYS_CPU         0x00000001
#define PROBE_RANGE_SYS_MEM         0x00000002
#define PROBE_RANGE_SYS_NIC         0x00000004
#define PROBE_RANGE_SYS_NET         0x00000008
#define PROBE_RANGE_SYS_DISK        0x00000010
#define PROBE_RANGE_SYS_FS          0x00000020
#define PROBE_RANGE_SYS_PROC        0x00000040
#define PROBE_RANGE_SYS_HOST        0x00000080

/* tprofiling subprobe define */
#define PROBE_RANGE_TPROFILING_ONCPU            0x00000001
#define PROBE_RANGE_TPROFILING_SYSCALL_FILE     0x00000002
#define PROBE_RANGE_TPROFILING_SYSCALL_NET      0x00000004
#define PROBE_RANGE_TPROFILING_SYSCALL_SCHED    0x00000008
#define PROBE_RANGE_TPROFILING_SYSCALL_LOCK     0x00000010

/* hardware subprobe define */
#define PROBE_RANGE_HW_NIC          0x00000001
#define PROBE_RANGE_HW_MEM          0x00000002

/* sched subprobe define */
#define PROBE_RANGE_SCHED_SYSTIME   0x00000001
#define PROBE_RANGE_SCHED_SYSCALL   0x00000002

/*
    copy probe_type_e, snooper_obj_e, snooper_con_info_s, snooper_obj_s, ipc_body_s code to python.probe/ipc.py.
    if modify above struct , please sync change to ipc.py
*/
enum probe_type_e {
    PROBE_BASEINFO = 1,
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
    PROBE_TP,
    PROBE_HW,
    PROBE_KSLI,
    PROBE_SCHED,
    PROBE_CONTAINER,

    // If you want to add a probe, add the probe type.

    PROBE_TYPE_MAX
};

enum snooper_obj_e {
    SNOOPER_OBJ_PROC = 0,
    SNOOPER_OBJ_CON,
    SNOOPER_OBJ_GAUSSDB,

    SNOOPER_OBJ_MAX
};

struct snooper_gaussdb_s {
    u32 port;
    char *ip;
    char *dbname;
    char *usr;
    char *pass;
};

struct snooper_con_info_s {
    u32 flags;
    u32 cpucg_inode;
    char *con_id;
    char *container_name;
    char *libc_path;
    char *libssl_path;
    // pod_info
    char *pod_id;
    char *pod_ip_str;
};

struct snooper_obj_s {
    enum snooper_obj_e type;
    union {
        struct proc_s proc;
        struct snooper_con_info_s con_info;
        struct snooper_gaussdb_s gaussdb;
    } obj;
};

#define IPC_FLAGS_SNOOPER_CHG   0x00000001
#define IPC_FLAGS_PARAMS_CHG    0x00000002
struct ipc_body_s {
    u32 probe_range_flags;                              // Refer to flags defined [PROBE_RANGE_XX_XX]
    u32 snooper_obj_num;
    u32 probe_flags;
    struct probe_params probe_param;
    struct snooper_obj_s snooper_objs[SNOOPER_MAX];
};

int create_ipc_msg_queue(int ipc_flag);
void destroy_ipc_msg_queue(int msqid);
int send_ipc_msg(int msqid, long msg_type, struct ipc_body_s *ipc_body);
int recv_ipc_msg(int msqid, long msg_type, struct ipc_body_s *ipc_body);
void clear_ipc_msg(long msg_type);
void destroy_ipc_body(struct ipc_body_s *ipc_body);
#endif
