
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
 * Create: 2023-06-12
 * Description: the header file of sched probe
 ******************************************************************************/
#ifndef __BPF_PROG_H__
#define __BPF_PROG_H__

#pragma once

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "kern_symb.h"
#include "ipc.h"

#define SCHED_PROBE_SYSTIME     (u32)(1)
#define SCHED_PROBE_SYSCALL     (u32)(1 << 1)
#define SCHED_PROBE_ALL         (u32)(SCHED_PROBE_SYSTIME | SCHED_PROBE_SYSCALL)

/* Path to pin map */
#define SCHED_ARGS_PATH            "/sys/fs/bpf/gala-gopher/__sched_args"
#define SCHED_REPORT_CHANNEL_PATH  "/sys/fs/bpf/gala-gopher/__sched_report_channel"

#define RM_SCHED_PATH              "/usr/bin/rm -rf /sys/fs/bpf/gala-gopher/__sched*"

#define __LOAD_SCHED_LATENCY(probe_name, end, load) \
    OPEN(probe_name, end, load); \
    MAP_SET_PIN_PATH(probe_name, sched_args_map, SCHED_ARGS_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, sched_report_channel_map, SCHED_REPORT_CHANNEL_PATH, load); \
    LOAD_ATTACH(schedprobe, probe_name, end, load)

struct sched_probe_s {
    struct ipc_body_s ipc_body;
    struct bpf_prog_s *sched_prog;
    struct ksymb_tbl_s *ksymbs;
    int sched_args_fd;
    int sched_syscall_stackmap_fd;
    int sched_systime_stackmap_fd;
};

int load_sched_bpf_prog(struct ipc_body_s *ipc_body, struct sched_probe_s *sched_probe);

void clean_map_files();

#endif