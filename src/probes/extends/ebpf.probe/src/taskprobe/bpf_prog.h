/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: luzhihao
 * Create: 2022-07-13
 * Description: bpf load prog
 ******************************************************************************/
#ifndef __BPF_PROG__H
#define __BPF_PROG__H

#pragma once

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "common.h"
#include "ipc.h"
#include "__libbpf.h"
#include "glibc_probe.h"

#define THREAD_OUTPUT_PATH "/sys/fs/bpf/gala-gopher/__taskprobe_thread_output"
#define PROC_OUTPUT_PATH "/sys/fs/bpf/gala-gopher/__taskprobe_proc_output"
#define ARGS_PATH "/sys/fs/bpf/gala-gopher/__taskprobe_args"
#define THREAD_PATH "/sys/fs/bpf/gala-gopher/__taskprobe_thread"
#define PROC_PATH "/sys/fs/bpf/gala-gopher/__taskprobe_proc"

#define GLIBC_EBPF_PROG_MAX 256
struct glibc_ebpf_prog_s {
    char *glibc_path;
    struct bpf_prog_s* prog;
};

struct task_probe_s {
    struct ipc_body_s ipc_body;
    struct bpf_prog_s* thread_bpf_progs;
    struct bpf_prog_s* proc_bpf_progs;
    struct dns_entry_s *dns_entrys;
    struct glibc_ebpf_prog_s glibc_bpf_progs[GLIBC_EBPF_PROG_MAX];
    int args_fd;
    int proc_map_fd;
};

void destroy_dns_entrys(struct task_probe_s *task_probe);
void scan_dns_entrys(struct task_probe_s *task_probe);
int load_glibc_bpf_prog(struct task_probe_s *task_probe, const char *glibc_path, struct bpf_prog_s **new_prog);
int load_thread_bpf_prog(struct task_probe_s *task_probe, struct ipc_body_s *ipc_body, struct bpf_prog_s **new_prog);
int load_proc_bpf_prog(struct task_probe_s *task_probe, struct ipc_body_s *ipc_body, struct bpf_prog_s **new_prog);

#endif
