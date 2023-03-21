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
 * Author: wo_cow
 * Create: 2023-03-15
 * Description: uprobe loader header file
 ******************************************************************************/
#ifndef __UPROBE_LOADER_H__
#define __UPROBE_LOADER_H__

#include <signal.h>
#include "hash.h"
#include "args.h"

enum proc_attach_state_t {
    PID_NOEXIST,
    PID_ELF_NO_NEED_ATTACHED,
    PID_ELF_TOBE_ATTACHED,
    PID_ELF_ATTACHED
};

#define MAX_BPF_PROGS 32
struct proc_bpf_s {
    enum proc_attach_state_t pid_state;
    char elf_path[MAX_PATH_LEN];
    int bpf_link_num;
    struct bpf_link *bpf_links[MAX_BPF_PROGS];
};

struct proc_bpf_hash_t {
    H_HANDLE;
    int pid; // key
    struct proc_bpf_s v; // value
};

struct proc_load_args_s {
    int proc_obj_map_fd;
    int *init;
    const char *libname;
    struct bpf_object *bpf_obj;
};

void *load_n_unload_uprobe(void *arg);

#endif
