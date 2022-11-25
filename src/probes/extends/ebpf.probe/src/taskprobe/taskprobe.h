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
 * Description: task_probe include file
 ******************************************************************************/
#ifndef __TASKPROBE__H
#define __TASKPROBE__H

#include "common.h"
#include "hash.h"
#include "whitelist_config.h"

struct proc_id_s {
    H_HANDLE;
    u32 id;
    char comm[TASK_COMM_LEN];
};

struct task_probe_s {
    struct probe_params params;
    struct proc_id_s *procs;
    ApplicationsConfig *conf;
    int args_fd;
    int thread_map_fd;
    int proc_map_fd;
};

void load_thread2bpf(u32 proc_id, int fd);
void load_proc2bpf(u32 proc_id, const char *comm, int fd);

#endif
