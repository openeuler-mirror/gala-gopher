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
 * Author: luzhihao
 * Create: 2024-04-17
 * Description: sli probe
 ******************************************************************************/
#ifndef __SLI_OBJ_H__
#define __SLI_OBJ_H__

#pragma once

typedef u64 cpu_cgrp_inode_t;
#define CPUACCT_GLOBAL_CGPID    (-1)

enum sli_cpu_t {
    SLI_CPU_WAIT = 0,
    SLI_CPU_SLEEP,
    SLI_CPU_IOWAIT,
    SLI_CPU_BLOCK,
    SLI_CPU_RUNDELAY,
    SLI_CPU_LONGSYS,
    SLI_CPU_MAX
};

enum sli_mem_t {
    SLI_MEM_RECLAIM = 0,
    SLI_MEM_COMPACT,
    SLI_MEM_SWAPIN,
    SLI_MEM_MAX
};

struct sli_cpu_s {
    u64 lat_ns[SLI_CPU_MAX];
};

struct sli_mem_s {
    u64 lat_ns[SLI_MEM_MAX];
};

struct sli_io_s {
    u64 lat_ns;
};

struct sli_cpu_obj_s {
    u64 last_report;
    u32 cpu_cgroup_inode;
    struct sli_cpu_s sli;
};

struct sli_mem_obj_s {
    u64 last_report;
    u32 cpu_cgroup_inode;
    struct sli_mem_s sli;
};

struct sli_io_obj_s {
    u64 last_report;
    u32 cpu_cgroup_inode;
    struct sli_io_s sli;
};


struct sli_args_s {
    u64 report_period;
};


#endif
