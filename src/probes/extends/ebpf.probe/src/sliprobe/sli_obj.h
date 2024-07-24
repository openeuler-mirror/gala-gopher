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

enum sli_io_lat_t {
    SLI_IO_LAT_0_1 = 0,
    SLI_IO_LAT_1_5,
    SLI_IO_LAT_5_10,
    SLI_IO_LAT_10_100,
    SLI_IO_LAT_100_500,
    SLI_IO_LAT_500_1000,
    SLI_IO_LAT_1000_INTF,
    SLI_IO_LAT_NR
};

enum sli_mem_lat_t {
    SLI_MEM_LAT_0_1 = 0,
    SLI_MEM_LAT_1_5,
    SLI_MEM_LAT_5_10,
    SLI_MEM_LAT_10_100,
    SLI_MEM_LAT_100_500,
    SLI_MEM_LAT_500_1000,
    SLI_MEM_LAT_1000_INTF,
    SLI_MEM_LAT_NR
};

enum sli_cpu_lat_t {
    SLI_CPU_LAT_0_1 = 0,
    SLI_CPU_LAT_1_5,
    SLI_CPU_LAT_5_10,
    SLI_CPU_LAT_10_100,
    SLI_CPU_LAT_100_500,
    SLI_CPU_LAT_500_1000,
    SLI_CPU_LAT_1000_INTF,
    SLI_CPU_LAT_NR
};

static __always_inline __maybe_unused enum sli_cpu_lat_t get_sli_cpu_lat_type(u64 delay_ns)
{
    u64 delay_ms = delay_ns >> 6; // ms
    enum sli_cpu_lat_t idx;

    if (delay_ms < 1)
        idx = SLI_CPU_LAT_0_1;
    else if (delay_ms < 5)
        idx = SLI_CPU_LAT_1_5;
    else if (delay_ms < 10)
        idx = SLI_CPU_LAT_5_10;
    else if (delay_ms < 100)
        idx = SLI_CPU_LAT_10_100;
    else if (delay_ms < 500)
        idx = SLI_CPU_LAT_100_500;
    else if (delay_ms < 1000)
        idx = SLI_CPU_LAT_500_1000;
    else
        idx = SLI_CPU_LAT_1000_INTF;
    
    return idx;
}

static __always_inline __maybe_unused enum sli_mem_lat_t get_sli_mem_lat_type(u64 delay_ns)
{
    u64 delay_ms = delay_ns >> 6; // ms
    enum sli_mem_lat_t idx;

    if (delay_ms < 1)
        idx = SLI_MEM_LAT_0_1;
    else if (delay_ms < 5)
        idx = SLI_MEM_LAT_1_5;
    else if (delay_ms < 10)
        idx = SLI_MEM_LAT_5_10;
    else if (delay_ms < 100)
        idx = SLI_MEM_LAT_10_100;
    else if (delay_ms < 500)
        idx = SLI_MEM_LAT_100_500;
    else if (delay_ms < 1000)
        idx = SLI_MEM_LAT_500_1000;
    else
        idx = SLI_MEM_LAT_1000_INTF;
    
    return idx;
}

static __always_inline __maybe_unused enum sli_io_lat_t get_sli_io_lat_type(u64 delay_ns)
{
    u64 delay_ms = delay_ns >> 6; // ms
    enum sli_io_lat_t idx;

    if (delay_ms < 1)
        idx = SLI_IO_LAT_0_1;
    else if (delay_ms < 5)
        idx = SLI_IO_LAT_1_5;
    else if (delay_ms < 10)
        idx = SLI_IO_LAT_5_10;
    else if (delay_ms < 100)
        idx = SLI_IO_LAT_10_100;
    else if (delay_ms < 500)
        idx = SLI_IO_LAT_100_500;
    else if (delay_ms < 1000)
        idx = SLI_IO_LAT_500_1000;
    else
        idx = SLI_IO_LAT_1000_INTF;
    
    return idx;
}

struct sli_cpu_lat_s {
    u32 cnt[SLI_CPU_LAT_NR];
};

struct sli_mem_lat_s {
    u32 cnt[SLI_MEM_LAT_NR];
};

struct sli_io_lat_s {
    u32 cnt[SLI_IO_LAT_NR];
};

struct sli_cpu_s {
    struct sli_cpu_lat_s cpu_lats[SLI_CPU_MAX];
    u64 lat_ns[SLI_CPU_MAX];
};

struct sli_mem_s {
    struct sli_mem_lat_s mem_lats[SLI_MEM_MAX];
    u64 lat_ns[SLI_MEM_MAX];
};

struct sli_io_s {
    struct sli_io_lat_s io_lats;
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
