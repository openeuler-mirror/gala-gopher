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
 * Author: dowzyx
 * Create: 2022-06-19
 * Description: include file for system_disk
 ******************************************************************************/
#ifndef SYSTEM_DISK_RPOBE__H
#define SYSTEM_DISK_RPOBE__H

#pragma once

#include "args.h"
#include "common.h"

/* the interval of time (@p) is given in second */
#define S_VALUE(m,n,p)      (((double) ((n) - (m))) / (p))

#define FSTYPE_LEN  64
#define MOUNTON_LEN 128
typedef struct {
    char fsys_type[FSTYPE_LEN];
    char mount_on[MOUNTON_LEN];
    long inode_or_blk_sum;
    long inode_or_blk_used;
    long inode_or_blk_free;
    long inode_or_blk_used_per;
} df_stats;

typedef struct {
    // u32 major;
    // u32 minor;
    char disk_name[DISK_NAME_LEN];
    u32 rd_ios;
    // u32 rd_merges;
    u32 rd_sectors;
    u32 rd_ticks;
    u32 wr_ios;
    // u32 wr_merges;
    u32 wr_sectors;
    u32 wr_ticks;
    // u32 in_flight;
    u32 io_ticks;
    // u32 time_in_queue;
    // u32 discard_ios;
    // u32 discard_merges;
    // u32 discard_sectors;
    // u32 discard_ticks;
} disk_stats;

typedef struct {
    float rd_speed;
    float rdkb_speed;
    float rd_await;
    float rareq_sz;
    float wr_speed;
    float wrkb_speed;
    float wr_await;
    float wareq_sz;
    float util;
} disk_io_stats;

int system_disk_probe(struct probe_params *params);
int system_iostat_probe(struct probe_params *params);
int system_iostat_init(void);
void system_iostat_destroy(void);

#endif
