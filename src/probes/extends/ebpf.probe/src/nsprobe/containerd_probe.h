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
 * Create: 2022-06-6
 * Description: container traceing
 ******************************************************************************/
#ifndef __CONTAINERPROBE__H
#define __CONTAINERPROBE__H

#pragma once

#include "args.h"
#include "hash.h"

#define CONTAINER_KEY_LEN (CONTAINER_ABBR_ID_LEN + 4)
struct container_key {
    char container_id[CONTAINER_KEY_LEN];
};

#define CONTAINER_FLAGS_VALID       0x02
struct container_value {
    u32 flags;                              // flags
    u32 proc_id;                            // First process id of container
    u32 cpucg_inode;                        // cpu group inode of container
    u32 memcg_inode;                        // memory group inode of container
    u32 pidcg_inode;                        // pids group inode of container
    u32 mnt_ns_id;                          // Mount namespace id of container
    u32 net_ns_id;                          // Net namespace id of container

    unsigned long long bps;
    char name[CONTAINER_NAME_LEN];           // Name of container

    char cpucg_dir[PATH_LEN];
    char memcg_dir[PATH_LEN];
    char pidcg_dir[PATH_LEN];
    char netcg_dir[PATH_LEN];
};

struct container_hash_t {
    H_HANDLE;
    struct container_key k;
    struct container_value v;
};

struct container_value* get_container_by_proc_id(struct container_hash_t **pphead,
                                                            u32 proc_id);
void get_containers(struct container_hash_t **pphead, struct probe_params_deprecated *params);
void put_containers(struct container_hash_t **pphead);

#endif /* __TRACE_CONTAINERD__H */
