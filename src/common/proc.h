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
 * Author: 
 * Create: 
 * Description: 
 ******************************************************************************/

#ifndef __PROC_H__
#define __PROC_H__

#include "hash.h"

#define MAX_CACHE_SIZE  10000

struct proc_info {
    char container_id[CONTAINER_ID_LEN];
    char container_name[CONTAINER_NAME_LEN];
    char pod_name[POD_NAME_LEN];
};

struct tgid_info_hash_t
{
    unsigned int tgid;          // key
    struct proc_info info;      // val
    H_HANDLE;
};

int add_to_cache_with_LRU(struct tgid_info_hash_t **tgid_infos, unsigned int tgid, struct proc_info *info);
int find_in_cache_with_LRU(struct tgid_info_hash_t **tgid_infos, unsigned int tgid, struct proc_info *info);
int get_proc_info_by_tgid(unsigned int tgid, struct proc_info *info);
struct proc_info * look_up_proc_info_by_tgid(struct tgid_info_hash_t **tgid_infos, unsigned int tgid);

#endif
