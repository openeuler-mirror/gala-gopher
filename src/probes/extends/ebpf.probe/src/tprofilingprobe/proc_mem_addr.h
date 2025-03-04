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
 * Create: 2024-10-24
 * Description: process memory address map
 ******************************************************************************/
#ifndef __PROC_MEM_ADDR_H__
#define __PROC_MEM_ADDR_H__

#include "common.h"
#include "hash.h"

struct mem_alloc_key_s {
    u32 proc_id;
    u64 addr;
};

struct mem_alloc_s {
    struct mem_alloc_key_s key;
    u64 size;
    void *symb_addr;    // 若值为NULL，则表示当前保存的是一个free事件
    u64 ts; 
    H_HANDLE;
};

#define MEM_ALLOC_TBL_MAX_NUM 1000000   // 用于限制表的最大内存占用不超过100M

int mem_alloc_tbl_add_item(struct mem_alloc_s **mem_alloc_tbl, u32 proc_id, u64 addr, u64 ts,
    void *symb_addr, u64 size);
struct mem_alloc_s *mem_alloc_tbl_find_item(struct mem_alloc_s **mem_alloc_tbl, u32 proc_id, u64 addr);
void mem_alloc_tbl_delete_item(struct mem_alloc_s **mem_alloc_tbl, struct mem_alloc_s *item);
void destroy_mem_alloc_tbl(struct mem_alloc_s **mem_alloc_tbl);

#endif