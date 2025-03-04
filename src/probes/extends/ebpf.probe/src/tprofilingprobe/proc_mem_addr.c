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
#include <stdlib.h>

#include "tprofiling.h"
#include "proc_mem_addr.h"

int mem_alloc_tbl_add_item(struct mem_alloc_s **mem_alloc_tbl, u32 proc_id, u64 addr, u64 ts,
    void *symb_addr, u64 size)
{
    struct mem_alloc_s *new_item = NULL;

    if (H_COUNT(*mem_alloc_tbl) >= MEM_ALLOC_TBL_MAX_NUM) {
        TP_ERROR("Failed to add mem alloc item: reach max limit\n");
        return -1;
    }

    new_item = (struct mem_alloc_s *)malloc(sizeof(struct mem_alloc_s));
    if (new_item == NULL) {
        TP_ERROR("Failed to add mem alloc item: malloc failed\n");
        return -1;
    }
    memset(new_item, 0, sizeof(struct mem_alloc_s));
    new_item->key.proc_id = proc_id;
    new_item->key.addr = addr;
    new_item->ts = ts;
    new_item->symb_addr = symb_addr;
    new_item->size = size;
    H_ADD(*mem_alloc_tbl, key, sizeof(new_item->key), new_item);
    return 0;
}

struct mem_alloc_s *mem_alloc_tbl_find_item(struct mem_alloc_s **mem_alloc_tbl, u32 proc_id, u64 addr)
{
    struct mem_alloc_key_s key = {0};
    key.addr =addr;
    key.proc_id = proc_id;
    struct mem_alloc_s *item = NULL;
    H_FIND(*mem_alloc_tbl, &key, sizeof(key), item);
    return item;
}

void mem_alloc_tbl_delete_item(struct mem_alloc_s **mem_alloc_tbl, struct mem_alloc_s *item)
{
    H_DEL(*mem_alloc_tbl, item);
    free(item);
}
