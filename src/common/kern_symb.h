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
 * Create: 2022-11-7
 * Description: kernel symb
 ******************************************************************************/
#ifndef __KERN_SYMB_H__
#define __KERN_SYMB_H__

#pragma once

#include "common.h"
#include "hash.h"

struct ksymb_s {
    u64 addr;
    char *sym;
    char *kmod;
};

struct ksymb_tbl_s {
    u32 ksym_size;
    struct ksymb_s ksyms[];
};

struct addr_symb_s {
    char *sym;      // No release is required.
    char *mod;      // No release is required.
    u64 orign_addr;
    u64 relat_addr;
    u64 offset;
};

void destroy_ksymbs_tbl(struct ksymb_tbl_s *ksym_tbl);
struct ksymb_tbl_s* create_ksymbs_tbl(void);
int search_kern_addr_symb(struct ksymb_tbl_s *ksymbs, u64 addr, struct addr_symb_s *addr_symb);
int sort_kern_syms(struct ksymb_tbl_s *ksymbs);
int load_kern_syms(struct ksymb_tbl_s *ksymbs);

#endif
