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
 * Author: Mr.lu
 * Create: 2022-08-18
 * Description: elf symb
 ******************************************************************************/
#ifndef __GOPHER_ELF_SYMB_H__
#define __GOPHER_ELF_SYMB_H__

#pragma once

#include "symbol.h"

struct elf_symbo_s* get_elf_symb(const char* elf);
void rm_elf_symb(struct elf_symbo_s* elf_symb);
int search_elf_symb(struct elf_symbo_s* elf_symb,
        u64 orign_addr, u64 target_addr, const char* comm, struct addr_symb_s* addr_symb);
void deinit_elf_symbs(void);

#endif
