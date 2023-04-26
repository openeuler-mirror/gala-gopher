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

#define JAVASYMB_NAME_LEN  128

enum sym_file_t {
    ELF_SYM = 0,
    JAVA_SYM = 1
};

struct elf_symbo_s* update_symb_from_jvm_sym_file(const char* elf);
struct elf_symbo_s* get_symb_from_file(const char* elf, enum sym_file_t sym_file_type);
void rm_elf_symb(struct elf_symbo_s* elf_symb);
int search_elf_symb(struct elf_symbo_s* elf_symb,
        u64 orign_addr, u64 target_addr, const char* comm, struct addr_symb_s* addr_symb);
void deinit_elf_symbs(void);

#endif
