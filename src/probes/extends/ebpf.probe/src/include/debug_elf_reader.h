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
 * Description: DEBUG ELF reader
 ******************************************************************************/
#ifndef __GOPHER_DEBUG_ELF_READER_H__
#define __GOPHER_DEBUG_ELF_READER_H__

#pragma once

#include "hash.h"
#include "symbol.h"

struct elf_reader_s {
    char global_dbg_dir[PATH_LEN];  // Must NOT end with '/' 
};

struct elf_reader_s* create_elf_reader(const char *global_dbg_dir);
void destroy_elf_reader(struct elf_reader_s* reader);

int get_elf_debug_file(struct elf_reader_s* reader, struct proc_symbs_s* proc_symbs,
        const char* elf, const char* elf_link, char debug_file[], size_t len);


#endif
