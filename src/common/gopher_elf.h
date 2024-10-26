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
 * Description: elf defined
 ******************************************************************************/
#ifndef __GOPHER_ELF_H__
#define __GOPHER_ELF_H__

#pragma once

#include "common.h"

/**
* return code1: -1
* return code2: refer to /usr/include/elf.h
* #define ET_NONE         0
* #define ET_REL          1
* #define ET_EXEC         2
* #define ET_DYN          3
* #define ET_CORE         4
* #define ET_NUM          5
* #define ET_LOOS         0xfe00
* #define ET_HIOS         0xfeff
* #define ET_LOPROC       0xff00
* #define ET_HIPROC       0xffff
*/
int gopher_get_elf_type(const char *elf_file);
int gopher_get_elf_text_section(const char *elf_file, u64 *addr, u64 *offset);

typedef enum elf_sym_cb_e {
    ELF_SYMB_CB_OK = 0,
    ELF_SYMB_CB_BREAK = 1,
    ELF_SYMB_CB_ERR = -1
} ELF_CB_RET;
/*
* ret val: 0  succeed; -1 failed; 1 break;
*/
typedef ELF_CB_RET (*elf_sym_cb)(const char *symb, u64 addr_start, u64 size, void *ctx);
int gopher_iter_elf_fd_symb(int fd, elf_sym_cb cb, void *ctx);
int gopher_iter_elf_file_symb(const char *elf_file, elf_sym_cb cb, void *ctx);
int gopher_get_elf_symb(const char *elf_file, char *symb_name, u64 *symb_offset);
int gopher_get_elf_symb_addr(const char *elf_file, char *symb_name, u64 *symb_addr);
int gopher_get_elf_build_id(const char *elf_file, char build_id[], size_t len);
int gopher_get_elf_debug_link(const char *elf_file, char debug_link[], size_t len);
u64 get_func_offset_by_build_id(const char *build_id, const char *func_name);

#endif
