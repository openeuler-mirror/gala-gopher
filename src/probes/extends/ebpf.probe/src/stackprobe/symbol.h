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
 * Create: 2022-02-18
 * Description: symbol defined
 ******************************************************************************/
#ifndef __GOPHER_SYMBOL_H__
#define __GOPHER_SYMBOL_H__

#pragma once

#include "kern_symb.h"

#define MOD_MAX_COUNT       1000
#define SYMBS_MAX_COUNT     1000000
#define SYMBS_STEP_COUNT    1000
enum module_type {
    MODULE_UNKNOW = 0,
    MODULE_SO = 1,
    MODULE_EXEC = 2,
    MODULE_JVM,
    MODULE_MAP,
    MODULE_VDSO         /* The virtual dynamically linked shared object. */
};

struct symb_s {
    char *symb_name;
    u64 start;
    u64 size;
};

struct mod_addr_rage_s {
    u64 start;
    u64 end;
    u64 f_offset;
};

struct mod_info_s {
    enum module_type type;
    char *name;
    char *path;
    u64 elf_so_addr;
    u64 elf_so_offset;

    u64 start;
    u64 end;
    u64 f_offset;

    u64 inode;
};

struct elf_symbo_s {
    H_HANDLE;
    u32 i_inode;
    u32 refcnt;
    char *elf;
    long elf_offset; // for jvm symbols 
    u32 symbs_count;
    u32 symbs_capability;
    struct symb_s** __symbs;
};

#define MOD_ADDR_RANGE_COUNT 100
struct mod_s {
    struct mod_info_s __mod_info;
    #define mod_type            __mod_info.type
    #define mod_name            __mod_info.name
    #define mod_path            __mod_info.path
    #define mod_elf_so_addr     __mod_info.elf_so_addr
    #define mod_elf_so_offset   __mod_info.elf_so_offset
    #define mod_start           __mod_info.start
    #define mod_end             __mod_info.end
    #define mod_f_offset        __mod_info.f_offset
    #define mod_inode           __mod_info.inode

    u32 addr_ranges_count;
    struct mod_addr_rage_s addr_ranges[MOD_ADDR_RANGE_COUNT];

    struct elf_symbo_s *debug_symbs;
    void *elf_reader;   // No release is required.

    struct elf_symbo_s *mod_symbs;
};

struct proc_symbs_s {
    int proc_id;
    char comm[TASK_COMM_LEN];
    int is_java;
    int need_update; // update jvm symbols
    u32 mods_count;
    struct mod_s* mods[MOD_MAX_COUNT];
};

struct proc_symbs_s* proc_load_all_symbs(void *elf_reader, int proc_id);
void proc_delete_all_symbs(struct proc_symbs_s *proc_symbs);
int proc_search_addr_symb(struct proc_symbs_s *proc_symbs,
        u64 addr, struct addr_symb_s *addr_symb, char *comm);

#endif
