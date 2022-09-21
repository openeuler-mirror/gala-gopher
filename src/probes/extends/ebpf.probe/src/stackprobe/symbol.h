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

#include "common.h"
#include "hash.h"

// example: ffff800009294000 t __nft_trace_packet   [nf_tables]
#if defined(__TARGET_ARCH_x86)
#define KERN_ADDR_SPACE     (0x00FFFFFFFFFFFFFF)
#else
#define KERN_ADDR_SPACE     (0x0)
#endif

#define IS_KERN_DATA_SYMBOL(S)  (((S) == 'B') || ((S) == 'b') || ((S) == 'd') \
                                || ((S) == 'R') || ((S) == 'r') || ((S) == 'D'))

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
    u64 offset;
};

void destroy_ksymbs_tbl(struct ksymb_tbl_s *ksym_tbl);
struct ksymb_tbl_s* create_ksymbs_tbl(void);
int search_kern_addr_symb(struct ksymb_tbl_s *ksymbs, u64 addr, struct addr_symb_s *addr_symb);
int sort_kern_syms(struct ksymb_tbl_s *ksymbs);
int load_kern_syms(struct ksymb_tbl_s *ksymbs);

#define MOD_MAX_COUNT       1000
#define SYMBS_MAX_COUNT     1000000
#define SYMBS_STEP_COUNT    1000
enum module_type {
    MODULE_UNKNOW = 0,
    MODULE_SO = 1,
    MODULE_EXEC = 2,
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

    u32 mods_count;
    struct mod_s* mods[MOD_MAX_COUNT];
};

struct proc_symbs_s* proc_load_all_symbs(void *elf_reader, int proc_id, char *comm);
void proc_delete_all_symbs(struct proc_symbs_s *proc_symbs);
int proc_search_addr_symb(struct proc_symbs_s *proc_symbs,
        u64 addr, struct addr_symb_s *addr_symb);

#endif
