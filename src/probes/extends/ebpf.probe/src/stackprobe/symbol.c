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
 * Create: 2022-08-22
 * Description: symbol module
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sched.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <gelf.h>

#include "common.h"
#include "gopher_elf.h"
#include "debug_elf_reader.h"
#include "elf_symb.h"
#include "symbol.h"
#include "java_support.h"

#ifdef symbs
#undef symbs
#endif
#define symbs   mod_symbs->__symbs

#ifdef symbs_count
#undef symbs_count
#endif
#define symbs_count   mod_symbs->symbs_count

#ifdef symbs_capability
#undef symbs_capability
#endif
#define symbs_capability   mod_symbs->symbs_capability

enum symbol_err_e {
    GET_MOD_NAME    = -2,
    GET_MOD_TYPE    = -3,
    GET_MOD_PATH    = -4,
    ADD_MOD_RANGE   = -5,
    FMT_MAP         = -6,
    LOAD_SYMBS      = -7,
    SORT_SYMBS      = -8,
    GET_ELF_OFFSET  = -9,
    ADD_MOD         = -10,
};
#define __UNKNOW_NAME     "Unknow"

#ifdef GOPHER_DEBUG

#define __RANGE_COL_NUM       3
static void __print_range_header(void)
{
    int i, len, ret;
    char *pos;
    char buf[LINE_BUF_LEN];

    const char *col[__RANGE_COL_NUM] = {"START", "END", "OFFSET"};
    const int offset[__RANGE_COL_NUM] = {-24, -22, 24};

    buf[0] = 0;
    pos = buf;
    len = LINE_BUF_LEN;
    for (i = 0; i < __RANGE_COL_NUM - 1; i++) {
        ret = snprintf(pos, len, "%*s", offset[i], col[i]);
        len -= ret;
        pos += ret;
    }
    (void)snprintf(pos, len, "%*s\n", offset[i], col[i]);
    INFO(buf);
}

static void __print_range(struct mod_addr_rage_s *range)
{
    int i, len, ret;
    char *pos;
    char buf[LINE_BUF_LEN];

    const int offset[__RANGE_COL_NUM] = {-24, -22, 24};

    i = 0;
    buf[0] = 0;
    pos = buf;
    len = LINE_BUF_LEN;

    ret = snprintf(pos, len, "0x%*llx", offset[i++], range->start);
    len -= ret;
    pos += ret;

    ret = snprintf(pos, len, "0x%*llx", offset[i++], range->end);
    len -= ret;
    pos += ret;

    (void)snprintf(pos, len, "%*llx\n", offset[i++], range->f_offset);
    INFO(buf);
}

#define __SYMB_COL_NUM       3
static void __print_symbs_header(void)
{
    int i, len, ret;
    char *pos;
    char buf[LINE_BUF_LEN];

    const char *col[__SYMB_COL_NUM] = {"SYMB_NAME", "START", "SIZE"};
    const int offset[__SYMB_COL_NUM] = {-64, -12, 12};

    buf[0] = 0;
    pos = buf;
    len = LINE_BUF_LEN;
    for (i = 0; i < __SYMB_COL_NUM - 1; i++) {
        ret = snprintf(pos, len, "%*s", offset[i], col[i]);
        len -= ret;
        pos += ret;
    }
    (void)snprintf(pos, len, "%*s\n", offset[i], col[i]);
    INFO(buf);
}

static void __print_symbs(struct symb_s *symb)
{
    int i, len, ret;
    char *pos;
    char buf[LINE_BUF_LEN];

    const int offset[__SYMB_COL_NUM] = {-64, -12, 12};

    i = 0;
    buf[0] = 0;
    pos = buf;
    len = LINE_BUF_LEN;

    ret = snprintf(pos, len, "%*s", offset[i++], (symb->symb_name ? : __UNKNOW_NAME));
    len -= ret;
    pos += ret;

    ret = snprintf(pos, len, "%*llx", offset[i++], symb->start);
    len -= ret;
    pos += ret;

    (void)snprintf(pos, len, "%*llx\n", offset[i++], symb->size);
    INFO(buf);
}

#define __MOD_COL_NUM       7
static void __print_mods(struct mod_s *mod)
{
    int i, len, ret;
    char *pos;
    char buf[LINE_BUF_LEN];

    const char *col[__MOD_COL_NUM] = {"MOD_NAME", "TYPE", "PATH", "ELF", "ELF_OFFSET",
        "RANGE", "SYMBOS"};
    const int offset[__MOD_COL_NUM] = {-32, -12, -32, -12, -12, -12, 12};

    buf[0] = 0;
    pos = buf;
    len = LINE_BUF_LEN;
    for (i = 0; i < __MOD_COL_NUM - 1; i++) {
        ret = snprintf(pos, len, "%*s", offset[i], col[i]);
        len -= ret;
        pos += ret;
    }
    (void)snprintf(pos, len, "%*s\n", offset[i], col[i]);
    INFO(buf);

    i = 0;
    buf[0] = 0;
    pos = buf;
    len = LINE_BUF_LEN;

    ret = snprintf(pos, len, "%*s", offset[i++], (mod->mod_name ? : __UNKNOW_NAME));
    len -= ret;
    pos += ret;

    ret = snprintf(pos, len, "%*u", offset[i++], mod->mod_type);
    len -= ret;
    pos += ret;

    ret = snprintf(pos, len, "%*s", offset[i++], (mod->mod_path ? : __UNKNOW_NAME));
    len -= ret;
    pos += ret;

    ret = snprintf(pos, len, "%*llx", offset[i++], mod->mod_elf_so_addr);
    len -= ret;
    pos += ret;

    ret = snprintf(pos, len, "%*llx", offset[i++], mod->mod_elf_so_offset);
    len -= ret;
    pos += ret;

    ret = snprintf(pos, len, "%*u", offset[i++], mod->addr_ranges_count);
    len -= ret;
    pos += ret;

    (void)snprintf(pos, len, "%*u\n", offset[i++], mod->symbs_count);
    INFO(buf);

#if 0
    if (mod->symbs_count > 0) {
        __print_symbs_header();
    }
    for (i = 0; i < mod->symbs_count; i++) {
        if (mod->symbs[i]) {
            __print_symbs(mod->symbs[i]);
        }
    }
#endif
    if (mod->addr_ranges_count > 0) {
        __print_range_header();
    }
    for (i = 0; i < mod->addr_ranges_count; i++) {
        __print_range(&mod->addr_ranges[i]);
    }
}

static void __print_proc_ranges(struct proc_symbs_s* proc_symbs)
{
    struct mod_s *mod;
    __print_range_header();

    for (int i = 0; i < proc_symbs->mods_count; i++) {
        mod = proc_symbs->mods[i];
        if (mod) {
            for (int j = 0; j < mod->addr_ranges_count; j++) {
                __print_range(&mod->addr_ranges[j]);
            }
        }
    }
}

static void __print_mod_symbs(struct mod_s *mod)
{
    __print_symbs_header();

    for (int i = 0; i < mod->symbs_count; i++) {
        if (mod->symbs[i]) {
            __print_symbs(mod->symbs[i]);
        }
    }
}

static void __print_proc(struct proc_symbs_s* proc_symbs)
{
    INFO("[SYMBOL]: loaded proc symbos [%s, %d], %u mods\n",
            proc_symbs->comm, proc_symbs->proc_id, proc_symbs->mods_count);
    for (int i = 0; i < proc_symbs->mods_count; i++) {
        if (proc_symbs->mods[i]) {
            __print_mods(proc_symbs->mods[i]);
        }
    }
}
#endif

#if 1
#if 0
static void symb_destroy(struct symb_s *symb)
{
    if (!symb) {
        return;
    }

    if (symb->symb_name) {
        (void)free(symb->symb_name);
        symb->symb_name = NULL;
    }
    return;
}
#endif
static void mod_info_destroy(struct mod_info_s *mod_info)
{
    if (mod_info->name) {
        (void)free(mod_info->name);
        mod_info->name = NULL;
    }
    if (mod_info->path) {
        (void)free(mod_info->path);
        mod_info->path = NULL;
    }
}

static void mod_destroy(struct mod_s *mod)
{
    if (!mod) {
        return;
    }

    mod_info_destroy(&(mod->__mod_info));

    rm_elf_symb(mod->mod_symbs);
    rm_elf_symb(mod->debug_symbs);

    mod->mod_symbs = NULL;
    mod->debug_symbs = NULL;
    return;
}

static void proc_symbs_destroy(struct proc_symbs_s *proc_symbs)
{
    if (!proc_symbs) {
        return;
    }
    for (int i = 0; i < proc_symbs->mods_count; i++) {
        mod_destroy(proc_symbs->mods[i]);
        if (proc_symbs->mods[i]) {
            (void)free(proc_symbs->mods[i]);
            proc_symbs->mods[i] = NULL;
        }
    }
    return;
}
#endif

#if 0
static int inc_symbs_capability(struct mod_s* mod)
{
    u32 new_capa, old_capa;
    struct symb_s** new_symbs_capa;
    struct symb_s** old_symbs_capa;

    old_capa = mod->symbs_capability;
    new_capa = mod->symbs_capability + SYMBS_STEP_COUNT;
    if (new_capa >= SYMBS_MAX_COUNT) {
        return -1;
    }

    old_symbs_capa = mod->__symbs;

    new_symbs_capa = (struct symb_s **)malloc(new_capa * sizeof(struct symb_s *));
    if (!new_symbs_capa) {
        return -1;
    }

    (void)memset(new_symbs_capa, 0, new_capa * sizeof(struct symb_s *));
    if (old_capa > 0 && old_symbs_capa != NULL) {
        (void)memcpy(new_symbs_capa, old_symbs_capa, old_capa * sizeof(struct symb_s *));
    }
    if (old_symbs_capa != NULL) {
        (void)free(old_symbs_capa);
        old_symbs_capa = NULL;
    }
    mod->__symbs = new_symbs_capa;
    mod->symbs_capability = new_capa;
    return 0;
}

static ELF_CB_RET __add_symbs(const char *symb, u64 addr_start, u64 size, void *ctx)
{
    struct mod_s* mod = ctx;
    struct symb_s* new_symb;

    if (mod->symbs_count >= mod->symbs_capability) {
        if (inc_symbs_capability(mod)) {
            ERROR("[SYMBOL]: Too many symbos(%s).\n", mod->mod_name ?: __UNKNOW_NAME);
            return ELF_SYMB_CB_ERR;
        }
    }

    new_symb = (struct symb_s*)malloc(sizeof(struct symb_s));
    if (!new_symb) {
        return ELF_SYMB_CB_ERR;
    }

    (void)memset(new_symb, 0, sizeof(struct symb_s));
    new_symb->start = addr_start;
    new_symb->size = size;
    new_symb->symb_name = strdup(symb);
    SPLIT_NEWLINE_SYMBOL(new_symb->symb_name);

    mod->symbs[mod->symbs_count++] = new_symb;
    return ELF_SYMB_CB_OK;
}

static int __symb_cmp(const void *a, const void *b)
{
    struct symb_s **symb1 = (struct symb_s **)a;
    struct symb_s **symb2 = (struct symb_s **)b;

    return (*symb1)->start - (*symb2)->start;
}

static int sort_symbs(struct mod_s* mod)
{
    if (!mod) {
        return SORT_SYMBS;
    }
    if (mod->symbs_count == 0) {
        return 0;
    }
    qsort(mod->symbs, mod->symbs_count, sizeof(struct symb_s *), __symb_cmp);
    return 0;
}
#endif

#if 1
static u64 __get_mod_target_addr(struct mod_s* mod, struct mod_addr_rage_s *range, u64 addr)
{
    if (mod->mod_type == MODULE_SO || mod->mod_type == MODULE_VDSO) {
        return addr - (range->start - range->f_offset) +
         (mod->mod_elf_so_addr - mod->mod_elf_so_offset);
    } else {
        return addr;
    }
}

static char is_mod_contain_addr(struct mod_s* mod, u64 addr, u64 *target_addr)
{
    struct mod_addr_rage_s *range;
    for (int i = 0; i < mod->addr_ranges_count; i++) {
        range = &(mod->addr_ranges[i]);
        if (addr >= range->start && addr < range->end) {
            *target_addr = __get_mod_target_addr(mod, range, addr);
            return 1;
        }
    }
    return 0;
}

#if 0
#define MOD_ERR_INDEX(mod, index)   (((index) < 0) || (mod->symbs_count <= (index)))

static int search_addr_upper_bound(struct mod_s* mod, int bgn, int end, u64 target_addr)
{
    int left = bgn, right = end, mid = 0;

    if ((bgn >= end) || (bgn < 0) || (end < 0)) {
        return -1;
    }

    while (left < right) {
        mid = (left + right) / 2;
        if (mid >= mod->symbs_count) {
            return -1;
        }
        if (target_addr >= mod->symbs[mid]->start) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }

    if (MOD_ERR_INDEX(mod, right)) {
        return -1;
    }
    return target_addr >= mod->symbs[right]->start ? (right + 1): right;
}

static int __do_mod_search_addr(struct mod_s* mod, u64 orign_addr, u64 target_addr, struct addr_symb_s* addr_symb)
{
    u64 range;
    int search_index = search_addr_upper_bound(mod, 0, mod->symbs_count, target_addr);

    // Take a step back.
    search_index -= 1;
    if (MOD_ERR_INDEX(mod, search_index)) {
        return -1;
    }

    range = mod->symbs[search_index]->start;

    while (!MOD_ERR_INDEX(mod, search_index) && target_addr >= mod->symbs[search_index]->start) {
        if (target_addr < mod->symbs[search_index]->start + mod->symbs[search_index]->size) {
            addr_symb->sym = mod->symbs[search_index]->symb_name;
            addr_symb->offset = target_addr - mod->symbs[search_index]->start;
            addr_symb->orign_addr = orign_addr;
            addr_symb->mod = mod->mod_name;
            return 0;
        }
        if (range > mod->symbs[search_index]->start + mod->symbs[search_index]->size) {
            break;
        }
        // Take a step back.
        search_index -= 1;
    }

    return -1;
}
#endif
#endif

#if 1

static int load_debug_symbs(struct proc_symbs_s* proc_symbs, struct mod_s* mod)
{
    char debug_file[PATH_LEN];

    if (mod->mod_type != MODULE_SO && mod->mod_type != MODULE_EXEC) {
        return 0;
    }

    debug_file[0] = 0;
    (void)get_elf_debug_file(mod->elf_reader,
                             proc_symbs->proc_id,
                             (const char *)mod->mod_name,
                             (const char *)mod->mod_path,
                             debug_file,
                             PATH_LEN);

    if (debug_file[0] != 0) {
        mod->debug_symbs = get_symb_from_file((const char *)debug_file, ELF_SYM);
    }

#if 0
    elf_symb = get_elf_symbol(mod->elf_reader, proc_symbs->proc_id,
                (const char *)mod->mod_name, (const char *)mod->mod_path);
    if (!elf_symb) {
        return -1;
    }

    mod->debug_symbs = elf_symb;
#endif
    return 0;
}

static int load_symbs(struct mod_s* mod)
{
    if (!mod || !mod->mod_path) {
        return LOAD_SYMBS;
    }

    if (mod->mod_type == MODULE_JVM) {
        mod->mod_symbs = get_symb_from_file((const char *)mod->__mod_info.name, JAVA_SYM);
        // It's okay if mod->mod_symbs is NULL. We'll get JVM symbols from file periodically.
        return 0;
    }

    if (mod->mod_type == MODULE_SO || mod->mod_type == MODULE_EXEC) {
        mod->mod_symbs = get_symb_from_file((const char *)(mod->mod_path), ELF_SYM);
        if (mod->mod_symbs == NULL) {
            ERROR("[SYMBOL]: Failed to load elf %s.\n", mod->mod_path);
            return LOAD_SYMBS;
        }
        return 0;
#if 0
        if (gopher_iter_elf_file_symb((const char *)(mod->mod_path), __add_symbs, mod)) {
            ERROR("[SYMBOL]: Failed to load elf %s.\n", mod->mod_path);
            return LOAD_SYMBS;
        } else {
            return 0;
        }
#endif
    }

    /*
    if (mod->type == MODULE_MAP) {
        return gopher_iter_perf_map_symb((const char *)(mod->mod_path), __add_symbs, mod);
    }
    */

    // TOOD: MODULE_VDSO, MODULE_MAP
    if ((mod->mod_type == MODULE_MAP) || (mod->mod_type == MODULE_VDSO)) {
        return 0;
    }

    return LOAD_SYMBS;
}

static int get_mod_elf_so_offset(struct mod_s* mod)
{
    if (!mod) {
        return GET_ELF_OFFSET;
    }

    if (mod->mod_type != MODULE_SO) {
        return 0;
    }

    if (gopher_get_elf_text_section((const char *)mod->mod_path, 
        &mod->mod_elf_so_addr, &mod->mod_elf_so_offset)) {
        ERROR("[SYMBOL]: Get elf offset failed(%s).\n", mod->mod_path);
        return GET_ELF_OFFSET;
    }

    return 0;
}

static int add_mod(void *elf_reader, struct proc_symbs_s* proc_symbs, struct mod_info_s* mod_info)
{
    int ret;
    struct mod_s* new_mod;

    if (proc_symbs->mods_count >= MOD_MAX_COUNT) {
        return ADD_MOD;
    }

    new_mod = malloc(sizeof(struct mod_s));
    if (!new_mod) {
        return ADD_MOD;
    }
    (void)memset(new_mod, 0, sizeof(struct mod_s));

    (void)memcpy(&(new_mod->__mod_info), mod_info, sizeof(struct mod_info_s));
    (void)memset(mod_info, 0, sizeof(struct mod_info_s));   // avoid refree
    new_mod->elf_reader = elf_reader;

    ret = load_symbs(new_mod);
    if (ret != 0) {
        goto err;
    }

    if (new_mod->mod_symbs != NULL && new_mod->symbs_count == 0) {
        ret = 0;
        goto err;
    }
    
    if (new_mod->mod_type == MODULE_JVM) {
        if (new_mod->mod_symbs != NULL && new_mod->symbs_count != 0)
            proc_symbs->need_update = 0;
    }

#if 0
    ret = sort_symbs(new_mod);
    if (ret != 0) {
        goto err;
    }
#endif
    ret = get_mod_elf_so_offset(new_mod);
    if (ret != 0) {
        goto err;
    }

    (void)load_debug_symbs(proc_symbs, new_mod);

    new_mod->addr_ranges[0].start = new_mod->mod_start;
    new_mod->addr_ranges[0].end = new_mod->mod_end;
    new_mod->addr_ranges[0].f_offset = new_mod->mod_f_offset;
    new_mod->addr_ranges_count = 1;

    proc_symbs->mods[proc_symbs->mods_count++] = new_mod;
    return 0;

err:
    mod_destroy(new_mod);
    (void)free(new_mod);
    return ret;
}

static int add_mod_range(struct mod_s* mod, u64 start, u64 end, u64 f_offset)
{
    if (mod->addr_ranges_count >= MOD_ADDR_RANGE_COUNT) {
        return ADD_MOD_RANGE;
    }

    mod->addr_ranges[mod->addr_ranges_count].start = start;
    mod->addr_ranges[mod->addr_ranges_count].end = end;
    mod->addr_ranges[mod->addr_ranges_count].f_offset = f_offset;
    mod->addr_ranges_count++;
    return 0;
}

static char __is_perf_map(const char *perf_map_file)
{
    char *pos;

    if ((pos = strstr(perf_map_file, ".map")) != NULL) {
        pos += strlen(".map");
        if (*pos == 0) {
            return 1;
        }
    }
    return 0;
}

static int get_mod_type(struct mod_info_s* mod_info)
{
    int elf_type;

    if (!mod_info || !mod_info->path) {
        return GET_MOD_TYPE;
    }

    if (mod_info->type == MODULE_JVM) {
        return 0;
    }

    elf_type = gopher_get_elf_type((const char *)mod_info->path);
    if (elf_type == ET_DYN) {
        mod_info->type = MODULE_SO;
        return 0;
    }

    if (elf_type == ET_EXEC) {
        mod_info->type = MODULE_EXEC;
        return 0;
    }

    if (__is_perf_map((const char *)mod_info->path)) {
        mod_info->type = MODULE_MAP;
        return 0;
    }

    if (!strcmp(mod_info->path, "[vdso]")) {
        mod_info->type = MODULE_VDSO;
        return 0;
    }

    mod_info->type = MODULE_UNKNOW;
    return GET_MOD_TYPE;
}

static void __do_get_mod_path_byname(struct mod_info_s* mod_info, int proc_id)
{
    char *fmt = "/proc/%d/root%s";
    char path[PATH_LEN];

    path[0] = 0;
    (void)snprintf(path, PATH_LEN, fmt, proc_id, mod_info->name);
    mod_info->path = strdup(path);
    return;
}

#define IS_CONTAIN_STR(s, contain_s)    (strstr(s, contain_s))
#define IS_BACKEND_MOD(name)            IS_CONTAIN_STR(name, "/memfd:")

#define __PATH_LEN  (PATH_LEN + 32)
static int get_mod_path(struct mod_info_s* mod_info, int proc_id)
{
    int ret = GET_MOD_PATH;
    char fd_path[PATH_LEN];
    char fd_file[__PATH_LEN];
    DIR *ds = NULL;
    struct stat f_stat;
    struct dirent *dir_entry;

    if (!mod_info->name) {
        return -1;
    }
    if (mod_info->type == MODULE_JVM) {
        mod_info->path = strdup(mod_info->name);
        return 0;
    }
    if (!IS_BACKEND_MOD(mod_info->name)) {
        __do_get_mod_path_byname(mod_info, proc_id);
        return 0;
    }

    fd_path[0] = 0;
    (void)snprintf(fd_path, PATH_LEN, "/proc/%d/fd", proc_id);
    ds = opendir(fd_path);
    if (!ds) {
        goto err;
    }

    while ((dir_entry = readdir(ds)) != NULL) {
        fd_file[0] = 0;
        (void)snprintf(fd_file, __PATH_LEN, "/proc/%d/fd/%s", proc_id, dir_entry->d_name);
        SPLIT_NEWLINE_SYMBOL(fd_file);
        if (stat(fd_file, &f_stat)) {
            continue;
        }

        if (f_stat.st_ino == mod_info->inode) {
            mod_info->path = strdup(fd_file);
            ret = 0;
            break;
        }
    }

err:
    if (ds) {
        closedir(ds);
    }
    return ret;
}

#define __MOD_CORRECT_TARGET    "(deleted)"
#define IS_NUMBER(c)                    ((c) >= '0' && (c) <= '9')
#define IS_STARTED_STR(s, started_s)    (!strncmp(s, started_s, strlen(started_s)))
#define MOD_NAME_ERR(name)              IS_NUMBER(name[0]) \
                                        || IS_STARTED_STR(name, "/SYSV") || IS_STARTED_STR(name, "[vsyscall]") \
                                        || IS_STARTED_STR(name, "//anon") || IS_STARTED_STR(name, "/dev/zero") \
                                        || IS_STARTED_STR(name, "[stack") || IS_STARTED_STR(name, "[heap]") \
                                        || IS_STARTED_STR(name, "/anon_hugepage") || IS_STARTED_STR(name, "[uprobes]")
static int get_mod_name(struct mod_info_s* mod_info, char *maps_line, struct proc_symbs_s* proc_symbs)
{
    char *end, *name, *target;

    target = strstr(maps_line, __MOD_CORRECT_TARGET);
    if (target) {
        end = target - 1;
        *end = 0;
    }

    end = maps_line + strlen(maps_line);
    while (*end != ' ' && end > maps_line) {
        end--;
    }
    name = end + 1;
    if (MOD_NAME_ERR(name)) {
        return GET_MOD_NAME;
    }

    mod_info->name = strdup(name);
    if (!mod_info->name) {
        return GET_MOD_NAME;
    }

    // SO mod in /proc/<pid>/maps is like as follows:
    // 111222330000-111222334000 r-xp 00004000 fd:00 123456 /usr/lib64/libpthread-2.28.so
    if (mod_info->name[0] != '\n') {
        SPLIT_NEWLINE_SYMBOL(mod_info->name);
        return 0;
    }

    // JVM mod dont' display no mod name in /proc/<pid>/maps which is like as follows:
    // 111222330000-111222334000 rwxp 00000000 00:00 0
    if (proc_symbs->is_java) {
        free(mod_info->name);
        mod_info->name = malloc(PATH_LEN);
        if (!mod_info->name) {
            return GET_MOD_NAME;
        }
        mod_info->type = MODULE_JVM; // TODO: Is it necessary to check maps_perm or else?
        (void)memset(mod_info->name, 0, PATH_LEN);
         // It's okay if we can't get java_sym_file now. We'll check it periodically.
        (void)get_host_java_sym_file(proc_symbs->proc_id, mod_info->name, PATH_LEN);
    }

    return 0;
}
#endif

#if 1
static struct mod_s* proc_get_mod_by_name(struct proc_symbs_s* proc_symbs, const char *name)
{
    struct mod_s *mod;

    for (int i = 0; i < proc_symbs->mods_count; i++) {
        mod = proc_symbs->mods[i];
        if (mod != NULL && mod->mod_name != NULL && !strcmp(mod->mod_name, name)) {
            return mod;
        }
    }
    return NULL;
}

#define MAPS_PERM_MAX    5
#define MAPS_IS_EXEC_PERM(perm) (perm[2] == 'x')

static int proc_iter_maps(void *elf_reader, struct proc_symbs_s* proc_symbs, FILE *fp)
{
    int ret = 0, is_over = 0;
    u64 dev_major __maybe_unused;
    u64 dev_minor __maybe_unused;
    struct mod_info_s mod_info;
    struct mod_s *exist_mod;
    char line[LINE_BUF_LEN];
    char maps_perm[MAPS_PERM_MAX];

    while (fgets(line, sizeof(line), fp)) {
        maps_perm[0] = 0;
        (void)memset(&mod_info, 0, sizeof(mod_info));
        ret = 0;
        if (sscanf(line, "%llx-%llx %4s %llx %llx:%llx %llu",
            &mod_info.start, &mod_info.end, maps_perm, &mod_info.f_offset,
            &dev_major, &dev_minor, &mod_info.inode) != 7) {
            ret = FMT_MAP;
            is_over = 1;
            goto next;
        }

        if (!MAPS_IS_EXEC_PERM(maps_perm)) {
            goto next;
        }
        ret = get_mod_name(&mod_info, line, proc_symbs);
        if (ret != 0) {
            goto next;
        }

        exist_mod = proc_get_mod_by_name(proc_symbs, (const char *)mod_info.name);
        if (exist_mod) {
            ret = add_mod_range(exist_mod, mod_info.start, mod_info.end, mod_info.f_offset);
            if (ret != 0) {
                goto next;
            }
            mod_info_destroy(&mod_info);
        } else {
            ret = get_mod_path(&mod_info, proc_symbs->proc_id);
            if (ret != 0) {
                goto next;
            }
            ret = get_mod_type(&mod_info);
            if (ret != 0) {
                goto next;
            }
            ret = add_mod(elf_reader, proc_symbs, &mod_info);
            if (ret != 0) {
                is_over = 1;
                goto next;
            }
        }
        continue;
next:
        mod_info_destroy(&mod_info);
        if (is_over) {
            break;
        }
    }

    return is_over ? ret : 0;
}

struct proc_symbs_s* proc_load_all_symbs(void *elf_reader, int proc_id)
{
    int ret;
    FILE* fp = NULL;
    char maps_file[PATH_LEN];
    struct proc_symbs_s* proc_symbs;

    proc_symbs = (struct proc_symbs_s *)malloc(sizeof(struct proc_symbs_s));
    if (!proc_symbs) {
        return NULL;
    }
    (void)memset(proc_symbs, 0, sizeof(struct proc_symbs_s));
    proc_symbs->proc_id = proc_id;

    maps_file[0] = 0;
    (void)snprintf(maps_file, PATH_LEN, "/proc/%d/maps", proc_id);
    if (access(maps_file, 0)) {
        goto err;
    }
    fp = fopen(maps_file, "r");
    if (!fp){
        ERROR("[SYMBOL]: Open proc maps-file failed.[%s] %s.\n", maps_file, strerror(errno));
        goto err;
    }

    if (detect_proc_is_java(proc_symbs->proc_id, proc_symbs->comm, TASK_COMM_LEN)) {
        proc_symbs->is_java = 1;
        proc_symbs->need_update = 1;  // to init JVM symbs
    }

    ret = proc_iter_maps(elf_reader, proc_symbs, fp);
    if (ret != 0) {
        ERROR("[SYMBOL]: Iter proc maps failed[proc = %d, ret = %d].\n", proc_id, ret);
        goto err;
    }

    fclose(fp);
#ifdef GOPHER_DEBUG
    __print_proc(proc_symbs);
#endif
    return proc_symbs;
err:
    proc_symbs_destroy(proc_symbs);
    (void)free(proc_symbs);
    if (fp) {
        fclose(fp);
    }
    return NULL;
}

void proc_delete_all_symbs(struct proc_symbs_s *proc_symbs)
{
    if (!proc_symbs) {
        return;
    }

    proc_symbs_destroy(proc_symbs);
    (void)free(proc_symbs);
    return;
}

int proc_search_addr_symb(struct proc_symbs_s *proc_symbs,
        u64 addr, struct addr_symb_s *addr_symb, char *comm)
{
    int ret = -1, is_contain_range = 0;
    u64 target_addr;

    addr_symb->orign_addr = addr;
    for (int i = 0; i < proc_symbs->mods_count; i++) {
        target_addr = 0;
        
        if (proc_symbs->mods[i]) {
            // search jvm mods
            if (proc_symbs->mods[i]->mod_type == MODULE_JVM) {
                ret = search_elf_symb(proc_symbs->mods[i]->mod_symbs,
                        addr, addr, proc_symbs->comm, addr_symb);
                if (ret == 0) {
                    break;
                }
                continue;
            }

            // search debug symbs
            ret = search_elf_symb(proc_symbs->mods[i]->debug_symbs,
                    addr, addr, comm, addr_symb);
            if (ret == 0) {
                break;
            }

             // search other mods
            if (is_mod_contain_addr(proc_symbs->mods[i], addr, &target_addr)) {
                is_contain_range = 1;
                ret = search_elf_symb(proc_symbs->mods[i]->mod_symbs,
                        addr, target_addr, comm, addr_symb);
                if (ret != 0) {
#ifdef GOPHER_DEBUG
                    __print_mod_symbs(proc_symbs->mods[i]);
#endif
                } else {
                    break;
                }
            }
        }
    }

    if (!is_contain_range) {
#ifdef GOPHER_DEBUG
        __print_proc_ranges(proc_symbs);
#endif
    }

    return ret;
}
#endif
