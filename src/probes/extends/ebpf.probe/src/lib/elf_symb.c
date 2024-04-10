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
 * Description: debug reader
 ******************************************************************************/
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <cxxabi.h>

#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "container.h"
#include "gopher_elf.h"
#include "elf_symb.h"

static struct elf_symbo_s* __head = NULL;

#ifdef symbs
#undef symbs
#endif
#define symbs   __symbs

#if 1
#define __STAT_INODE "/usr/bin/stat --format=%%i %s"
int __get_inode(const char *elf, u32 *inode)
{
    char command[COMMAND_LEN];
    char inode_s[INT_LEN];

    if (access(elf, 0) != 0) {
        return -1;
    }

    command[0] = 0;
    inode_s[0] = 0;
    (void)snprintf(command, COMMAND_LEN, __STAT_INODE, elf);

    if (exec_cmd_chroot((const char *)command, inode_s, INT_LEN) < 0) {
        return -1;
    }

    *inode = (u32)atoi((const char *)inode_s);
    return 0;
}

static void __symb_destroy(struct symb_s *symb)
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

static void __destroy_symbol(struct elf_symbo_s* elf_symbo)
{
    if (!elf_symbo) {
        return;
    }

    if (elf_symbo->elf) {
        (void)free(elf_symbo->elf);
        elf_symbo->elf = NULL;
    }

    if (elf_symbo->symbs) {
        for (int i = 0; i < elf_symbo->symbs_count; i++) {
            __symb_destroy(elf_symbo->symbs[i]);
            if (elf_symbo->symbs[i]) {
                (void)free(elf_symbo->symbs[i]);
                elf_symbo->symbs[i] = NULL;
            }
        }

        (void)free(elf_symbo->symbs);
        elf_symbo->symbs = NULL;
    }

    return;
}

static int __symb_cmp(const void *a, const void *b)
{
    struct symb_s **symb1 = (struct symb_s **)a;
    struct symb_s **symb2 = (struct symb_s **)b;

    return (*symb1)->start - (*symb2)->start;
}

static int __sort_symbol(struct elf_symbo_s* elf_symbo)
{
    if (elf_symbo->symbs_count == 0) {
        return 0;
    }
    qsort(elf_symbo->symbs, elf_symbo->symbs_count, sizeof(struct symb_s *), __symb_cmp);
    return 0;
}

static struct elf_symbo_s* __lkup_symb(u32 inode)
{
    struct elf_symbo_s *item = NULL;

    H_FIND_I(__head, &inode, item);
    return item;
}

static struct elf_symbo_s* __create_symbol(const char* elf, u32 inode)
{
    struct elf_symbo_s* elf_symbo = malloc(sizeof(struct elf_symbo_s));
    if (!elf_symbo) {
        return NULL;
    }
    (void)memset(elf_symbo, 0, sizeof(struct elf_symbo_s));
    elf_symbo->i_inode = inode;
    elf_symbo->elf = strdup(elf);
    elf_symbo->refcnt += 1;
    return elf_symbo;
}

static int __inc_symbs_capability(struct elf_symbo_s* elf_symbo)
{
    u32 new_capa, old_capa;
    struct symb_s** new_symbs_capa;
    struct symb_s** old_symbs_capa;

    old_capa = elf_symbo->symbs_capability;
    new_capa = elf_symbo->symbs_capability + SYMBS_STEP_COUNT;
    if (new_capa >= SYMBS_MAX_COUNT) {
        return -1;
    }

    old_symbs_capa = elf_symbo->symbs;

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
    elf_symbo->symbs = new_symbs_capa;
    elf_symbo->symbs_capability = new_capa;
    return 0;
}

static char *dup_symb_with_demangling(const char *symb)
{
    int status;
    char *symb1;
    char *real_symb;

    symb1 = strdup(symb);
    if (!symb1) {
        return NULL;
    }
    SPLIT_NEWLINE_SYMBOL(symb1);

    real_symb = __cxa_demangle(symb1, NULL, NULL, &status);
    if (!real_symb) {
        return symb1;
    }
    free(symb1);
    return real_symb;
}

static ELF_CB_RET __add_symbs(const char *symb, u64 addr_start, u64 size, void *ctx)
{
    struct elf_symbo_s* elf_symbo = ctx;
    struct symb_s* new_symb;

    if (elf_symbo->symbs_count >= elf_symbo->symbs_capability) {
        if (__inc_symbs_capability(elf_symbo)) {
            ERROR("[ELF_SYMBOL]: Too many symbos(%s).\n", elf_symbo->elf);
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
    new_symb->symb_name = dup_symb_with_demangling(symb);

    elf_symbo->symbs[elf_symbo->symbs_count++] = new_symb;
    return ELF_SYMB_CB_OK;
}

static void __destroy_java_symbs(struct symb_s* new_symb)
{
    if (new_symb) {
        if (new_symb->symb_name) {
            (void)free(new_symb->symb_name);
            new_symb->symb_name = NULL;
        }
        (void)free(new_symb);
    }
}

static struct symb_s* resolve_java_symbs(char *s)
{
    char symb[JAVASYMB_NAME_LEN] = {0};
    char *code_size, *method_name;
    size_t name_len = 0;
    struct symb_s* new_symb = NULL;

    // 1. malloc new_symb
    new_symb = (struct symb_s*)malloc(sizeof(struct symb_s));
    if (!new_symb) {
        goto err;
    }
    (void)memset(new_symb, 0, sizeof(struct symb_s));

    // 2. set new_symb start_addr
    new_symb->start = strtoull(s, &code_size, 16);

    // 3. set new_symb code_size
    code_size++;
    new_symb->size = strtoull(code_size, &method_name, 16);

    // 4. set new_symb method_name
    method_name++;
    while (*method_name != ' ' && *method_name != '\n' && name_len < JAVASYMB_NAME_LEN - 1) {
        symb[name_len++] = *method_name;
        method_name++;
    }
    symb[name_len] = 0;
    if (name_len == 0) {
        goto err;
    }
    new_symb->symb_name = (char *)malloc(name_len + 1);
    if (!new_symb->symb_name) {
        goto err;
    }
    (void)memcpy(new_symb->symb_name, symb, name_len + 1);
    return new_symb;

err:
    __destroy_java_symbs(new_symb);
    return NULL;
}

static void __reset_java_symbol(struct elf_symbo_s* elf_symbo)
{
    if (!elf_symbo) {
        return;
    }

    for (int i = 0; i < elf_symbo->symbs_count; i++) {
        __symb_destroy(elf_symbo->symbs[i]);
        if (elf_symbo->symbs[i]) {
            (void)free(elf_symbo->symbs[i]);
            elf_symbo->symbs[i] = NULL;
        }
    }

    if (elf_symbo->symbs) {
        (void)free(elf_symbo->symbs);
        elf_symbo->symbs = NULL;
    }

    elf_symbo->elf_offset = 0;
    elf_symbo->symbs_count = 0;
    elf_symbo->symbs_capability = 0;

    return;
}

int __get_java_symb_from_file(const char *file, struct elf_symbo_s* elf_symbo)
{
    int ret = 0;
    FILE *fd = NULL;
    char line[LINE_BUF_LEN] = {0};
    struct symb_s* new_symb = NULL;

    fd = fopen(file, "r");
    if (!fd) {
        return -1;
    }

    if (fseek(fd, elf_symbo->elf_offset, SEEK_SET)) {
        ERROR("[ELF_SYMBOL]: seek err(%s) at %ld.\n", elf_symbo->elf, elf_symbo->elf_offset);
        __reset_java_symbol(elf_symbo); // TODO: need to clear file?
        ret = -1;
        goto err;
    }

    while (fgets(line, sizeof(line), fd)) {
        if (elf_symbo->symbs_count >= elf_symbo->symbs_capability) {
            if (__inc_symbs_capability(elf_symbo)) {
                ERROR("[ELF_SYMBOL]: Too many symbos(%s).\n", elf_symbo->elf);
                ret = -1;
                goto err;
            }
        }
        new_symb = resolve_java_symbs(line);
        if (new_symb == NULL) {
            continue;
        }
        elf_symbo->symbs[elf_symbo->symbs_count++] = new_symb;
    }
    elf_symbo->elf_offset = ftell(fd);

err:
    if (fd > 0) {
        fclose(fd);
    }
    DEBUG("[ELF_SYMBOL]: get java symb from file %s ret %d\n", file, ret);
    return ret;
}

static int __load_symbol_from_file(struct elf_symbo_s* elf_symbo, enum sym_file_t sym_file_type)
{
    int ret;
    if (!elf_symbo->elf) {
        return -1;
    }

#if 0
    if (!access(elf_symbo->elf, 0)) {
        return -1;
    }
#endif

    if (sym_file_type == ELF_SYM) {
        ret = gopher_iter_elf_file_symb((const char *)(elf_symbo->elf), __add_symbs, elf_symbo);
    } else if (sym_file_type == JAVA_SYM){
        ret = __get_java_symb_from_file((const char *)(elf_symbo->elf), elf_symbo);
    } else {
        ret = -1;
    }

    return ret;
}


#define __ERR_INDEX(elf_symb, index)   (((index) < 0) || (elf_symb->symbs_count <= (index)))

static int __search_addr_upper_bound(struct elf_symbo_s* elf_symb, int bgn, int end, u64 target_addr)
{
    int left = bgn, right = end, mid = 0;

    if ((bgn >= end) || (bgn < 0) || (end < 0)) {
        return -1;
    }

    while (left < right) {
        mid = (left + right) / 2;
        if (mid >= elf_symb->symbs_count) {
            return -1;
        }
        if (target_addr >= elf_symb->symbs[mid]->start) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }

    if (__ERR_INDEX(elf_symb, right)) {
        return -1;
    }
    return target_addr >= elf_symb->symbs[right]->start ? (right + 1) : right;
}

static int __do_search_addr(struct elf_symbo_s* elf_symb,
        u64 orign_addr, u64 target_addr, const char* comm, struct addr_symb_s* addr_symb)
{
    u64 range;
    int search_index = __search_addr_upper_bound(elf_symb, 0, elf_symb->symbs_count, target_addr);

    // Take a step back.
    search_index -= 1;
    if (__ERR_INDEX(elf_symb, search_index)) {
        return -1;
    }

    range = elf_symb->symbs[search_index]->start;

    while (!__ERR_INDEX(elf_symb, search_index) && target_addr >= elf_symb->symbs[search_index]->start) {
        if (target_addr < elf_symb->symbs[search_index]->start + elf_symb->symbs[search_index]->size) {
            addr_symb->sym = elf_symb->symbs[search_index]->symb_name;
            addr_symb->offset = target_addr - elf_symb->symbs[search_index]->start;
            addr_symb->orign_addr = orign_addr;
            addr_symb->mod = (char *)comm;
            return 0;
        }
        if (range > elf_symb->symbs[search_index]->start + elf_symb->symbs[search_index]->size) {
            break;
        }
        // Take a step back.
        search_index -= 1;
    }

    return -1;
}


#endif

struct elf_symbo_s* update_symb_from_jvm_sym_file(const char* elf)
{
    int ret;
    u32 inode;
    enum sym_file_t sym_file_type = JAVA_SYM;
    struct elf_symbo_s* item = NULL;
    ret = __get_inode(elf, &inode);
    if (ret != 0) {
        return NULL;
    }

    item = __lkup_symb(inode);
    if (!item) {
        item = __create_symbol(elf, inode);
        if (!item) {
            goto err;
        }
        H_ADD_I(__head, i_inode, item);
    }

    ret = __load_symbol_from_file(item, sym_file_type);
    if (ret != 0) {
        ERROR("[ELF_SYMBOL]: Failed to load symbol(%s).\n", item->elf);
        goto err;
    }

    (void)__sort_symbol(item);

    DEBUG("[ELF_SYMBOL]: Succeed to update JVM symbs %s(symbs_count = %u).\n", item->elf, item->symbs_count);
    return item;

err:
    if (item) {
        __destroy_symbol(item);
        (void)free(item);
    }
    return NULL;
}

struct elf_symbo_s* get_symb_from_file(const char* elf, enum sym_file_t sym_file_type)
{
    int ret;
    u32 inode;
    struct elf_symbo_s* item = NULL, *new_item = NULL;
    ret = __get_inode(elf, &inode);
    if (ret != 0) {
        return NULL;
    }

    item = __lkup_symb(inode);
    if (item) {
        item->refcnt++;
        return item;
    }

    new_item = __create_symbol(elf, inode);
    if (!new_item) {
        goto err;
    }
    ret = __load_symbol_from_file(new_item, sym_file_type);
    if (ret != 0) {
        ERROR("[ELF_SYMBOL]: Failed to load symbol(%s).\n", new_item->elf);
        goto err;
    }

    (void)__sort_symbol(new_item);

    H_ADD_I(__head, i_inode, new_item);
    if (sym_file_type == JAVA_SYM) {
        DEBUG("[ELF_SYMBOL]: Succeed to init JVM symbs %s(symbs_count = %u).\n", new_item->elf, new_item->symbs_count);
    }

    return new_item;
err:
    if (new_item) {
        __destroy_symbol(new_item);
        (void)free(new_item);
    }
    return NULL;
}

void rm_elf_symb(struct elf_symbo_s* elf_symb)
{
    struct elf_symbo_s *item = NULL;

    if (!elf_symb) {
        return;
    }

    item = __lkup_symb(elf_symb->i_inode);
    if (!item) {
        return;
    }

    if (item->refcnt > 0) {
        item->refcnt -= 1;
    }

    if (item->refcnt > 0) {
        return;
    }

    //INFO("[ELF_SYMBOL]: Succeed to delete elf %s.\n", item->elf);

    __destroy_symbol(item);
    H_DEL(__head, item);
    (void)free(item);
    return;
}

int search_elf_symb(struct elf_symbo_s* elf_symb,
        u64 orign_addr, u64 target_addr, const char* comm, struct addr_symb_s* addr_symb)
{
    if (elf_symb == NULL) {
        return -1;
    }

    return __do_search_addr(elf_symb, orign_addr, target_addr, comm, addr_symb);
}

void deinit_elf_symbs(void)
{
    struct elf_symbo_s *item, *tmp;

    if (!__head) {
        return;
    }

    H_ITER(__head, item, tmp) {
        __destroy_symbol(item);
        H_DEL(__head, item);
        (void)free(item);
    }
    __head = NULL;
    return;
}
