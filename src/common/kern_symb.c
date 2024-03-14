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

#include "common.h"
#include "kern_symb.h"

// example: ffff800009294000 t __nft_trace_packet   [nf_tables]
#if defined(__TARGET_ARCH_x86)
#define KERN_ADDR_SPACE     (0x00FFFFFFFFFFFFFF)
#else
#define KERN_ADDR_SPACE     (0x0)
#endif

#define KSYMB_NAME_LEN      64
#define KSYMB_MOD_LEN       64
#define KSYMB_MAX           1000000
#define ADDR_ERR(addr)  (((addr) == 0) || ((addr) == 0xFFFFFFFFFFFFFFFF) \
                        || ((addr) < KERN_ADDR_SPACE))

#define IS_KERN_DATA_SYMBOL(S)  (((S) == 'B') || ((S) == 'b') || ((S) == 'd') \
                                || ((S) == 'R') || ((S) == 'r') || ((S) == 'D'))

#define KSYMB_ERR(symb)  IS_KERN_DATA_SYMBOL(symb)

static void destroy_ksymbs(struct ksymb_s *ksym)
{
    if (ksym) {
        if (ksym->kmod) {
            (void)free(ksym->kmod);
            ksym->kmod = NULL;
        }
        if (ksym->sym) {
            (void)free(ksym->sym);
            ksym->sym = NULL;
        }
        ksym->addr = 0;
    }
}

static int resolve_ksymbs(const char *s, struct ksymb_s* ksymb)
{
    char *p, *p1, *p2;
    char symb_type;
    char symb[KSYMB_NAME_LEN + 1];
    char kmod[KSYMB_MOD_LEN + 1];
    size_t name_len = 0, mod_len = 0;

    ksymb->addr = strtoull(s, &p, 16);
    if (ADDR_ERR(ksymb->addr)) {
        goto err;
    }

    p++;
    symb_type = *p;
    if (KSYMB_ERR(symb_type)) {
        goto err;
    }

    p += 2; // point to kern symbol name
    while (*p != ' ' && *p != '\n' && name_len < KSYMB_NAME_LEN) {
        symb[name_len++] = *p;
        p++;
    }
    symb[name_len] = 0;

    p1 = strchr(p, '[');
    p2 = strchr(p, ']');
    if (p1 && p2) {
        p = p1 + 1;
        while (*p != ' ' && *p != '\n' && p != p2 && mod_len < KSYMB_MOD_LEN) {
            kmod[mod_len++] = *p;
            p++;
        }
        kmod[mod_len] = 0;
    }

    if (name_len == 0) {
        goto err;
    }

    ksymb->sym = (char *)malloc(name_len + 1);
    if (!ksymb->sym) {
        goto err;
    }

    (void)memcpy(ksymb->sym, symb, name_len + 1);

    if (mod_len > 0) {
        ksymb->kmod = (char *)malloc(mod_len + 1);
        if (!ksymb->kmod) {
            goto err;
        }
        (void)memcpy(ksymb->kmod, kmod, mod_len + 1);
    }
    return 0;

err:
    destroy_ksymbs(ksymb);
    return -1;
}

void destroy_ksymbs_tbl(struct ksymb_tbl_s *ksym_tbl)
{
    if (!ksym_tbl) {
        return;
    }

    for(int i = 0; i < ksym_tbl->ksym_size; i++) {
        destroy_ksymbs(&(ksym_tbl->ksyms[i]));
    }
}

struct ksymb_tbl_s* create_ksymbs_tbl(void)
{
    size_t size = KSYMB_MAX * sizeof(struct ksymb_s) + sizeof(struct ksymb_tbl_s);
    struct ksymb_tbl_s *tbl = (struct ksymb_tbl_s *)malloc(size);
    if (!tbl) {
        return NULL;
    }
    (void)memset(tbl, 0, size);
    tbl->ksym_size = 0;
    return tbl;
}

static char __kern_unknow_symb[] = "[kernel]";

int search_kern_addr_symb(struct ksymb_tbl_s *ksymbs, u64 addr, struct addr_symb_s *addr_symb)
{
    int start, end;
    int result;
    size_t mid;

    if (!ksymbs) {
        return -1;
    }

    // init data
    addr_symb->orign_addr = addr;
    addr_symb->sym = NULL;
    addr_symb->mod = __kern_unknow_symb;
    addr_symb->offset = 0;

    start = 0;
    end = ksymbs->ksym_size;

    while (start < end) {
        mid = start + (end - start) / 2;

        result = addr - ksymbs->ksyms[mid].addr;
        if (result < 0) {
            end = mid;
        } else if (result > 0) {
            start = mid + 1;
        } else {
            addr_symb->sym = ksymbs->ksyms[mid].sym;
            addr_symb->mod = ksymbs->ksyms[mid].kmod;
            addr_symb->offset = 0;
            return 0;
        }
    }

    if (start >= 1) {
        if (ksymbs->ksyms[start - 1].addr < addr) {
            addr_symb->sym = ksymbs->ksyms[start - 1].sym;
            addr_symb->mod = ksymbs->ksyms[start - 1].kmod;
            addr_symb->offset = addr - ksymbs->ksyms[start - 1].addr;
            return 0;
        }

        if (ksymbs->ksyms[start - 1].addr > addr) {
            addr_symb->sym = ksymbs->ksyms[start - 1].sym;
            addr_symb->mod = ksymbs->ksyms[start - 1].kmod;
            addr_symb->offset = ksymbs->ksyms[start - 1].addr - addr;
            return 0;
        }
    }

    return -1;
}

static int __ksymb_cmp(const void *key1, const void *key2)
{
    struct ksymb_s *symb1 = ((struct ksymb_s *)key1);
    struct ksymb_s *symb2 = ((struct ksymb_s *)key2);
    return symb1->addr - symb2->addr;
}

int sort_kern_syms(struct ksymb_tbl_s *ksymbs)
{
    if (!ksymbs) {
        return -1;
    }
    qsort(ksymbs->ksyms, ksymbs->ksym_size, sizeof(struct ksymb_s), __ksymb_cmp);
    return 0;
}

int load_kern_syms(struct ksymb_tbl_s *ksymbs)
{
    FILE *kallsyms;
    char line[LINE_BUF_LEN];

    if (!ksymbs) {
        return -1;
    }

    kallsyms = fopen("/proc/kallsyms", "r");
    if (!kallsyms) {
        return -2;
    }

    line[0] = 0;
    while (fgets(line, sizeof(line), kallsyms)) {
        if (ksymbs->ksym_size >= KSYMB_MAX) {
            ERROR("[SYMBOL]: Too many kern symbols.\n");
            break;
        }
        if (resolve_ksymbs((const char *)line, &(ksymbs->ksyms[ksymbs->ksym_size]))) {
            continue;
        }

        ksymbs->ksym_size++;
    }

    fclose(kallsyms);
    return 0;
}
