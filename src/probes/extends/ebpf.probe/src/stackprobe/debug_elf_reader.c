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
#include "debug_elf_reader.h"

#if 0
#define __STAT_INODE "/usr/bin/stat --format=%%i %s"
int get_inode(const char *file, u32 *inode)
{
    char command[COMMAND_LEN];
    char inode_s[INT_LEN];

    if (access(file, 0) != 0) {
        return -1;
    }

    command[0] = 0;
    inode_s[0] = 0;
    (void)snprintf(command, COMMAND_LEN, __STAT_INODE, file);

    if (exec_cmd((const char *)command, inode_s, INT_LEN) < 0) {
        return -1;
    }

    *inode = (u32)atoi((const char *)inode_s);
    return 0;
}
#endif

#if 1

/*

References https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html

  So, for example, suppose you ask GDB to debug /usr/bin/ls, which has a debug link
  that specifies the file ls.debug, and a build ID whose value in hex is abcdef1234.
  If the list of the global debug directories includes /usr/lib/debug, then GDB will
  look for the following debug information files, in the indicated order:

- /usr/lib/debug/.build-id/ab/cdef1234.debug
- /usr/bin/ls.debug
- /usr/bin/.debug/ls.debug
- /usr/lib/debug/usr/bin/ls.debug.

*/

#define IS_SYSTEM_ROOT(dir) (!strcmp((dir), "/"))

static int get_build_id_path(const char* pid_root, const char* dbg_dir,
        const char* build_id, char buid_path[], size_t len)
{
    const char *p = build_id + 2;
    const char* fmt = "%s%s/.build-id/%c%c/%s.debug";
    (void)snprintf(buid_path, len, fmt,
        IS_SYSTEM_ROOT(pid_root) ? "" : pid_root, dbg_dir, build_id[0], build_id[1], p);

    if (access(buid_path, 0) == 0) {
        return 0;
    }
    return -1;
}

static int __get_path_by_full_path(const char* full_path, char dir[], size_t len)
{
    char *end;

    (void)strncpy(dir, full_path, len - 1);
    end = strrchr(dir, '/');
    if (!end) {
        return -1;
    }
    *(end + 1) = 0;

    return 0;
}

static int get_debug_link_path(const char* pid_root, const char* dbg_dir,
        const char* elf, const char* debug_link, char debug_link_path[], size_t len)
{
    size_t elf_dir_len;
    char elf_dir[PATH_LEN];
    const char* fmt = "%s%s%s%s";

    elf_dir[0] = 0;
    if (__get_path_by_full_path(elf, elf_dir, PATH_LEN)) {
        return -1;
    }

    elf_dir_len = strlen(elf_dir);
    if (elf_dir_len == 0 || (elf_dir[0] != '/') || (elf_dir[elf_dir_len - 1] != '/')) {
        ERROR("[DEBUG_ELF]: Failed to get elf dir(%s).\n", elf);
        return -1;
    }

    debug_link_path[0] = 0;

    (void)snprintf(debug_link_path, len, fmt,
            IS_SYSTEM_ROOT(pid_root) ? "" : pid_root, elf_dir, "", debug_link);
    if (access(debug_link_path, 0) == 0) {
        return 0;
    }

    debug_link_path[0] = 0;
    (void)snprintf(debug_link_path, len, fmt,
            IS_SYSTEM_ROOT(pid_root) ? "" : pid_root, elf_dir, ".debug/", debug_link);
    if (access(debug_link_path, 0) == 0) {
        return 0;
    }

    debug_link_path[0] = 0;
    (void)snprintf(debug_link_path, len, fmt,
            IS_SYSTEM_ROOT(pid_root) ? "" : pid_root, dbg_dir, elf_dir, debug_link);
    if (access(debug_link_path, 0) == 0) {
        return 0;
    }

    return -1;
}


#define __GET_CONTAINER_ID_CMD  "/usr/bin/cat /proc/%d/cpuset | awk -F '/' '{print $NF}'"
static int __get_container_id_by_pid(int pid, char container_id[], size_t len)
{
    char cmd[COMMAND_LEN];
    char buf[CONTAINER_ID_LEN];

    if (len <= CONTAINER_ABBR_ID_LEN) {
        return -1;
    }

    buf[0] = 0;
    cmd[0] = 0;
    (void)snprintf(cmd, COMMAND_LEN, __GET_CONTAINER_ID_CMD, pid);

    if (exec_cmd((const char *)cmd, buf, CONTAINER_ID_LEN)) {
        return -1;
    }

    if (strstr(buf, "No such file")) {
        return -1;
    }
    (void)strncpy(container_id, buf, CONTAINER_ABBR_ID_LEN);
    return 0;
}

#define __GET_ROOT_PATH_CMD  "/usr/bin/readlink /proc/%d/root"
static int __get_pid_root_path(int pid, char root_path[], size_t len)
{
    char cmd[COMMAND_LEN];

    root_path[0] = 0;
    cmd[0] = 0;
    (void)snprintf(cmd, COMMAND_LEN, __GET_ROOT_PATH_CMD, pid);

    if (exec_cmd((const char *)cmd, root_path, len)) {
        return -1;
    }
    return 0;
}

static int get_pid_root_path(int pid, char root_path[], size_t len)
{
    int ret, path_len;
    char pid_root[PATH_LEN];
    char container_root[PATH_LEN];
    char container_id[CONTAINER_ABBR_ID_LEN + 1] = {0};

    pid_root[0] = 0;
    ret = __get_pid_root_path(pid, pid_root, PATH_LEN);
    if (ret != 0) {
        return ret;
    }

    (void)__get_container_id_by_pid(pid, container_id, CONTAINER_ABBR_ID_LEN + 1);
    if (container_id[0] == 0) {
        if (IS_SYSTEM_ROOT(pid_root)) {
            (void)strncpy(root_path, pid_root, len - 1);
        } else {
            /* Eliminate end '/' */
            path_len = strlen(pid_root);
            if (pid_root[path_len - 1] == '/') {
                pid_root[path_len - 1] = 0;
            }
            (void)strncpy(root_path, pid_root, len - 1);
        }
        return 0;
    }

    container_root[0] = 0;
    ret = get_container_merged_path((const char *)container_id, container_root, PATH_LEN);
    if (ret != 0) {
        return ret;
    }

    (void)snprintf(root_path, len, "%s%s", container_root, IS_SYSTEM_ROOT(pid_root) ? "" : pid_root);

    /* Eliminate end '/' */
    path_len = strlen(root_path);
    if (root_path[path_len - 1] == '/') {
        root_path[path_len - 1] = 0;
    }
    return 0;
}


#endif

#if 0

#define ELF_SYMBO_ERR_INDEX(elf_symbo, index)   (((index) < 0) || (elf_symbo->symbs_count <= (index)))

static int __search_addr_upper_bound(struct elf_symbo_s* elf_symbo, int bgn, int end, u64 target_addr)
{
    int left = bgn, right = end, mid = 0;

    if ((bgn >= end) || (bgn < 0) || (end < 0)) {
        return -1;
    }

    while (left < right) {
        mid = (left + right) / 2;
        if (mid >= elf_symbo->symbs_count) {
            return -1;
        }
        if (target_addr >= elf_symbo->symbs[mid]->start) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }

    if (ELF_SYMBO_ERR_INDEX(elf_symbo, right)) {
        return -1;
    }
    return target_addr >= elf_symbo->symbs[right]->start ? (right + 1): right;
}

static int search_symbs(u64 target_addr, char *comm, struct elf_symbo_s* elf_symbo, struct addr_symb_s* addr_symb)
{
    u64 range;
    int search_index = __search_addr_upper_bound(elf_symbo, 0, elf_symbo->symbs_count, target_addr);

    // Take a step back.
    search_index -= 1;
    if (ELF_SYMBO_ERR_INDEX(elf_symbo, search_index)) {
        return -1;
    }

    range = elf_symbo->symbs[search_index]->start;

    while (!ELF_SYMBO_ERR_INDEX(elf_symbo, search_index) && target_addr >= elf_symbo->symbs[search_index]->start) {
        if (target_addr < elf_symbo->symbs[search_index]->start + elf_symbo->symbs[search_index]->size) {
            addr_symb->sym = elf_symbo->symbs[search_index]->symb_name;
            addr_symb->offset = target_addr - elf_symbo->symbs[search_index]->start;
            addr_symb->orign_addr = target_addr;
            addr_symb->mod = comm;
            return 0;
        }
        if (range > elf_symbo->symbs[search_index]->start + elf_symbo->symbs[search_index]->size) {
            break;
        }
        // Take a step back.
        search_index -= 1;
    }

    return -1;
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

    old_symbs_capa = elf_symbo->__symbs;

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
    elf_symbo->__symbs = new_symbs_capa;
    elf_symbo->symbs_capability = new_capa;
    return 0;
}

static ELF_CB_RET __add_symbs(const char *symb, u64 addr_start, u64 size, void *ctx)
{
    struct elf_symbo_s* elf_symbo = ctx;
    struct symb_s* new_symb;

    if (elf_symbo->symbs_count >= elf_symbo->symbs_capability) {
        if (__inc_symbs_capability(elf_symbo)) {
            ERROR("[DEBUG_ELF]: Too many symbos(%s).\n", elf_symbo->file);
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

    elf_symbo->symbs[elf_symbo->symbs_count++] = new_symb;
    return ELF_SYMB_CB_OK;
}

static int load_elf_symbol(struct elf_symbo_s* elf_symbo)
{
    if (!elf_symbo->file) {
        return -1;
    }

    if (!access(elf_symbo->file, 0)) {
        return -1;
    }

    return gopher_iter_elf_file_symb((const char *)(elf_symbo->file), __add_symbs, elf_symbo);
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

static void destroy_elf_symbol(struct elf_symbo_s* elf_symbo)
{
    if (!elf_symbo) {
        return;
    }

    if (elf_symbo->file) {
        (void)free(elf_symbo->file);
        elf_symbo->file = NULL;
    }

    for (int i = 0; i < elf_symbo->symbs_count; i++) {
        __symb_destroy(elf_symbo->symbs[i]);
        if (elf_symbo->symbs[i]) {
            (void)free(elf_symbo->symbs[i]);
            elf_symbo->symbs[i] = NULL;
        }
    }
    if (elf_symbo->__symbs) {
        (void)free(elf_symbo->__symbs);
        elf_symbo->__symbs = NULL;
    }
    return;
}

static struct elf_symbo_s* create_elf_symbol(struct elf_reader_s* reader, u32 inode)
{
    struct elf_symbo_s* elf_symbo = malloc(sizeof(struct elf_symbo_s));
    if (!elf_symbo) {
        return NULL;
    }
    (void)memset(elf_symbo, 0, sizeof(struct elf_symbo_s));
    elf_symbo->i_inode = inode;
    elf_symbo->refcnt += 1;
    return elf_symbo;
}

static struct elf_symbo_s* find_elf_symbol(struct elf_reader_s* reader, u32 inode)
{
    struct elf_symbo_s *item = NULL;

    H_FIND_I(reader->head, &inode, item);
    return item;
}

static int __symb_cmp(const void *a, const void *b)
{
    struct symb_s **symb1 = (struct symb_s **)a;
    struct symb_s **symb2 = (struct symb_s **)b;

    return (*symb1)->start - (*symb2)->start;
}

static int sort_elf_symbol(struct elf_symbo_s* elf_symbo)
{
    if (elf_symbo->symbs_count == 0) {
        return 0;
    }
    qsort(elf_symbo->symbs, elf_symbo->symbs_count, sizeof(struct symb_s *), __symb_cmp);
    return 0;
}

#endif

int get_elf_debug_file(struct elf_reader_s* reader, int pid,
        const char* elf, const char* elf_link, char debug_file[], size_t len)
{
    int ret;
    char debug_link[PATH_LEN];
    char debug_link_path[PATH_LEN];
    char build_id[PATH_LEN];
    char pid_root_path[PATH_LEN];
    char build_id_path[PATH_LEN * 2];

    // step1: get pid root path.
    pid_root_path[0] = 0;
    ret = get_pid_root_path(pid, pid_root_path, PATH_LEN);
    if (ret != 0) {
        return ret;
    }

    // step2: get elf build-id
    build_id[0] = 0;
    (void)gopher_get_elf_build_id(elf_link, build_id, PATH_LEN);
    if (build_id[0] != 0) {
        // step3: get elf build-id path, if not exist, go on...
        build_id_path[0] = 0;
        ret = get_build_id_path((const char *)pid_root_path, (const char *)reader->global_dbg_dir,
            (const char *)build_id, build_id_path, PATH_LEN * 2);

        if (ret == 0) {
            (void)strncpy(debug_file, build_id_path, len - 1);
            return 0;
        }
    }

    // step4: get elf debug-link
    debug_link[0] = 0;
    (void)gopher_get_elf_debug_link(elf_link, debug_link, PATH_LEN);
    if (debug_link[0] != 0) {
        debug_link_path[0] = 0;
        // step5: get debug-link path, if not exist, go on...
        ret = get_debug_link_path((const char *)pid_root_path, (const char *)reader->global_dbg_dir, 
                elf, (const char *)debug_link, debug_link_path, PATH_LEN);
        if (ret == 0) {
            (void)strncpy(debug_file, debug_link_path, len - 1);
            return 0;
        }
    }

    return -1;
}

struct elf_reader_s* create_elf_reader(const char *global_dbg_dir)
{
    struct elf_reader_s* reader = malloc(sizeof(struct elf_reader_s));
    if (!reader) {
        return NULL;
    }

    (void)memset(reader, 0, sizeof(struct elf_reader_s));
    (void)strncpy(reader->global_dbg_dir, global_dbg_dir, PATH_LEN - 1);
    return reader;
}

void destroy_elf_reader(struct elf_reader_s* reader)
{
    if (!reader) {
        return;
    }

    (void)free(reader);
    return;
}
#if 0

void rm_elf_symbol(struct elf_reader_s* reader, struct elf_symbo_s* elf_symbol)
{
    struct elf_symbo_s *item = NULL;

    if (!elf_symbol || !reader) {
        return;
    }

    INFO("[DEBUG_ELF]: Try to delete debug file %s.\n", item->file);

    item = find_elf_symbol(reader, elf_symbol->i_inode);
    if (!item) {
        return;
    }

    if (item->refcnt > 0) {
        item->refcnt -= 1;
    }

    if (item->refcnt > 0) {
        return;
    }

    INFO("[DEBUG_ELF]: Succeed to delete debug file %s.\n", item->file);

    destroy_elf_symbol(item);
    H_DEL(reader->head, item);
    (void)free(item);
    return;
}


struct elf_symbo_s* get_elf_symbol(struct elf_reader_s* reader, int pid, const char *elf, const char *elf_link)
{
    int ret;
    u32 inode = 0;
    char debug_file[PATH_LEN];
    struct elf_symbo_s *item = NULL, *new_item = NULL;

    ret = get_inode(elf_link, &inode)
    if (ret != 0) {
        return NULL;
    }

    item = find_elf_symbol(reader, inode);
    if (item) {
        item->refcnt += 1;
        INFO("[DEBUG_ELF]: Succeed to lkup debug file %s(refcnt = %u).\n", item->file, item->refcnt);
        return item;
    }

    debug_file[0] = 0;
    ret = get_elf_debug_file(reader, pid, elf, elf_link, debug_file, PATH_LEN);
    if (ret != 0) {
        goto err;
    }

    if (debug_file[0] == 0) {
        goto err;
    }

    new_item = create_elf_symbol(reader, inode);
    if (!new_item) {
        return NULL;
    }

    new_item->file = strdup(debug_file);
    if (new_item->file == NULL) {
        goto err;
    }

    ret = load_elf_symbol(new_item)
    if (ret != 0) {
        ERROR("[DEBUG_ELF]: Failed to load symbol(%s).\n", new_item->file);
        goto err;
    }

    (void)sort_elf_symbol(new_item);

    INFO("[DEBUG_ELF]: Succeed to create debug file %s(refcnt = %u).\n", new_item->file, new_item->refcnt);

    H_ADD_I(reader->head, i_inode, new_item);

    return new_item;
err:
    if (new_item) {
        destroy_elf_symbol(new_item);
        (void)free(new_item);
    }
    return NULL;
}

int search_elf_symbol(u64 target_addr, char *comm, struct elf_symbo_s* elf_symbo, struct addr_symb_s* addr_symb)
{
    return search_symbs(target_addr, comm, elf_symbo, addr_symb);
}
#endif
