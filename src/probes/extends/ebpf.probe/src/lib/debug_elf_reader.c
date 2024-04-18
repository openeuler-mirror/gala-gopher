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

    (void)snprintf(dir, len, "%s", full_path);
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

static int get_pid_root_path(struct proc_symbs_s* proc_symbs, char root_path[], size_t len)
{
    int ret, path_len;
    char pid_root[PATH_LEN];
    char container_root[PATH_LEN];

    int pid = proc_symbs->proc_id;
    char *container_id = proc_symbs->container_id;

    pid_root[0] = 0;
    ret = __get_pid_root_path(pid, pid_root, PATH_LEN);
    if (ret != 0) {
        return ret;
    }

    if (container_id[0] == 0) {
        if (IS_SYSTEM_ROOT(pid_root)) {
            (void)snprintf(root_path, len, "%s", pid_root);
        } else {
            /* Eliminate end '/' */
            path_len = strlen(pid_root);
            if (path_len > 0 && pid_root[path_len - 1] == '/') {
                pid_root[path_len - 1] = 0;
            }
            (void)snprintf(root_path, len, "%s", pid_root);
        }
        return 0;
    }

    container_root[0] = 0;
    ret = get_container_root_path((const char *)container_id, container_root, PATH_LEN);
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

int get_elf_debug_file(struct elf_reader_s* reader, struct proc_symbs_s* proc_symbs,
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
    ret = get_pid_root_path(proc_symbs, pid_root_path, PATH_LEN);
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
            (void)snprintf(debug_file, len, "%s", build_id_path);
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
            (void)snprintf(debug_file, len, "%s", debug_link_path);
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

    (void)snprintf(reader->global_dbg_dir, sizeof(reader->global_dbg_dir), "%s", global_dbg_dir);
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