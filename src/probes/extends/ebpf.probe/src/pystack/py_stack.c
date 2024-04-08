/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: algorithmofdish
 * Create: 2023-11-16
 * Description: python stack user function
 ******************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "gopher_elf.h"
#include "debug_elf_reader.h"
#include "container.h"
#include "py_stack.h"

extern struct py_offset py37_offset;
extern struct py_offset py39_offset;

#define PYTHON_VERSION_LEN 32
#define LIB_PYTHON_COMMON_PREFIX    "libpython"
#define PYTHON_KEYWORD              "python"
#define PY_VAR_PYRUNTIME            "_PyRuntime"

#define CMD_GET_EXE_PATH    "/usr/bin/readlink /proc/%d/exe"
#define PROC_MAPS_PATH      "/proc/%d/maps"

struct py_support_version {
    char version[PYTHON_VERSION_LEN];
    struct py_offset *py_offset;
};

static struct py_support_version g_py_support_vers[] = {
    {"python3.7", &py37_offset},
    {"python3.9", &py39_offset}
};

#define SUPPORT_PYTHON_VERSION_NUM (sizeof(g_py_support_vers) / sizeof(struct py_support_version))

static struct py_support_version *get_curr_py_version(const char *path)
{
    int i;

    for (i = 0; i < SUPPORT_PYTHON_VERSION_NUM; i++) {
        if (strstr(path, g_py_support_vers[i].version)) {
            return &g_py_support_vers[i];
        }
    }
    return NULL;
}

static bool is_python_proc(const char *exe_path)
{
    if (strstr(exe_path, PYTHON_KEYWORD)) {
        return true;
    }
    return false;
}

#if 0
static int get_libpy_debug_so_path(int pid, char *debug_so_path, int size, const char *so_path, const char *debug_dir)
{
    struct proc_symbs_s *proc_symbs;
    struct elf_reader_s elf_reader;
    int ret;

    proc_symbs = new_proc_symbs(pid);
    if (proc_symbs == NULL) {
        WARN("Failed to create proc_symbs(pid=%d)\n", pid);
        return -1;
    }

    elf_reader.global_dbg_dir[0] = 0;
    (void)snprintf(elf_reader.global_dbg_dir, sizeof(elf_reader.global_dbg_dir), "%s", debug_dir);
    ret = get_elf_debug_file(&elf_reader, proc_symbs, so_path, so_path, debug_so_path, size);
    if (ret) {
        WARN("Failed to get libpython debug file(pid=%d, so_path=%s), "
            "please install python debuginfo rpm package\n", pid, so_path);
        free(proc_symbs);
        return -1;
    }
    DEBUG("Debug file path of (pid=%d, so_path=%s) is: %s\n", pid, so_path, debug_so_path);
    free(proc_symbs);
    return 0;
}
#endif

static int get_proc_container_id(int pid, char *container_id, int size)
{
    char pid_str[INT_LEN];

    pid_str[0] = 0;
    (void)snprintf(pid_str, sizeof(pid_str), "%d", pid);
    return get_container_id_by_pid_cpuset(pid_str, container_id, size);
}

static int get_real_path(const char *orig_path, char *real_path, int real_path_size, int pid)
{
    char container_id[CONTAINER_ABBR_ID_LEN + 1];
    char pid_root_path[PATH_LEN];
    char so_host_path[PATH_LEN];
    int ret;

    container_id[0] = 0;
    ret = get_proc_container_id(pid, container_id, sizeof(container_id));
    if (ret) {
        return ret;
    }

    // consider that the process may runs in container
    pid_root_path[0] = 0;
    if (container_id[0] != 0) {
        ret = get_container_root_path(container_id, pid_root_path, sizeof(pid_root_path));
        if (ret) {
            return ret;
        }
    }
    so_host_path[0] = 0;
    ret = snprintf(so_host_path, sizeof(so_host_path), "%s%s", pid_root_path, orig_path);
    if (ret < 0 || ret >= sizeof(so_host_path)) {
        return -1;
    }

    // consider that gopher may runs in container
    convert_to_host_path(real_path, so_host_path, real_path_size);
    return 0;
}

static int init_py_proc_data(int pid, struct py_proc_data *data,
    const char *elf_path, struct mod_info_s *mod_info)
{
    struct py_support_version *py_ver;
    char real_path[PATH_LEN];
    int ret;

    py_ver = get_curr_py_version(elf_path);
    if (!py_ver) {
        DEBUG("Current python version is not supported, pid=%d\n", pid);
        return -1;
    }

    real_path[0] = 0;
    ret = get_real_path(elf_path, real_path, sizeof(real_path), pid);
    if (ret) {
        ERROR("Failed to get real path of %s\n", elf_path);
        return -1;
    }

    ret = gopher_get_elf_symb_addr(real_path, PY_VAR_PYRUNTIME, &data->py_runtime_addr);
    if (ret) {
        DEBUG("Failed to get _PyRuntime addr from %s\n", elf_path);
        return -1;
    }
    DEBUG("Succeed to get _PyRuntime addr:%llx, elf_path=%s\n", data->py_runtime_addr, elf_path);

    data->py_runtime_addr += mod_info->start - mod_info->f_offset;
    memcpy(&data->offsets, py_ver->py_offset, sizeof(struct py_offset));
    return 0;
}

int try_init_py_proc_data(int pid, struct py_proc_data *data)
{
    char cmd[PATH_LEN];
    char map_file[PATH_LEN];
    FILE *fp = NULL;
    int ret;

    struct mod_info_s mod_info;
    char buf[PATH_LEN];
    char exe_path[PATH_LEN];
    char so_path[PATH_LEN];
    char perm[5];

    cmd[0] = 0;
    snprintf(cmd, sizeof(cmd), CMD_GET_EXE_PATH, pid);
    exe_path[0] = 0;
    ret = exec_cmd(cmd, exe_path, sizeof(exe_path));
    if (ret) {
        DEBUG("Failed to get exe path of proc %d\n", pid);
        return -1;
    }
    if (!is_python_proc(exe_path)) {
        return -1;
    }

    map_file[0] = 0;
    snprintf(map_file, sizeof(map_file), PROC_MAPS_PATH, pid);
    fp = fopen(map_file, "r");
    if (!fp) {
        DEBUG("Failed to open map file %s\n", map_file);
        return -1;
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        if (sscanf(buf, "%llx-%llx %4s %llx %*s %*u %s",
            &mod_info.start, &mod_info.end, perm, &mod_info.f_offset, so_path) != 5) {
            continue;
        }
        if (perm[2] != 'x') {
            continue;
        }

        // Consider that cpython may statically link to exe path(for example, in conda environment)
        if (strstr(so_path, LIB_PYTHON_COMMON_PREFIX) || strcmp(so_path, exe_path) == 0) {
            DEBUG("python mod info: start=%llx, end=%llx, so_path=%s\n", mod_info.start, mod_info.end, so_path);
            ret = init_py_proc_data(pid, data, so_path, &mod_info);
            if (ret) {
                continue;
            }

            fclose(fp);
            return 0;
        }
    }

    fclose(fp);
    return -1;
}