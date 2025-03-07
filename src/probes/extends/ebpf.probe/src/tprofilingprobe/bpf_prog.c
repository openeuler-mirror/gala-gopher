/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: algorithmofdish
 * Create: 2023-04-03
 * Description: the user-side program of thread profiling probe
 ******************************************************************************/
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "args.h"
#include "profiling_event.h"
#include "tprofiling.h"
#include "syscall.h"
#include "syscall_file.skel.h"
#include "syscall_net.skel.h"
#include "syscall_lock.skel.h"
#include "syscall_sched.skel.h"
#include "oncpu.skel.h"
#include "offcpu.skel.h"
#include "pygc.skel.h"
#include "pthrd_sync.skel.h"
#include "mem_glibc.skel.h"
#include "mem_pymem.skel.h"
#include "oncpu_sample.skel.h"
#include "bpf_prog.h"

#define PROC_MAPS_PATH      "/proc/%d/maps"

static int perf_event_handler(void *ctx, void *data, __u32 size)
{
    output_profiling_event((trace_event_data_t *)data);
    return 0;
}

static void clean_profiling_bpf_buffer(PerfBufferMgmt *pbMgmt)
{
    if (pbMgmt->perf_buffer_a != NULL) {
        bpf_buffer__free(pbMgmt->perf_buffer_a);
        pbMgmt->perf_buffer_a = NULL;
    }
    if (pbMgmt->perf_buffer_b != NULL) {
        bpf_buffer__free(pbMgmt->perf_buffer_b);
        pbMgmt->perf_buffer_b = NULL;
    }
}

static int open_profiling_bpf_buffer(PerfBufferMgmt *pbMgmt)
{
    int ret;

    if (pbMgmt->perf_buffer_a == NULL || pbMgmt->perf_buffer_b == NULL) {
        return -1;
    }
    if (pbMgmt->perf_buffer_a->inner == NULL) {
        ret = bpf_buffer__open(pbMgmt->perf_buffer_a, perf_event_handler, NULL, NULL);
        if (ret) {
            TP_ERROR("Failed to open profiling bpf buffer a.\n");
            return -1;
        }
    }
    if (pbMgmt->perf_buffer_b->inner == NULL) {
        ret = bpf_buffer__open(pbMgmt->perf_buffer_b, perf_event_handler, NULL, NULL);
        if (ret) {
            TP_ERROR("Failed to open profiling bpf buffer b.\n");
            return -1;
        }
    }

    return 0;
}

LOAD_SYSCALL_BPF_PROG(file)

LOAD_SYSCALL_BPF_PROG(net)

LOAD_SYSCALL_BPF_PROG(lock)

LOAD_SYSCALL_BPF_PROG(sched)

int load_syscall_bpf_prog(struct ipc_body_s *ipc_body, struct bpf_prog_s *prog)
{
    char is_load_syscall_file, is_load_syscall_net;
    char is_load_syscall_lock, is_load_syscall_sched;

    is_load_syscall_file = is_load_probe_ipc(ipc_body, PROBE_RANGE_TPROFILING_SYSCALL_FILE);
    is_load_syscall_net = is_load_probe_ipc(ipc_body, PROBE_RANGE_TPROFILING_SYSCALL_NET);
    is_load_syscall_lock = is_load_probe_ipc(ipc_body, PROBE_RANGE_TPROFILING_SYSCALL_LOCK);
    is_load_syscall_sched = is_load_probe_ipc(ipc_body, PROBE_RANGE_TPROFILING_SYSCALL_SCHED);

    if (__load_syscall_file_bpf_prog(prog, is_load_syscall_file)) {
        return -1;
    }

    if (__load_syscall_net_bpf_prog(prog, is_load_syscall_net)) {
        return -1;
    }

    if (__load_syscall_lock_bpf_prog(prog, is_load_syscall_lock)) {
        return -1;
    }

    if (__load_syscall_sched_bpf_prog(prog, is_load_syscall_sched)) {
        return -1;
    }

    return 0;
}

static int __load_oncpu_bpf_prog(struct bpf_prog_s *prog, char is_load)
{
    int ret = 0;

    LOAD_ONCPU_PROBE(oncpu, err, is_load, &tprofiler.pbMgmt);
    if (is_load) {
        prog->skels[prog->num].skel = oncpu_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)oncpu_bpf__destroy;
        prog->custom_btf_paths[prog->num] = oncpu_open_opts.btf_custom_path;

        int is_attach_tp = (probe_kernel_version() >= KERNEL_VERSION(6, 4, 0));
        PROG_ENABLE_ONLY_IF(oncpu, bpf_raw_trace_sched_switch, is_attach_tp);
        PROG_ENABLE_ONLY_IF(oncpu, bpf_finish_task_switch, !is_attach_tp);

        LOAD_ATTACH(tprofiling, oncpu, err, is_load);

        ret = open_profiling_bpf_buffer(&tprofiler.pbMgmt);
        if (ret) {
            goto err;
        }

        prog->num++;
    }

    return ret;
err:
    UNLOAD(oncpu);
    CLEANUP_CUSTOM_BTF(oncpu);
    return -1;
}

int load_oncpu_bpf_prog(struct ipc_body_s *ipc_body, struct bpf_prog_s *prog)
{

    char is_load_oncpu;

    is_load_oncpu = is_load_probe_ipc(ipc_body, PROBE_RANGE_TPROFILING_ONCPU);
    if (__load_oncpu_bpf_prog(prog, is_load_oncpu)) {
        return -1;
    }

    return 0;
}

static int __load_offcpu_bpf_prog(struct bpf_prog_s *prog, char is_load)
{
    int ret = 0;

    LOAD_OFFCPU_PROBE(offcpu, err, is_load, &tprofiler.pbMgmt);
    if (is_load) {
        prog->skels[prog->num].skel = offcpu_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)offcpu_bpf__destroy;
        prog->custom_btf_paths[prog->num] = offcpu_open_opts.btf_custom_path;

        int is_attach_tp = (probe_kernel_version() >= KERNEL_VERSION(6, 4, 0));
        PROG_ENABLE_ONLY_IF(offcpu, bpf_raw_trace_sched_switch, is_attach_tp);
        PROG_ENABLE_ONLY_IF(offcpu, bpf_finish_task_switch, !is_attach_tp);

        LOAD_ATTACH(tprofiling, offcpu, err, is_load);

        ret = open_profiling_bpf_buffer(&tprofiler.pbMgmt);
        if (ret) {
            goto err;
        }

        prog->num++;
    }

    return ret;
err:
    UNLOAD(offcpu);
    CLEANUP_CUSTOM_BTF(offcpu);
    return -1;
}

int load_offcpu_bpf_prog(struct ipc_body_s *ipc_body, struct bpf_prog_s *prog)
{

    char is_load_offcpu;

    is_load_offcpu = is_load_probe_ipc(ipc_body, PROBE_RANGE_TPROFILING_OFFCPU);
    if (__load_offcpu_bpf_prog(prog, is_load_offcpu)) {
        return -1;
    }

    return 0;
}

proc_ubpf_link_t *proc_link_tbl = NULL;
#define MAX_PROC_LINK_TBL_NUM 100
#define BPF_FUNC_NAME_LEN 64

#define UPROBE_PREFIX       "ubpf_"
#define URETPROBE_PREFIX    "ubpf_ret_"
static int get_func_name_from_bpf_prog(struct bpf_program *prog, char *func_name, int func_len, bool *is_retprobe)
{
    const char *prog_name = bpf_program__name(prog);
    int ret;

    func_name[0] = 0;
    if (strncmp(prog_name, URETPROBE_PREFIX, sizeof(URETPROBE_PREFIX) - 1) == 0) { // must be judged first
        *is_retprobe = true;
        ret = snprintf(func_name, func_len, "%s", prog_name + sizeof(URETPROBE_PREFIX) - 1);
    } else if (strncmp(prog_name, UPROBE_PREFIX, sizeof(UPROBE_PREFIX) - 1) == 0) {
        *is_retprobe = false;
        ret = snprintf(func_name, func_len, "%s", prog_name + sizeof(UPROBE_PREFIX) - 1);
    } else {
        return -1;
    }

    if (ret < 0 || ret >= func_len) {
        func_name[0] = 0;
        return -1;
    }

    return 0;
}

void unload_uprobe_link(ubpf_link_t **link_ptr)
{
    ubpf_link_t *link = *link_ptr;
    int i;

    if (link == NULL) {
        return;
    }
    for (i = 0; i < link->link_num; i++) {
        (void)bpf_link__destroy(link->links[i]);
        link->links[i] = NULL;
    }
    free(link);
    *link_ptr = NULL;
}

typedef int (*func_get_symb_addr)(char *, ubpf_link_t *, u64 *);

int attach_uprobe_link(struct bpf_object *obj, ubpf_link_t *ulink, int pid, func_get_symb_addr callback)
{
    char func_name[BPF_FUNC_NAME_LEN];
    u64 func_offset;
    struct bpf_program *program;
    struct bpf_link *link;
    bool is_retprobe;
    int ret;

    bpf_object__for_each_program(program, obj) {
        ret = get_func_name_from_bpf_prog(program, func_name, BPF_FUNC_NAME_LEN, &is_retprobe);
        if (ret) {
            TP_DEBUG("Failed to get function name from bpf program\n");
            goto err;
        }
        ret = callback(func_name, ulink, &func_offset);
        if (ret) {
            TP_DEBUG("Failed to attach uprobe: pid=%d, elf_path=%s, func_name=%s\n",
                pid, ulink->elf_path, func_name);
            goto err;
        }
        link = bpf_program__attach_uprobe(program, is_retprobe, pid, ulink->elf_path, func_offset);
        ret = libbpf_get_error(link);
        if (ret) {
            TP_DEBUG("Failed to attach uprobe: pid=%d, elf_path=%s, func_name=%s, func_offset=%llu\n",
                pid, ulink->elf_path, func_name, func_offset);
            goto err;
        }
        TP_DEBUG("Succeed to attach uprobe: pid=%d, elf_path=%s, func_name=%s, func_offset=%llu\n",
            pid, ulink->elf_path, func_name, func_offset);
        ulink->links[ulink->link_num++] = link;
    }

    return 0;
err:
    unload_uprobe_link(&ulink);
    return -1;
}

ubpf_link_t *create_pygc_link(proc_ubpf_link_t *proc_link)
{
    ubpf_link_t *pygc_link;
    int pid = proc_link->pid;
    int ret;

    pygc_link = (ubpf_link_t *)calloc(1, sizeof(ubpf_link_t));
    if (!pygc_link) {
        return NULL;
    }
    ret = get_so_path(pid, pygc_link->elf_path, sizeof(pygc_link->elf_path), "libpython");
    if (ret) {
        TP_DEBUG("Failed to get libpython path, use default exe path(pid=%d)\n", pid);
        (void)snprintf(pygc_link->elf_path, sizeof(pygc_link->elf_path), "/proc/%d/root%s",
            pid, proc_link->exe_path);
        return pygc_link;
    }
    ret = gopher_get_elf_build_id(pygc_link->elf_path, pygc_link->build_id, sizeof(pygc_link->build_id));
    if (ret) {
        TP_DEBUG("Failed to get build id of the path:%s\n", pygc_link->elf_path);
        free(pygc_link);
        return NULL;
    }

    return pygc_link;
}

int get_pygc_symb_addr(char *func_name, ubpf_link_t *link, u64 *addr)
{
    char func_name_constprop[BPF_FUNC_NAME_LEN];
    int ret;

    ret = gopher_get_elf_symb(link->elf_path, func_name, addr);
    if (ret < 0) {
        func_name_constprop[0] = 0;
        (void)snprintf(func_name_constprop, BPF_FUNC_NAME_LEN, "%s.constprop.0", func_name);
        ret = gopher_get_elf_symb(link->elf_path, func_name_constprop, addr);
    }
    if (ret < 0) {
        if (link->build_id[0] == 0) {
            TP_DEBUG("Failed to get function offset: func_name=%s, elf_path=%s\n",
                func_name, link->elf_path);
            return -1;
        }
        *addr = get_func_offset_by_build_id(link->build_id, func_name);
        if (*addr == 0) {
            TP_DEBUG("Failed to get function offset by build-id: func_name=%s, build-id=%s\n",
                func_name, link->build_id);
            return -1;
        }
    }
    return 0;
}

int attach_pygc_probes_per_proc(struct bpf_object *obj, proc_ubpf_link_t *proc_link)
{
    ubpf_link_t *pygc_link;
    int ret;

    pygc_link = create_pygc_link(proc_link);
    if (!pygc_link) {
        return -1;
    }
    ret = attach_uprobe_link(obj, pygc_link, proc_link->pid, get_pygc_symb_addr);
    if (ret) {
        return -1;
    }
    proc_link->pygc_link = pygc_link;

    return 0;
}

static void unload_uprobe_links(void)
{
    proc_ubpf_link_t *link, *tmp;

    if (!proc_link_tbl) {
        return;
    }
    HASH_ITER(hh, proc_link_tbl, link, tmp) {
        if (link->pygc_link != NULL) {
            unload_uprobe_link(&link->pygc_link);
        }
        if (link->pthrd_sync_link != NULL) {
            unload_uprobe_link(&link->pthrd_sync_link);
        }
        if (link->mem_glibc_link != NULL) {
            unload_uprobe_link(&link->mem_glibc_link);
        }
        if (link->mem_pymem_link != NULL) {
            unload_uprobe_link(&link->mem_pymem_link);
        }
    }
}

ubpf_link_t *create_glibc_link(int pid)
{
    ubpf_link_t *link;
    int ret;

    link = (ubpf_link_t *)calloc(1, sizeof(ubpf_link_t));
    if (!link) {
        return NULL;
    }
    // TODO: GLIBC 2.34 内置了pthread库到libc库中，因此对于小于 2.34 版本的GLIBC，需要从pthread库中获取函数地址
    ret = get_so_path(pid, link->elf_path, sizeof(link->elf_path), "libc.so");
    if (ret) {
        TP_DEBUG("Failed to get libc.so path(pid=%d)\n", pid);
        free(link);
        return NULL;
    }

    return link;
}

ubpf_link_t *create_pymem_link(int pid)
{
    ubpf_link_t *link;
    int ret;

    link = (ubpf_link_t *)calloc(1, sizeof(ubpf_link_t));
    if (!link) {
        return NULL;
    }

    ret = get_so_path(pid, link->elf_path, sizeof(link->elf_path), "python");
    if (ret) {
        TP_DEBUG("Failed to get python path(pid=%d)\n", pid);
        free(link);
        return NULL;
    }

    return link;
}

int get_elf_symb_addr(char *func_name, ubpf_link_t *link, u64 *addr)
{
    int ret;

    ret = gopher_get_elf_symb(link->elf_path, func_name, addr);
    if (ret < 0) {
        TP_DEBUG("Failed to get function offset: func_name=%s, elf_path=%s\n",
            func_name, link->elf_path);
        return -1;
    }
    return 0;
}

int attach_pthrd_sync_probes_per_proc(struct bpf_object *obj, proc_ubpf_link_t *proc_link)
{
    ubpf_link_t *pthrd_sync_link;
    int ret;

    pthrd_sync_link = create_glibc_link(proc_link->pid);
    if (!pthrd_sync_link) {
        return -1;
    }
    ret = attach_uprobe_link(obj, pthrd_sync_link, proc_link->pid, get_elf_symb_addr);
    if (ret) {
        return -1;
    }
    proc_link->pthrd_sync_link = pthrd_sync_link;

    return 0;
}

int attach_mem_glibc_probes_per_proc(struct bpf_object *obj, proc_ubpf_link_t *proc_link)
{
    ubpf_link_t *mem_glibc_link;
    int ret;

    mem_glibc_link = create_glibc_link(proc_link->pid);
    if (!mem_glibc_link) {
        return -1;
    }
    ret = attach_uprobe_link(obj, mem_glibc_link, proc_link->pid, get_elf_symb_addr);
    if (ret) {
        return -1;
    }
    proc_link->mem_glibc_link = mem_glibc_link;

    return 0;
}

int attach_mem_pymem_probes_per_proc(struct bpf_object *obj, proc_ubpf_link_t *proc_link)
{
    ubpf_link_t *mem_pymem_link;
    int ret;

    mem_pymem_link = create_pymem_link(proc_link->pid);
    if (!mem_pymem_link) {
        return -1;
    }
    ret = attach_uprobe_link(obj, mem_pymem_link, proc_link->pid, get_elf_symb_addr);
    if (ret) {
        return -1;
    }
    proc_link->mem_pymem_link = mem_pymem_link;

    return 0;
}


static proc_ubpf_link_t *find_proc_link(int pid)
{
    proc_ubpf_link_t *proc_link;

    HASH_FIND_INT(proc_link_tbl, &pid, proc_link);
    return proc_link;
}

#define LANG_JAVA_KEYWORD "java"
#define LANG_PYTHON_KEYWORD "python"

enum lang_type get_proc_lang_type(const char *exe_path)
{
    enum lang_type typ = LANG_TYPE_UNDEF;
    char *path_copy = strdup(exe_path);
    char *base_name;

    if (!path_copy) {
        return typ;
    }
    base_name = basename(path_copy);
    if (!base_name) {
        free(path_copy);
        return typ;
    }

    if (strcmp(base_name, LANG_JAVA_KEYWORD) == 0) {
        typ = LANG_TYPE_JAVA;
    } else if (strncmp(base_name, LANG_PYTHON_KEYWORD, strlen(LANG_PYTHON_KEYWORD)) == 0) {
        typ = LANG_TYPE_PYTHON;
    }

    free(path_copy);
    return typ;
}

static int add_proc_link(int pid, proc_ubpf_link_t **proc_link_ptr)
{
    proc_ubpf_link_t *proc_link;
    int ret;

    *proc_link_ptr = NULL;
    if (HASH_COUNT(proc_link_tbl) >= MAX_PROC_LINK_TBL_NUM) {
        TP_WARN("Failed to add proc link: table full\n");
        return -1;
    }

    proc_link = (proc_ubpf_link_t *)calloc(1, sizeof(proc_ubpf_link_t));
    if (!proc_link) {
        return -1;
    }
    proc_link->pid = pid;
    proc_link->is_active = 1;
    ret = get_proc_exe(pid, proc_link->exe_path, sizeof(proc_link->exe_path));
    if (ret) {
        TP_DEBUG("Failed to get proc exe path(pid=%d)\n", pid);
        free(proc_link);
        return -1;
    }
    proc_link->lang = get_proc_lang_type(proc_link->exe_path);

    HASH_ADD_INT(proc_link_tbl, pid, proc_link);
    *proc_link_ptr = proc_link;
    return 0;
}

void destroy_proc_link(proc_ubpf_link_t *proc_link)
{
    if (!proc_link) {
        return;
    }
    if (proc_link->pygc_link != NULL) {
        unload_uprobe_link(&proc_link->pygc_link);
    }
    if (proc_link->pthrd_sync_link != NULL) {
        unload_uprobe_link(&proc_link->pthrd_sync_link);
    }
    if (proc_link->mem_glibc_link != NULL) {
        unload_uprobe_link(&proc_link->mem_glibc_link);
    }
    if (proc_link->mem_pymem_link != NULL) {
        unload_uprobe_link(&proc_link->mem_pymem_link);
    }
    free(proc_link);
}

int attach_uprobes(struct ipc_body_s *ipc_body)
{
    proc_ubpf_link_t *proc_link;
    struct bpf_object *pygc_obj = NULL;
    struct bpf_object *pthrd_sync_obj = NULL;
    struct bpf_object *mem_glibc_obj = NULL;
    struct bpf_object *mem_pymem_obj = NULL;
    int pid;
    int i;
    int ret;

    if (tprofiler.pygc_skel != NULL) {
        pygc_obj = GET_PROG_OBJ_BY_SKEL(tprofiler.pygc_skel, pygc);
    }
    if (tprofiler.pthrd_sync_skel != NULL) {
        pthrd_sync_obj = GET_PROG_OBJ_BY_SKEL(tprofiler.pthrd_sync_skel, pthrd_sync);
    }
    if (tprofiler.mem_glibc_skel != NULL) {
        mem_glibc_obj = GET_PROG_OBJ_BY_SKEL(tprofiler.mem_glibc_skel, mem_glibc);
    }
    if (tprofiler.mem_pymem_skel != NULL) {
        mem_pymem_obj = GET_PROG_OBJ_BY_SKEL(tprofiler.mem_pymem_skel, mem_pymem);
    }
    for (i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        if (ipc_body->snooper_objs[i].type != SNOOPER_OBJ_PROC) {
            continue;
        }
        pid = ipc_body->snooper_objs[i].obj.proc.proc_id;

        proc_link = find_proc_link(pid);
        if (!proc_link) {
            (void)add_proc_link(pid, &proc_link);
            if (!proc_link) {
                continue;
            }
        }
        if (pygc_obj != NULL && proc_link->lang == LANG_TYPE_PYTHON && proc_link->pygc_link == NULL) {
            ret = attach_pygc_probes_per_proc(pygc_obj, proc_link);
            if (ret) {
                TP_DEBUG("Failed to attach pygc probes: pid=%d\n", pid);
            }
        }
        if (pthrd_sync_obj != NULL && proc_link->pthrd_sync_link == NULL) {
            ret = attach_pthrd_sync_probes_per_proc(pthrd_sync_obj, proc_link);
            if (ret) {
                TP_DEBUG("Failed to attach pthrd_sync probes: pid=%d\n", pid);
            }
        }

        if (proc_link->lang == LANG_TYPE_PYTHON) {
            if (mem_pymem_obj != NULL && proc_link->mem_pymem_link == NULL) {
                ret = attach_mem_pymem_probes_per_proc(mem_pymem_obj, proc_link);
                if (ret == 0) {
                    return 0;
                }
                TP_DEBUG("Failed to attach mem_pymem probes: pid=%d\n", pid);
            }
        }
        if (mem_glibc_obj != NULL && proc_link->mem_glibc_link == NULL) {
            ret = attach_mem_glibc_probes_per_proc(mem_glibc_obj, proc_link);
            if (ret) {
                TP_DEBUG("Failed to attach mem_glibc probes: pid=%d\n", pid);
            }
        }
    }

    return 0;
}

int __load_pygc_bpf_prog(struct bpf_prog_s *prog, struct ipc_body_s *ipc_body)
{
    int ret;

    LOAD_PYGC_PROBE(pygc, err, 1, &tprofiler.pbMgmt);
    prog->skels[prog->num].skel = pygc_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)pygc_bpf__destroy;
    prog->custom_btf_paths[prog->num] = pygc_open_opts.btf_custom_path;

    ret = open_profiling_bpf_buffer(&tprofiler.pbMgmt);
    if (ret) {
        goto err;
    }

    prog->num++;
    tprofiler.pygc_skel = (void *)pygc_skel;
    return 0;
err:
    UNLOAD(pygc);
    CLEANUP_CUSTOM_BTF(pygc);
    return -1;
}

int __load_pthrd_sync_bpf_prog(struct bpf_prog_s *prog, struct ipc_body_s *ipc_body)
{
    int ret;

    LOAD_PTHRD_SYNC_PROBE(pthrd_sync, err, 1, &tprofiler.pbMgmt);
    prog->skels[prog->num].skel = pthrd_sync_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)pthrd_sync_bpf__destroy;
    prog->custom_btf_paths[prog->num] = pthrd_sync_open_opts.btf_custom_path;

    ret = open_profiling_bpf_buffer(&tprofiler.pbMgmt);
    if (ret) {
        goto err;
    }

    prog->num++;
    tprofiler.pthrd_sync_skel = (void *)pthrd_sync_skel;
    return 0;
err:
    UNLOAD(pthrd_sync);
    CLEANUP_CUSTOM_BTF(pthrd_sync);
    return -1;
}

int __load_mem_glibc_bpf_prog(struct bpf_prog_s *prog, struct ipc_body_s *ipc_body)
{
    int ret;

    LOAD_MEM_GLIBC_PROBE(mem_glibc, err, 1, &tprofiler.pbMgmt);
    prog->skels[prog->num].skel = mem_glibc_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)mem_glibc_bpf__destroy;
    prog->custom_btf_paths[prog->num] = mem_glibc_open_opts.btf_custom_path;

    ret = open_profiling_bpf_buffer(&tprofiler.pbMgmt);
    if (ret) {
        goto err;
    }

    prog->num++;
    tprofiler.mem_glibc_skel = (void *)mem_glibc_skel;
    return 0;
err:
    UNLOAD(mem_glibc);
    CLEANUP_CUSTOM_BTF(mem_glibc);
    return -1;
}

int __load_mem_pymem_bpf_prog(struct bpf_prog_s *prog, struct ipc_body_s *ipc_body)
{
    int ret;

    LOAD_MEM_GLIBC_PROBE(mem_pymem, err, 1, &tprofiler.pbMgmt);
    prog->skels[prog->num].skel = mem_pymem_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)mem_pymem_bpf__destroy;
    prog->custom_btf_paths[prog->num] = mem_pymem_open_opts.btf_custom_path;

    ret = open_profiling_bpf_buffer(&tprofiler.pbMgmt);
    if (ret) {
        goto err;
    }

    prog->num++;
    tprofiler.mem_pymem_skel = (void *)mem_pymem_skel;
    return 0;
err:
    UNLOAD(mem_pymem);
    CLEANUP_CUSTOM_BTF(mem_pymem);
    return -1;
}

void deactivate_proc_link_tbl()
{
    proc_ubpf_link_t *link, *tmp;

    HASH_ITER(hh, proc_link_tbl, link, tmp) {
        link->is_active = 0;
    }
}

void activate_proc_link_tbl(struct ipc_body_s *ipc_body)
{
    proc_ubpf_link_t *link;
    int pid;
    int i;

    for (i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        if (ipc_body->snooper_objs[i].type != SNOOPER_OBJ_PROC) {
            continue;
        }
        pid = ipc_body->snooper_objs[i].obj.proc.proc_id;
        link = find_proc_link(pid);
        if (link) {
            link->is_active = 1;
        }
    }
}

void clean_inactive_proc_links()
{
    proc_ubpf_link_t *link, *tmp;

    HASH_ITER(hh, proc_link_tbl, link, tmp) {
        if (!link->is_active) {
            HASH_DEL(proc_link_tbl, link);
            destroy_proc_link(link);
        }
    }
}

void clean_proc_link_tbl()
{
    proc_ubpf_link_t *link, *tmp;

    HASH_ITER(hh, proc_link_tbl, link, tmp) {
        HASH_DEL(proc_link_tbl, link);
        destroy_proc_link(link);
    }
}

void refresh_proc_link_tbl(struct ipc_body_s *ipc_body)
{
    deactivate_proc_link_tbl();
    activate_proc_link_tbl(ipc_body);
    clean_inactive_proc_links();
}

void reattach_uprobes(struct ipc_body_s *ipc_body)
{
    if (tprofiler.pygc_skel == NULL && tprofiler.pthrd_sync_skel == NULL &&
        tprofiler.mem_glibc_skel == NULL && tprofiler.mem_pymem_skel == NULL) {
        return;
    }
    refresh_proc_link_tbl(ipc_body);
    (void)attach_uprobes(ipc_body);
}

int load_pygc_bpf_prog(struct ipc_body_s *ipc_body, struct bpf_prog_s *prog)
{
    char is_load;
    int ret;

    is_load = is_load_probe_ipc(ipc_body, PROBE_RANGE_TPROFILING_PYTHON_GC);
    if (!is_load) {
        return 0;
    }
    ret = __load_pygc_bpf_prog(prog, ipc_body);
    if (ret) {
        return -1;
    }

    return 0;
}

int load_pthrd_sync_bpf_prog(struct ipc_body_s *ipc_body, struct bpf_prog_s *prog)
{
    char is_load;
    int ret;

    is_load = is_load_probe_ipc(ipc_body, PROBE_RANGE_TPROFILING_PTHREAD_SYNC);
    if (!is_load) {
        return 0;
    }
    ret = __load_pthrd_sync_bpf_prog(prog, ipc_body);
    if (ret) {
        return -1;
    }

    return 0;
}

int load_mem_glibc_bpf_prog(struct ipc_body_s *ipc_body, struct bpf_prog_s *prog)
{
    char is_load;
    int ret;

    is_load = is_load_probe_ipc(ipc_body, PROBE_RANGE_TPROFILING_MEM_GLIBC);
    if (!is_load) {
        return 0;
    }
    ret = __load_mem_glibc_bpf_prog(prog, ipc_body);
    if (ret) {
        return -1;
    }
    ret = __load_mem_pymem_bpf_prog(prog, ipc_body);
    if (ret) {
        return -1;
    }
    return 0;
}

void destroy_bpf_links(struct bpf_link **links, int link_size)
{
    int i;

    if (links == NULL) {
        return;
    }

    for (i = 0; i < link_size; i++) {
        (void)bpf_link__destroy(links[i]);
        links[i] = NULL;
    }
    free(links);
}

int attach_oncpu_sample_bpf_prog(struct bpf_program *bpf_prog, struct bpf_link **links, int link_size)
{
    struct perf_event_attr attr = {
        .sample_freq = DFT_PERF_SAMPLE_FREQ,
        .freq = 1,
        .type = PERF_TYPE_SOFTWARE,
        .config = PERF_COUNT_SW_CPU_CLOCK
    };
    int pmu_fd;
    int cpu_num = NR_CPUS;
    int cpu;

    if (cpu_num > link_size) {
        return -1;
    }

    for (cpu = 0; cpu < cpu_num; cpu++) {
        pmu_fd = perf_event_open(&attr, -1, cpu, -1, 0);
        if (pmu_fd < 0) {
            if (errno == ENODEV) {
                continue;
            }
            TP_ERROR("Failed to open perf event on cpu[%d]\n", cpu);
            return -1;
        }
        links[cpu] = bpf_program__attach_perf_event(bpf_prog, pmu_fd);
        if (links[cpu] == NULL) {
            TP_ERROR("Failed to attach perf event on cpu[%d]\n", cpu);
            close(pmu_fd);
            return -1;
        }
        // no need to close pmu_fd here because it is related to the links[cpu] object
    }

    return 0;
}

int __load_oncpu_sample_bpf_prog(struct bpf_prog_s *prog, struct ipc_body_s *ipc_body)
{
    struct bpf_link **links = NULL;
    int link_num;
    int ret;

    LOAD_ONCPU_SAMPLE_PROBE(oncpu_sample, err, 1, &tprofiler.pbMgmt);
    prog->skels[prog->num].skel = oncpu_sample_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)oncpu_sample_bpf__destroy;
    prog->custom_btf_paths[prog->num] = oncpu_sample_open_opts.btf_custom_path;

    link_num = NR_CPUS;
    links = (struct bpf_link **)calloc(link_num, sizeof(void *));
    if (links == NULL) {
        goto err;
    }
    ret = attach_oncpu_sample_bpf_prog(GET_PROGRAM_OBJ(oncpu_sample, bpf_perf_event_func), links, link_num);
    if (ret) {
        goto err;
    }

    ret = open_profiling_bpf_buffer(&tprofiler.pbMgmt);
    if (ret) {
        goto err;
    }

    tprofiler.oncpu_sample_bpf_links = (void **)links;
    tprofiler.oncpu_sample_link_num = link_num;
    prog->num++;
    return 0;
err:
    if (links != NULL) {
        destroy_bpf_links(links, link_num);
    }
    UNLOAD(oncpu_sample);
    CLEANUP_CUSTOM_BTF(oncpu_sample);
    return -1;
}

int load_oncpu_sample_bpf_prog(struct ipc_body_s *ipc_body, struct bpf_prog_s *prog)
{
    char is_load;
    int ret;

    is_load = is_load_probe_ipc(ipc_body, PROBE_RANGE_TPROFILING_ONCPU_SAMPLE);
    if (!is_load) {
        return 0;
    }
    ret = __load_oncpu_sample_bpf_prog(prog, ipc_body);
    if (ret) {
        return -1;
    }

    return 0;
}

void unload_oncpu_sample_links()
{
    if (tprofiler.oncpu_sample_bpf_links != NULL) {
        destroy_bpf_links((struct bpf_link **)tprofiler.oncpu_sample_bpf_links, tprofiler.oncpu_sample_link_num);
        tprofiler.oncpu_sample_bpf_links = NULL;
    }
    tprofiler.oncpu_sample_link_num = 0;
}

int load_profiling_bpf_progs(struct ipc_body_s *ipc_body)
{
    struct bpf_prog_s *prog;
    int ret;

    tprofiler.bpf_progs = NULL;
    if (!is_load_probe_ipc(ipc_body, TPROFILING_EBPF_PROBE_ALL)) {
        return 0;
    }
    prog = alloc_bpf_prog();
    if (prog == NULL) {
        TP_ERROR("Failed to allocate bpf prog\n");
        goto err;
    }

    ret = load_syscall_bpf_prog(ipc_body, prog);
    if (ret) {
        TP_ERROR("Failed to load syscall bpf prog\n");
        goto err;
    }
    ret = load_oncpu_bpf_prog(ipc_body, prog);
    if (ret) {
        TP_ERROR("Failed to load oncpu bpf prog\n");
        goto err;
    }
    ret = load_offcpu_bpf_prog(ipc_body, prog);
    if (ret) {
        TP_ERROR("Failed to load offcpu bpf prog\n");
        goto err;
    }
    ret = load_pygc_bpf_prog(ipc_body, prog);
    if (ret) {
        TP_ERROR("Failed to load pygc bpf prog\n");
        goto err;
    }
    ret = load_pthrd_sync_bpf_prog(ipc_body, prog);
    if (ret) {
        TP_ERROR("Failed to load pthread_sync bpf prog\n");
        goto err;
    }
    ret = load_mem_glibc_bpf_prog(ipc_body, prog);
    if (ret) {
        TP_ERROR("Failed to load mem_glibc bpf prog\n");
        goto err;
    }
    ret = load_oncpu_sample_bpf_prog(ipc_body, prog);
    if (ret) {
        TP_ERROR("Failed to load oncpu sample bpf prog\n");
        goto err;
    }

    tprofiler.bpf_progs = prog;
    return 0;
err:
    clean_profiling_bpf_buffer(&tprofiler.pbMgmt);
    unload_bpf_prog(&prog);
    return -1;
}

void unload_profiling_bpf_prog()
{
    if (tprofiler.bpf_progs == NULL) {
        return;
    }

    unload_uprobe_links();  // must be called before calling unload_bpf_prog()
    unload_oncpu_sample_links();
    clean_profiling_bpf_buffer(&tprofiler.pbMgmt);
    unload_bpf_prog(&tprofiler.bpf_progs);

    // they are invalid after calling unload_bpf_prog(), set them to null
    tprofiler.pygc_skel = NULL;
    tprofiler.pthrd_sync_skel = NULL;
    tprofiler.mem_glibc_skel = NULL;
    tprofiler.mem_pymem_skel = NULL;
}