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
 * Author: luzhihao
 * Create: 2024-04-22
 * Description: sli probe
 ******************************************************************************/
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "args.h"
#include "ipc.h"
#include "hash.h"
#include "cpu_sli.skel.h"
#include "mem_sli.skel.h"
#include "io_sli.skel.h"
#include "sli_obj.h"
#include "histogram.h"

#define OO_SLI_NODE "sli_node"  // Observation Object name
#define OO_SLI_CONTAINER "sli_container"  // Observation Object name

#define SLI_CPU_NODE                "sli_cpu_node"
#define SLI_CPU_CONTAINER      "sli_cpu_container"
#define SLI_MEM_NODE                "sli_mem_node"
#define SLI_MEM_CONTAINER      "sli_mem_container"
#define SLI_IO_NODE                  "sli_io_node"
#define SLI_IO_CONTAINER        "sli_io_container"

#define SLI_TBL_NODE_KEY        "sli_node_key"

/* Path to pin map */
#define SLI_ARGS_PATH            "/sys/fs/bpf/gala-gopher/__sli_args"
#define SLI_CPU_PATH             "/sys/fs/bpf/gala-gopher/__sli_cpu"
#define SLI_MEM_PATH             "/sys/fs/bpf/gala-gopher/__sli_mem"
#define SLI_IO_PATH              "/sys/fs/bpf/gala-gopher/__sli_io"

#define RM_SLI_PATH              "/usr/bin/rm -rf /sys/fs/bpf/gala-gopher/__sli*"

#define __OPEN_SLI_CPU(probe_name, end, load, buffer) \
    INIT_OPEN_OPTS(probe_name); \
    PREPARE_CUSTOM_BTF(probe_name); \
    OPEN_OPTS(probe_name, end, load); \
    MAP_INIT_BPF_BUFFER(probe_name, sli_cpu_channel_map, buffer, load); \
    MAP_SET_PIN_PATH(probe_name, sli_args_map, SLI_ARGS_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, sli_cpu_map, SLI_CPU_PATH, load);

#define __OPEN_SLI_MEM(probe_name, end, load, buffer) \
    INIT_OPEN_OPTS(probe_name); \
    PREPARE_CUSTOM_BTF(probe_name); \
    OPEN_OPTS(probe_name, end, load); \
    MAP_INIT_BPF_BUFFER(probe_name, sli_mem_channel_map, buffer, load); \
    MAP_SET_PIN_PATH(probe_name, sli_args_map, SLI_ARGS_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, sli_mem_map, SLI_MEM_PATH, load);

#define __OPEN_SLI_IO(probe_name, end, load, buffer) \
    INIT_OPEN_OPTS(probe_name); \
    PREPARE_CUSTOM_BTF(probe_name); \
    OPEN_OPTS(probe_name, end, load); \
    MAP_INIT_BPF_BUFFER(probe_name, sli_io_channel_map, buffer, load); \
    MAP_SET_PIN_PATH(probe_name, sli_args_map, SLI_ARGS_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, sli_io_map, SLI_IO_PATH, load);

#define SLI_UNKNOW      0x00000001
#define SLI_RUNNING     0x00000002

struct sli_container_s {
    H_HANDLE;
    cpu_cgrp_inode_t ino;
    char *container_id;
    u32 flags;
};

struct sli_probe_s {
    struct ipc_body_s ipc_body;
    struct sli_container_s *container_caches;
    struct bpf_prog_s* prog;
    int sli_args_fd;
    int sli_cpu_fd;
    int sli_mem_fd;
    int sli_io_fd;
    int init;
};

static struct sli_probe_s g_sli_probe;
static volatile sig_atomic_t g_stop;

static void destroy_sli_container(struct sli_probe_s *probe, struct sli_container_s *cache)
{
    (void)bpf_map_delete_elem(probe->sli_cpu_fd, &(cache->ino));
    (void)bpf_map_delete_elem(probe->sli_mem_fd, &(cache->ino));
    (void)bpf_map_delete_elem(probe->sli_io_fd, &(cache->ino));
    if (cache->container_id) {
        INFO("[SLIPROBE]: Del container succeed.(con_id = %s)\n", cache->container_id);
        free(cache->container_id);
        cache->container_id = NULL;
    }
    free(cache);
}

static void deinit_sli_container_tbl(struct sli_probe_s *probe)
{
    struct sli_container_s *cache, *tmp;

    H_ITER(probe->container_caches, cache, tmp) {
        H_DEL(probe->container_caches, cache);
        destroy_sli_container(probe, cache);
    }

    return;
}

static void destroy_sli_container_tbl_by_flags(struct sli_probe_s *probe, u32 flags)
{
    struct sli_container_s *cache, *tmp;

    H_ITER(probe->container_caches, cache, tmp) {
        if (cache->flags & flags) {
            H_DEL(probe->container_caches, cache);
            destroy_sli_container(probe, cache);
        }
    }

    return;
}

static void flush_sli_container_tbl(struct sli_probe_s *probe, u32 flags)
{
    struct sli_container_s *cache, *tmp;

    H_ITER(probe->container_caches, cache, tmp) {
        if (cache->ino != CPUACCT_GLOBAL_CGPID) {
            cache->flags = flags;
        }
    }

    return;
}

static int add_sli_container(struct sli_probe_s *probe, cpu_cgrp_inode_t ino, const char* container_id)
{
    struct sli_cpu_obj_s sli_cpu = {.cpu_cgroup_inode = ino};
    struct sli_mem_obj_s sli_mem = {.cpu_cgroup_inode = ino};
    struct sli_io_obj_s sli_io = {.cpu_cgroup_inode = ino};
    struct sli_container_s *container_cache = (struct sli_container_s *)malloc(sizeof(struct sli_container_s));
    if (container_cache == NULL) {
        return -1;
    }

    memset(container_cache, 0, sizeof(struct sli_container_s));

    if (container_id) {
        container_cache->container_id = strdup(container_id);
        if (container_cache->container_id == NULL) {
            free(container_cache);
            return -1;
        }
    }

    container_cache->ino = ino;
    container_cache->flags = SLI_RUNNING;
    H_ADD_KEYPTR(probe->container_caches, &container_cache->ino, sizeof(cpu_cgrp_inode_t), container_cache);

    (void)bpf_map_update_elem(probe->sli_cpu_fd, &container_cache->ino, &sli_cpu, BPF_ANY);
    (void)bpf_map_update_elem(probe->sli_mem_fd, &container_cache->ino, &sli_mem, BPF_ANY);
    (void)bpf_map_update_elem(probe->sli_io_fd, &container_cache->ino, &sli_io, BPF_ANY);

    return 0;
}

static struct sli_container_s * lkup_sli_container(struct sli_probe_s *probe, cpu_cgrp_inode_t ino)
{
    struct sli_container_s* sli_container = NULL;

    H_FIND(probe->container_caches, &ino, sizeof(cpu_cgrp_inode_t), sli_container);
    return sli_container;
}

static int load_default_container(struct sli_probe_s *probe)
{
    return add_sli_container(probe, CPUACCT_GLOBAL_CGPID, NULL);
}

static void reload_sli_container_tbl(struct sli_probe_s *probe)
{
    struct snooper_con_info_s *container;
    struct sli_container_s *sli_container;
    struct ipc_body_s *ipc_body = &probe->ipc_body;

    flush_sli_container_tbl(probe, SLI_UNKNOW);

    for (int i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        if (ipc_body->snooper_objs[i].type != SNOOPER_OBJ_CON) {
            continue;
        }

        container = &(ipc_body->snooper_objs[i].obj.con_info);

        sli_container = lkup_sli_container(probe, (cpu_cgrp_inode_t)container->cpucg_inode);
        if (sli_container) {
            sli_container->flags = SLI_RUNNING;
            continue;
        }

        if (add_sli_container(probe, (cpu_cgrp_inode_t)container->cpucg_inode, (const char *)container->con_id)) {
            ERROR("[SLIPROBE]: Add container failed.(con_id = %s)\n", container->con_id);
        } else {
            INFO("[SLIPROBE]: Add container succeed.(con_id = %s)\n", container->con_id);
        }
    }

    destroy_sli_container_tbl_by_flags(probe, SLI_UNKNOW);

    return;
}

static void sig_int(int signo)
{
    g_stop = 1;
}

static void __rcv_sli_cpu_container(struct sli_probe_s *probe, struct sli_container_s * sli_container, struct sli_cpu_obj_s *sli_cpu_obj)
{
    (void)fprintf(stdout,
        "|%s|%s"
        "|%llu|%llu|%llu|%llu|%llu|%llu|\n",
        SLI_CPU_CONTAINER,
        sli_container->container_id,

        sli_cpu_obj->sli.lat_ns[SLI_CPU_WAIT],
        sli_cpu_obj->sli.lat_ns[SLI_CPU_SLEEP],
        sli_cpu_obj->sli.lat_ns[SLI_CPU_IOWAIT],
        sli_cpu_obj->sli.lat_ns[SLI_CPU_BLOCK],
        sli_cpu_obj->sli.lat_ns[SLI_CPU_RUNDELAY],
        sli_cpu_obj->sli.lat_ns[SLI_CPU_LONGSYS]);
    (void)fflush(stdout);
    return;
}

static int __rcv_sli_cpu(struct sli_probe_s *probe, struct sli_cpu_obj_s *sli_cpu_obj)
{
    struct sli_container_s * sli_container = lkup_sli_container(probe, sli_cpu_obj->cpu_cgroup_inode);
    if (!sli_container) {
        return -1;
    }

    if (sli_container->ino != CPUACCT_GLOBAL_CGPID) {
        __rcv_sli_cpu_container(probe, sli_container, sli_cpu_obj);
    }
    return 0;
}

static int rcv_sli_cpu(void *ctx, void *data, __u32 size)
{
    char *p = data;
    size_t remain_size = (size_t)size, step_size = sizeof(struct sli_cpu_obj_s), offset = 0;
    struct sli_cpu_obj_s *sli_cpu_obj;
    struct sli_probe_s *probe = ctx;

    do {
        if (remain_size < step_size) {
            break;
        }
        p = (char *)data + offset;
        sli_cpu_obj = (struct sli_cpu_obj_s *)p;

        (void)__rcv_sli_cpu(probe, sli_cpu_obj);

        offset += step_size;
        remain_size -= step_size;
    } while (1);

    return 0;
}

static void __rcv_sli_mem_container(struct sli_probe_s *probe, struct sli_container_s * sli_container, struct sli_mem_obj_s *sli_mem_obj)
{
    (void)fprintf(stdout,
        "|%s|%s"
        "|%llu|%llu|%llu|\n",
        SLI_MEM_CONTAINER,
        sli_container->container_id,
        sli_mem_obj->sli.lat_ns[SLI_MEM_RECLAIM],
        sli_mem_obj->sli.lat_ns[SLI_MEM_COMPACT],
        sli_mem_obj->sli.lat_ns[SLI_MEM_SWAPIN]);
    (void)fflush(stdout);
    return;
}

static int __rcv_sli_mem(struct sli_probe_s *probe, struct sli_mem_obj_s *sli_mem_obj)
{
    struct sli_container_s * sli_container = lkup_sli_container(probe, sli_mem_obj->cpu_cgroup_inode);
    if (!sli_container) {
        return -1;
    }

    if (sli_container->ino != CPUACCT_GLOBAL_CGPID) {
        __rcv_sli_mem_container(probe, sli_container, sli_mem_obj);
    }
    return 0;
}

static int rcv_sli_mem(void *ctx, void *data, __u32 size)
{
    char *p = data;
    size_t remain_size = (size_t)size, step_size = sizeof(struct sli_mem_obj_s), offset = 0;
    struct sli_mem_obj_s *sli_mem_obj;
    struct sli_probe_s *probe = ctx;

    do {
        if (remain_size < step_size) {
            break;
        }
        p = (char *)data + offset;
        sli_mem_obj  = (struct sli_mem_obj_s *)p;

        (void)__rcv_sli_mem(probe, sli_mem_obj);

        offset += step_size;
        remain_size -= step_size;
    } while (1);

    return 0;
}

static void __rcv_sli_io_container(struct sli_probe_s *probe, struct sli_container_s *sli_container, struct sli_io_obj_s *sli_io_obj)
{
    (void)fprintf(stdout,
        "|%s|%s"
        "|%llu|\n",
        SLI_IO_CONTAINER,
        sli_container->container_id,
        sli_io_obj->sli.lat_ns);
    (void)fflush(stdout);
    return;
}

static int __rcv_sli_io(struct sli_probe_s *probe, struct sli_io_obj_s *sli_io_obj)
{
    struct sli_container_s * sli_container = lkup_sli_container(probe, sli_io_obj->cpu_cgroup_inode);
    if (!sli_container) {
        return -1;
    }

    if (sli_container->ino != CPUACCT_GLOBAL_CGPID) {
        __rcv_sli_io_container(probe, sli_container, sli_io_obj);
    }
    return 0;
}

static int rcv_sli_io(void *ctx, void *data, __u32 size)
{
    char *p = data;
    size_t remain_size = (size_t)size, step_size = sizeof(struct sli_io_obj_s), offset = 0;
    struct sli_io_obj_s *sli_io_obj;
    struct sli_probe_s *probe = ctx;

    do {
        if (remain_size < step_size) {
            break;
        }
        p = (char *)data + offset;
        sli_io_obj  = (struct sli_io_obj_s *)p;

        (void)__rcv_sli_io(probe, sli_io_obj);

        offset += step_size;
        remain_size -= step_size;
    } while (1);

    return 0;
}

static int load_sli_args(int fd, struct ipc_body_s* ipc_body)
{
    u32 key = 0;
    struct sli_args_s sli_args = {0};

    if (fd < 0) {
        return -1;
    }

    sli_args.report_period = NS(ipc_body->probe_param.period);

    return bpf_map_update_elem(fd, &key, &sli_args, BPF_ANY);
}

static int load_sli_cpu_probe(struct sli_probe_s *sli_probe, struct bpf_prog_s *prog)
{
    int ret;
    struct bpf_buffer *buffer = NULL;

    __OPEN_SLI_CPU(cpu_sli, err, 1, buffer);
    prog->skels[prog->num].skel = cpu_sli_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)cpu_sli_bpf__destroy;
    prog->custom_btf_paths[prog->num] = cpu_sli_open_opts.btf_custom_path;

    LOAD_ATTACH(sliprobe, cpu_sli, err, 1);

    ret = bpf_buffer__open(buffer, rcv_sli_cpu, NULL, sli_probe);
    if (ret) {
        ERROR("[SLIPROBE] Open 'cpu_sli' bpf_buffer failed.\n");
        bpf_buffer__free(buffer);
        goto err;
    }
    prog->buffers[prog->num] = buffer;
    prog->num++;

    if (sli_probe->sli_args_fd <= 0) {
        sli_probe->sli_args_fd = GET_MAP_FD(cpu_sli, sli_args_map);
    }

    if (sli_probe->sli_cpu_fd <= 0) {
        sli_probe->sli_cpu_fd = GET_MAP_FD(cpu_sli, sli_cpu_map);
    }

    return 0;
err:
    UNLOAD(cpu_sli);
    CLEANUP_CUSTOM_BTF(cpu_sli);
    return -1;
}

static int load_sli_mem_probe(struct sli_probe_s *sli_probe, struct bpf_prog_s *prog)
{
    int ret;
    struct bpf_buffer *buffer = NULL;

    __OPEN_SLI_MEM(mem_sli, err, 1, buffer);
    prog->skels[prog->num].skel = mem_sli_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)mem_sli_bpf__destroy;
    prog->custom_btf_paths[prog->num] = mem_sli_open_opts.btf_custom_path;

    LOAD_ATTACH(sliprobe, mem_sli, err, 1);

    ret = bpf_buffer__open(buffer, rcv_sli_mem, NULL, sli_probe);
    if (ret) {
        ERROR("[SLIPROBE] Open 'mem_sli' bpf_buffer failed.\n");
        bpf_buffer__free(buffer);
        goto err;
    }
    prog->buffers[prog->num] = buffer;
    prog->num++;

    if (sli_probe->sli_args_fd <= 0) {
        sli_probe->sli_args_fd = GET_MAP_FD(mem_sli, sli_args_map);
    }

    if (sli_probe->sli_mem_fd <= 0) {
        sli_probe->sli_mem_fd = GET_MAP_FD(mem_sli, sli_mem_map);
    }

    return 0;
err:
    UNLOAD(mem_sli);
    CLEANUP_CUSTOM_BTF(mem_sli);
    return -1;
}

static int load_sli_io_probe(struct sli_probe_s *sli_probe, struct bpf_prog_s *prog)
{
    int ret;
    struct bpf_buffer *buffer = NULL;

    __OPEN_SLI_IO(io_sli, err, 1, buffer);
    int kern_ver = probe_kernel_version();
    int is_load = (kern_ver > KERNEL_VERSION(4, 19, 0));
    int is_single_arg = (kern_ver > KERNEL_VERSION(5, 11, 0));
    PROG_ENABLE_ONLY_IF(io_sli, bpf_raw_trace_block_bio_queue_single_arg, is_load && is_single_arg);
    PROG_ENABLE_ONLY_IF(io_sli, bpf_raw_trace_block_bio_queue_double_arg, is_load && (!is_single_arg));
    PROG_ENABLE_ONLY_IF(io_sli, bpf_generic_make_request_checks, !is_load);
    PROG_ENABLE_ONLY_IF(io_sli, bpf_ret_generic_make_request_checks, !is_load);
    LOAD_ATTACH(sliprobe, io_sli, err, is_load);

    if (is_load) {
        prog->skels[prog->num].skel = io_sli_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)io_sli_bpf__destroy;
        prog->custom_btf_paths[prog->num] = io_sli_open_opts.btf_custom_path;

        ret = bpf_buffer__open(buffer, rcv_sli_io, NULL, sli_probe);
        if (ret) {
            ERROR("[SLIPROBE] Open 'io_sli' bpf_buffer failed.\n");
            bpf_buffer__free(buffer);
            goto err;
        }
        prog->buffers[prog->num] = buffer;
        prog->num++;

        if (sli_probe->sli_args_fd <= 0) {
            sli_probe->sli_args_fd = GET_MAP_FD(io_sli, sli_args_map);
        }

        if (sli_probe->sli_io_fd <= 0) {
            sli_probe->sli_io_fd = GET_MAP_FD(io_sli, sli_io_map);
        }
    }

    return 0;
err:
    UNLOAD(io_sli);
    CLEANUP_CUSTOM_BTF(io_sli);
    return -1;
}

static void sliprobe_unload_bpf(struct sli_probe_s *sli_probe)
{
    unload_bpf_prog(&(sli_probe->prog));
    sli_probe->sli_args_fd = -1;
}

static int sliprobe_load_bpf(struct sli_probe_s *sli_probe, struct ipc_body_s *ipc_body)
{
    int ret;

    sli_probe->prog = alloc_bpf_prog();
    if (sli_probe->prog == NULL) {
        return -1;
    }

    ret = load_sli_cpu_probe(sli_probe, sli_probe->prog);
    if (ret) {
        goto err;
    }

    ret = load_sli_mem_probe(sli_probe, sli_probe->prog);
    if (ret) {
        goto err;
    }

    ret = load_sli_io_probe(sli_probe, sli_probe->prog);
    if (ret) {
        goto err;
    }

    ret = load_sli_args(sli_probe->sli_args_fd, ipc_body);
    if (ret) {
        ERROR("[SLIPROBE] load sli args failed.\n");
        goto err;
    }

    return 0;
err:
    sliprobe_unload_bpf(sli_probe);
    return ret;
}

int main(int argc, char **argv)
{
    int ret = 0;
    FILE *fp = NULL;
    struct sli_probe_s *sli_probe = &g_sli_probe;
    struct ipc_body_s ipc_body;

    fp = popen(RM_SLI_PATH, "r");
    if (fp != NULL) {
        (void)pclose(fp);
        fp = NULL;
    }

    memset(&g_sli_probe, 0, sizeof(g_sli_probe));

    int msq_id = create_ipc_msg_queue(IPC_EXCL);
    if (msq_id < 0) {
        goto err;
    }

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        goto err;
    }

    INFO("Successfully started!\n");
    INIT_BPF_APP(sliprobe, EBPF_RLIM_LIMITED);

    while (!g_stop) {
        ret = recv_ipc_msg(msq_id, (long)PROBE_SLI, &ipc_body);
        if (ret == 0) {
            if (sli_probe->init == 0) {
                if (sliprobe_load_bpf(sli_probe, &ipc_body)) {
                    ERROR("[SLIPROBE]: load bpf prog failed.\n");
                    break;
                }
                load_default_container(sli_probe);
                sli_probe->init = 1;
            }

            destroy_ipc_body(&(sli_probe->ipc_body));
            (void)memcpy(&(sli_probe->ipc_body), &ipc_body, sizeof(ipc_body));
            if (ipc_body.probe_flags & IPC_FLAGS_SNOOPER_CHG || ipc_body.probe_flags == 0) {
                reload_sli_container_tbl(sli_probe);
            }
        }

        if (sli_probe->prog == NULL) {
            sleep(1);
            continue;
        }

        for (int i = 0; i < sli_probe->prog->num; i++) {
            if (sli_probe->prog->buffers[i]
                && ((ret = bpf_buffer__poll(sli_probe->prog->buffers[i], THOUSAND)) < 0)
                && ret != -EINTR) {
                ERROR("[SLIPROBE]: perf poll prog_%d failed.\n", i);
                break;
            }
        }
    }

err:
    deinit_sli_container_tbl(sli_probe);
    sliprobe_unload_bpf(sli_probe);
    destroy_ipc_body(&(sli_probe->ipc_body));

    return ret;
}

