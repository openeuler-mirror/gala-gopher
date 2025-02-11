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
#include "container.h"

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

#define SLI_CPU_NODE_STAT                   "sli_cpu_node_stat"
#define SLI_CPU_CONTAINER_STAT              "sli_cpu_container_stat"

#define SLI_CPU_NODE_GAUGE                  "sli_cpu_node_gauge"
#define SLI_CPU_NODE_HISTOGRAM              "sli_cpu_node_histogram"
#define SLI_CPU_CONTAINER_GAUGE             "sli_cpu_container_gauge"
#define SLI_CPU_CONTAINER_HISTOGRAM         "sli_cpu_container_histogram"

#define SLI_MEM_NODE_GAUGE                  "sli_mem_node_gauge"
#define SLI_MEM_NODE_HISTOGRAM              "sli_mem_node_histogram"
#define SLI_MEM_CONTAINER_GAUGE             "sli_mem_container_gauge"
#define SLI_MEM_CONTAINER_HISTOGRAM         "sli_mem_container_histogram"

#define SLI_IO_NODE_GAUGE                   "sli_io_node_gauge"
#define SLI_IO_NODE_HISTOGRAM               "sli_io_node_histogram"
#define SLI_IO_CONTAINER_GAUGE              "sli_io_container_gauge"
#define SLI_IO_CONTAINER_HISTOGRAM          "sli_io_container_histogram"

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
    int cpu_cores;
    cpu_cgrp_inode_t ino;
    u64 last_cpu_usage_ns;
    char *container_id;
    u32 flags;
    char cpu_usage_path[CG_PATH_LEN];
};

struct sli_cpu_lat_histo_s {
    enum sli_cpu_lat_t range;
    u64 min, max;
};

struct sli_mem_lat_histo_s {
    enum sli_mem_lat_t range;
    u64 min, max;
};

struct sli_io_lat_histo_s {
    enum sli_io_lat_t range;
    u64 min, max;
};

struct sli_bucket_ranges_s {
    struct bucket_range_s sli_cpu_lat_buckets[SLI_CPU_LAT_NR];
    struct bucket_range_s sli_mem_lat_buckets[SLI_MEM_LAT_NR];
    struct bucket_range_s sli_io_lat_buckets[SLI_IO_LAT_NR];
};

struct sli_probe_s {
    struct ipc_body_s ipc_body;
    struct sli_container_s *container_caches;
    struct bpf_prog_s* prog;
    u8 is_load_cpu;
    u8 is_load_mem;
    u8 is_load_io;
    u8 is_report_node;
    u8 is_report_container;
    u8 is_report_histogram;
    int host_cpu_cores;
    int sli_args_fd;
    int sli_cpu_fd;
    int sli_mem_fd;
    int sli_io_fd;
    time_t last_report;
    struct histo_bucket_array_s sli_cpu_lat_buckets;
    struct histo_bucket_array_s sli_mem_lat_buckets;
    struct histo_bucket_array_s sli_io_lat_buckets;
    struct sli_bucket_ranges_s sli_bucket_rgs;
    char cpu_wait_histo_str[MAX_HISTO_SERIALIZE_SIZE];
    char cpu_sleep_histo_str[MAX_HISTO_SERIALIZE_SIZE];
    char cpu_iowait_histo_str[MAX_HISTO_SERIALIZE_SIZE];
    char cpu_block_histo_str[MAX_HISTO_SERIALIZE_SIZE];
    char cpu_rundelay_histo_str[MAX_HISTO_SERIALIZE_SIZE];
    char cpu_longsys_histo_str[MAX_HISTO_SERIALIZE_SIZE];

    char mem_reclaim_histo_str[MAX_HISTO_SERIALIZE_SIZE];
    char mem_compact_histo_str[MAX_HISTO_SERIALIZE_SIZE];
    char mem_swapin_histo_str[MAX_HISTO_SERIALIZE_SIZE];

    char bio_latency_histo_str[MAX_HISTO_SERIALIZE_SIZE];
};

struct sli_cpu_lat_histo_s sli_cpu_lat_histios[SLI_CPU_LAT_NR] = {
    {SLI_CPU_LAT_0_1, 0,          1000000},
    {SLI_CPU_LAT_1_5, 1000000,    5000000},
    {SLI_CPU_LAT_5_10, 5000000,   10000000},
    {SLI_CPU_LAT_10_100, 10000000, 100000000},
    {SLI_CPU_LAT_100_500, 100000000, 500000000},
    {SLI_CPU_LAT_500_1000, 500000000, 1000000000},
    {SLI_CPU_LAT_1000_INTF, 1000000000, (u64)-1}
};

struct sli_mem_lat_histo_s sli_mem_lat_histios[SLI_MEM_LAT_NR] = {
    {SLI_MEM_LAT_0_1, 0,          1000000},
    {SLI_MEM_LAT_1_5, 1000000,    5000000},
    {SLI_MEM_LAT_5_10, 5000000,   10000000},
    {SLI_MEM_LAT_10_100, 10000000, 100000000},
    {SLI_MEM_LAT_100_500, 100000000, 500000000},
    {SLI_MEM_LAT_500_1000, 500000000, 1000000000},
    {SLI_MEM_LAT_1000_INTF, 1000000000, (u64)-1}
};

struct sli_io_lat_histo_s sli_io_lat_histios[SLI_IO_LAT_NR] = {
    {SLI_IO_LAT_0_1, 0,          1000000},
    {SLI_IO_LAT_1_5, 1000000,    5000000},
    {SLI_IO_LAT_5_10, 5000000,   10000000},
    {SLI_IO_LAT_10_100, 10000000, 100000000},
    {SLI_IO_LAT_100_500, 100000000, 500000000},
    {SLI_IO_LAT_500_1000, 500000000, 1000000000},
    {SLI_IO_LAT_1000_INTF, 1000000000, (u64)-1}
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

#define __CGROUP_CPUACCT_USAGE "%s/cpuacct.usage"
#define __ROOT_CGROUP_CPUACCT_USAGE "/sys/fs/cgroup/cpuacct/cpuacct.usage"
static int __fill_container_cpu_usage_path(struct sli_container_s *container_cache)
{
    if (container_cache->ino == CPUACCT_GLOBAL_CGPID) {
        (void)snprintf(container_cache->cpu_usage_path, PATH_LEN, "%s", __ROOT_CGROUP_CPUACCT_USAGE);
    } else {
        char cpucg_dir[CG_PATH_LEN];
        cpucg_dir[0] = 0;
        if (get_container_cpucg_dir(container_cache->container_id, cpucg_dir, CG_PATH_LEN) < 0) {
            return -1;
        }
        if (cpucg_dir[0] == 0) {
            return -1;
        }
        (void)snprintf(container_cache->cpu_usage_path, CG_PATH_LEN, __CGROUP_CPUACCT_USAGE, cpucg_dir);
    }
    return 0;
}

static u64 __read_cgroup_file(const char *path)
{
    u64 num = 0;
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        ERROR("[SLIPROBE] open file %s failed.\n", path);
        return 0;
    }

    char line[LINE_BUF_LEN];
    line[0] = 0;
    if (fgets(line, sizeof(line), f) != NULL) {
        num = strtoull(line, NULL, 10);
    } else {
        ERROR("[SLIPROBE] Error reading line from %s\n", path);
    }

    (void)fclose(f);

    return num;
}

#define __CGROUP_CPU_CFS_QUOTA "%s/cpu.cfs_quota_us"
#define __CGROUP_CPU_CFS_PERIOD "%s/cpu.cfs_period_us"
#define __ROOT_CGROUP_CFS_QUOTA "/sys/fs/cgroup/cpuacct/cpu.cfs_quota_us"
#define __ROOT_CGROUP_CFS_PERIOD "/sys/fs/cgroup/cpuacct/cpu.cfs_period_us"
static void __fill_container_cpu_cores(struct sli_probe_s *probe, struct sli_container_s *container_cache)
{
    char cpu_cfs_quota_path[CG_PATH_LEN];
    char cpu_cfs_period_path[CG_PATH_LEN];
    u64 cpu_cfs_quota_us;
    u64 cpu_cfs_period_us;
    if (container_cache->ino == CPUACCT_GLOBAL_CGPID) {
        (void)snprintf(cpu_cfs_quota_path, PATH_LEN, "%s", __ROOT_CGROUP_CFS_QUOTA);
        (void)snprintf(cpu_cfs_period_path, PATH_LEN, "%s", __ROOT_CGROUP_CFS_PERIOD);
    } else {
        char cpucg_dir[CG_PATH_LEN];
        cpucg_dir[0] = 0;
        if (get_container_cpucg_dir(container_cache->container_id, cpucg_dir, CG_PATH_LEN) < 0) {
            goto err;
        }
        if (cpucg_dir[0] == 0) {
            goto err;
        }
        (void)snprintf(cpu_cfs_quota_path, CG_PATH_LEN, __CGROUP_CPU_CFS_QUOTA, cpucg_dir);
        (void)snprintf(cpu_cfs_period_path, CG_PATH_LEN, __CGROUP_CPU_CFS_PERIOD, cpucg_dir);
    }

    cpu_cfs_quota_us = __read_cgroup_file(cpu_cfs_quota_path);
    cpu_cfs_period_us = __read_cgroup_file(cpu_cfs_period_path);

    if (cpu_cfs_quota_us == 0 || cpu_cfs_period_us == 0) {
        ERROR("[SLIPROBE] Error reading from :%s or :%s\n",
            cpu_cfs_quota_path, cpu_cfs_period_path);
        goto err;
    }

    if (cpu_cfs_quota_us != -1) {
        container_cache->cpu_cores = cpu_cfs_quota_us / cpu_cfs_period_us;
        return;
    }

err:
    container_cache->cpu_cores = probe->host_cpu_cores;
    return;
}

static int add_sli_container(struct sli_probe_s *probe, cpu_cgrp_inode_t ino, const char* container_id)
{
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
    if (__fill_container_cpu_usage_path(container_cache) || container_cache->cpu_usage_path[0] == 0) {
        ERROR("[SLIPROBE]: fill con[%s] cpu_usage_path failed.\n", container_cache->container_id);
        free(container_cache);
        return -1;
    }

    __fill_container_cpu_cores(probe, container_cache);

    H_ADD_KEYPTR(probe->container_caches, &container_cache->ino, sizeof(cpu_cgrp_inode_t), container_cache);

    if (probe->is_load_cpu) {
        struct sli_cpu_obj_s sli_cpu = {.cpu_cgroup_inode = ino};
        (void)bpf_map_update_elem(probe->sli_cpu_fd, &container_cache->ino, &sli_cpu, BPF_ANY);
    }
    if (probe->is_load_mem) {
        struct sli_mem_obj_s sli_mem = {.cpu_cgroup_inode = ino};
        (void)bpf_map_update_elem(probe->sli_mem_fd, &container_cache->ino, &sli_mem, BPF_ANY);
    }
    if (probe->is_load_io) {
        struct sli_io_obj_s sli_io = {.cpu_cgroup_inode = ino};
        (void)bpf_map_update_elem(probe->sli_io_fd, &container_cache->ino, &sli_io, BPF_ANY);
    }

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

static int probe_init(struct sli_probe_s *probe)
{
    HISTO_BUCKET_RANGE_INIT(g_sli_probe.sli_bucket_rgs.sli_cpu_lat_buckets, SLI_CPU_LAT_NR, sli_cpu_lat_histios);
    HISTO_BUCKET_RANGE_INIT(g_sli_probe.sli_bucket_rgs.sli_mem_lat_buckets, SLI_MEM_LAT_NR, sli_mem_lat_histios);
    HISTO_BUCKET_RANGE_INIT(g_sli_probe.sli_bucket_rgs.sli_io_lat_buckets, SLI_IO_LAT_NR, sli_io_lat_histios);
    probe->host_cpu_cores = (int)sysconf(_SC_NPROCESSORS_CONF);
    if (probe->host_cpu_cores <= 0) {
        ERROR("[SLIPROBE]: sysconf to read the number of cpus error\n");
        return -1;
    }
    return 0;
}

static void sig_int(int signo)
{
    g_stop = 1;
}

static int __get_sli_cpu_histo_str(struct sli_probe_s *probe, struct sli_cpu_lat_s *cpu_lat, char histo_str[], size_t size)
{
    for (int i = 0; i < SLI_CPU_LAT_NR; i++) {
        probe->sli_cpu_lat_buckets.histo_buckets[i]->count = cpu_lat->cnt[i];
    }

    histo_str[0] = 0;
    if (serialize_histo(g_sli_probe.sli_bucket_rgs.sli_cpu_lat_buckets, &probe->sli_cpu_lat_buckets, SLI_CPU_LAT_NR, histo_str, size)) {
        return -1;
    }
    return 0;
}

static void __rcv_sli_cpu_node(struct sli_probe_s *probe, struct sli_cpu_obj_s *sli_cpu_obj)
{
    if (probe->is_report_histogram) {
        (void)__get_sli_cpu_histo_str(probe, &(sli_cpu_obj->sli.cpu_lats[SLI_CPU_WAIT]), probe->cpu_wait_histo_str, MAX_HISTO_SERIALIZE_SIZE);
        (void)__get_sli_cpu_histo_str(probe, &(sli_cpu_obj->sli.cpu_lats[SLI_CPU_SLEEP]), probe->cpu_sleep_histo_str, MAX_HISTO_SERIALIZE_SIZE);
        (void)__get_sli_cpu_histo_str(probe, &(sli_cpu_obj->sli.cpu_lats[SLI_CPU_IOWAIT]), probe->cpu_iowait_histo_str, MAX_HISTO_SERIALIZE_SIZE);
        (void)__get_sli_cpu_histo_str(probe, &(sli_cpu_obj->sli.cpu_lats[SLI_CPU_BLOCK]), probe->cpu_block_histo_str, MAX_HISTO_SERIALIZE_SIZE);
        (void)__get_sli_cpu_histo_str(probe, &(sli_cpu_obj->sli.cpu_lats[SLI_CPU_RUNDELAY]), probe->cpu_rundelay_histo_str, MAX_HISTO_SERIALIZE_SIZE);
        (void)__get_sli_cpu_histo_str(probe, &(sli_cpu_obj->sli.cpu_lats[SLI_CPU_LONGSYS]), probe->cpu_longsys_histo_str, MAX_HISTO_SERIALIZE_SIZE);
        (void)fprintf(stdout,
            "|%s|%s"
            "|%s|%s|%s|%s|%s|%s|\n",
            SLI_CPU_NODE_HISTOGRAM,
            SLI_TBL_NODE_KEY,
            probe->cpu_wait_histo_str,
            probe->cpu_sleep_histo_str,
            probe->cpu_iowait_histo_str,
            probe->cpu_block_histo_str,
            probe->cpu_rundelay_histo_str,
            probe->cpu_longsys_histo_str);
    }

    (void)fprintf(stdout,
        "|%s|%s"
        "|%llu|%llu|%llu|%llu|%llu|%llu|\n",
        SLI_CPU_NODE_GAUGE,
        SLI_TBL_NODE_KEY,
        sli_cpu_obj->sli.lat_ns[SLI_CPU_WAIT],
        sli_cpu_obj->sli.lat_ns[SLI_CPU_SLEEP],
        sli_cpu_obj->sli.lat_ns[SLI_CPU_IOWAIT],
        sli_cpu_obj->sli.lat_ns[SLI_CPU_BLOCK],
        sli_cpu_obj->sli.lat_ns[SLI_CPU_RUNDELAY],
        sli_cpu_obj->sli.lat_ns[SLI_CPU_LONGSYS]);

    (void)fflush(stdout);
    return;
}

static void __rcv_sli_cpu_container(struct sli_probe_s *probe, struct sli_container_s * sli_container, struct sli_cpu_obj_s *sli_cpu_obj)
{
    if (probe->is_report_histogram) {
        (void)__get_sli_cpu_histo_str(probe, &(sli_cpu_obj->sli.cpu_lats[SLI_CPU_WAIT]), probe->cpu_wait_histo_str, MAX_HISTO_SERIALIZE_SIZE);
        (void)__get_sli_cpu_histo_str(probe, &(sli_cpu_obj->sli.cpu_lats[SLI_CPU_SLEEP]), probe->cpu_sleep_histo_str, MAX_HISTO_SERIALIZE_SIZE);
        (void)__get_sli_cpu_histo_str(probe, &(sli_cpu_obj->sli.cpu_lats[SLI_CPU_IOWAIT]), probe->cpu_iowait_histo_str, MAX_HISTO_SERIALIZE_SIZE);
        (void)__get_sli_cpu_histo_str(probe, &(sli_cpu_obj->sli.cpu_lats[SLI_CPU_BLOCK]), probe->cpu_block_histo_str, MAX_HISTO_SERIALIZE_SIZE);
        (void)__get_sli_cpu_histo_str(probe, &(sli_cpu_obj->sli.cpu_lats[SLI_CPU_RUNDELAY]), probe->cpu_rundelay_histo_str, MAX_HISTO_SERIALIZE_SIZE);
        (void)__get_sli_cpu_histo_str(probe, &(sli_cpu_obj->sli.cpu_lats[SLI_CPU_LONGSYS]), probe->cpu_longsys_histo_str, MAX_HISTO_SERIALIZE_SIZE);
        (void)fprintf(stdout,
            "|%s|%s"
            "|%s|%s|%s|%s|%s|%s\n",
            SLI_CPU_CONTAINER_HISTOGRAM,
            sli_container->container_id,

            probe->cpu_wait_histo_str,
            probe->cpu_sleep_histo_str,
            probe->cpu_iowait_histo_str,
            probe->cpu_block_histo_str,
            probe->cpu_rundelay_histo_str,
            probe->cpu_longsys_histo_str);
    }

    (void)fprintf(stdout,
        "|%s|%s"
        "|%llu|%llu|%llu|%llu|%llu|%llu|\n",
        SLI_CPU_CONTAINER_GAUGE,
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

    if (probe->is_report_node && sli_container->ino == CPUACCT_GLOBAL_CGPID) {
        __rcv_sli_cpu_node(probe, sli_cpu_obj);
    } else if (probe->is_report_container){
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

static int __get_sli_mem_histo_str(struct sli_probe_s *probe, struct sli_mem_lat_s *mem_lat, char histo_str[], size_t size)
{
    for (int i = 0; i < SLI_MEM_LAT_NR; i++) {
        probe->sli_mem_lat_buckets.histo_buckets[i]->count = mem_lat->cnt[i];
    }

    histo_str[0] = 0;
    if (serialize_histo(g_sli_probe.sli_bucket_rgs.sli_mem_lat_buckets, &probe->sli_mem_lat_buckets, SLI_MEM_LAT_NR, histo_str, size)) {
        return -1;
    }
    return 0;
}

static void __rcv_sli_mem_node(struct sli_probe_s *probe, struct sli_mem_obj_s *sli_mem_obj)
{
    if (probe->is_report_histogram) {
        (void)__get_sli_mem_histo_str(probe, &(sli_mem_obj->sli.mem_lats[SLI_MEM_RECLAIM]), probe->mem_reclaim_histo_str, MAX_HISTO_SERIALIZE_SIZE);
        (void)__get_sli_mem_histo_str(probe, &(sli_mem_obj->sli.mem_lats[SLI_MEM_COMPACT]), probe->mem_compact_histo_str, MAX_HISTO_SERIALIZE_SIZE);
        (void)__get_sli_mem_histo_str(probe, &(sli_mem_obj->sli.mem_lats[SLI_MEM_SWAPIN]), probe->mem_swapin_histo_str, MAX_HISTO_SERIALIZE_SIZE);
        (void)fprintf(stdout,
            "|%s|%s"
            "|%s|%s|%s|\n",
            SLI_MEM_NODE_HISTOGRAM,
            SLI_TBL_NODE_KEY,
            probe->mem_reclaim_histo_str,
            probe->mem_compact_histo_str,
            probe->mem_swapin_histo_str);
    }

    (void)fprintf(stdout,
        "|%s|%s"
        "|%llu|%llu|%llu|\n",
        SLI_MEM_NODE_GAUGE,
        SLI_TBL_NODE_KEY,
        sli_mem_obj->sli.lat_ns[SLI_MEM_RECLAIM],
        sli_mem_obj->sli.lat_ns[SLI_MEM_COMPACT],
        sli_mem_obj->sli.lat_ns[SLI_MEM_SWAPIN]);

    (void)fflush(stdout);
    return;
}

static void __rcv_sli_mem_container(struct sli_probe_s *probe, struct sli_container_s * sli_container, struct sli_mem_obj_s *sli_mem_obj)
{
    if (probe->is_report_histogram) {
        (void)__get_sli_mem_histo_str(probe, &(sli_mem_obj->sli.mem_lats[SLI_MEM_RECLAIM]), probe->mem_reclaim_histo_str, MAX_HISTO_SERIALIZE_SIZE);
        (void)__get_sli_mem_histo_str(probe, &(sli_mem_obj->sli.mem_lats[SLI_MEM_COMPACT]), probe->mem_compact_histo_str, MAX_HISTO_SERIALIZE_SIZE);
        (void)__get_sli_mem_histo_str(probe, &(sli_mem_obj->sli.mem_lats[SLI_MEM_SWAPIN]), probe->mem_swapin_histo_str, MAX_HISTO_SERIALIZE_SIZE);
        (void)fprintf(stdout,
            "|%s|%s"
            "|%s|%s|%s|\n",
            SLI_MEM_CONTAINER_HISTOGRAM,
            sli_container->container_id,
            probe->mem_reclaim_histo_str,
            probe->mem_compact_histo_str,
            probe->mem_swapin_histo_str);
    }

    (void)fprintf(stdout,
        "|%s|%s"
        "|%llu|%llu|%llu|\n",
        SLI_MEM_CONTAINER_GAUGE,
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

    if (probe->is_report_node && sli_container->ino == CPUACCT_GLOBAL_CGPID) {
        __rcv_sli_mem_node(probe, sli_mem_obj);
    } else if (probe->is_report_container){
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

static int __get_sli_io_histo_str(struct sli_probe_s *probe, struct sli_io_lat_s *io_lat, char histo_str[], size_t size)
{
    for (int i = 0; i < SLI_IO_LAT_NR; i++) {
        probe->sli_io_lat_buckets.histo_buckets[i]->count = io_lat->cnt[i];
    }

    histo_str[0] = 0;
    if (serialize_histo(g_sli_probe.sli_bucket_rgs.sli_io_lat_buckets, &probe->sli_io_lat_buckets, SLI_IO_LAT_NR, histo_str, size)) {
        return -1;
    }
    return 0;
}

static void __rcv_sli_io_node(struct sli_probe_s *probe, struct sli_io_obj_s *sli_io_obj)
{
    if (probe->is_report_histogram) {
        (void)__get_sli_io_histo_str(probe, &(sli_io_obj->sli.io_lats), probe->bio_latency_histo_str, MAX_HISTO_SERIALIZE_SIZE);
        (void)fprintf(stdout,
            "|%s|%s"
            "|%s|\n",
            SLI_IO_NODE_HISTOGRAM,
            SLI_TBL_NODE_KEY,
            probe->bio_latency_histo_str);
    }

    (void)fprintf(stdout,
        "|%s|%s"
        "|%llu|\n",
        SLI_IO_NODE_GAUGE,
        SLI_TBL_NODE_KEY,
        sli_io_obj->sli.lat_ns);

    (void)fflush(stdout);
    return;
}

static void __rcv_sli_io_container(struct sli_probe_s *probe, struct sli_container_s *sli_container, struct sli_io_obj_s *sli_io_obj)
{
    if (probe->is_report_histogram) {
        (void)__get_sli_io_histo_str(probe, &(sli_io_obj->sli.io_lats), probe->bio_latency_histo_str, MAX_HISTO_SERIALIZE_SIZE);
        (void)fprintf(stdout,
            "|%s|%s"
            "|%s|\n",
            SLI_IO_CONTAINER_HISTOGRAM,
            sli_container->container_id,
            probe->bio_latency_histo_str);
    }

    (void)fprintf(stdout,
        "|%s|%s"
        "|%llu|\n",
        SLI_IO_CONTAINER_GAUGE,
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

    if (probe->is_report_node && sli_container->ino == CPUACCT_GLOBAL_CGPID) {
        __rcv_sli_io_node(probe, sli_io_obj);
    } else if (probe->is_report_container){
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

    sli_probe->sli_args_fd = GET_MAP_FD(cpu_sli, sli_args_map);
    sli_probe->sli_cpu_fd = GET_MAP_FD(cpu_sli, sli_cpu_map);

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

    sli_probe->sli_args_fd = GET_MAP_FD(mem_sli, sli_args_map);
    sli_probe->sli_mem_fd = GET_MAP_FD(mem_sli, sli_mem_map);

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

        sli_probe->sli_args_fd = GET_MAP_FD(io_sli, sli_args_map);
        sli_probe->sli_io_fd = GET_MAP_FD(io_sli, sli_io_map);
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

static int init_sliprobe_histo()
{
    int status = 0;
    if (init_bucket_with_content(&g_sli_probe.sli_cpu_lat_buckets, SLI_CPU_LAT_NR)) {
        ERROR("[SLIPROBE] init_sliprobe_histo sli_cpu_lat_buckets failed\n");
        status = -1;
    }
    if (init_bucket_with_content(&g_sli_probe.sli_mem_lat_buckets, SLI_MEM_LAT_NR)) {
        ERROR("[SLIPROBE] init_sliprobe_histo sli_mem_lat_buckets failed\n");
        status = -1;
    }
    if (init_bucket_with_content(&g_sli_probe.sli_io_lat_buckets, SLI_IO_LAT_NR)) {
        ERROR("[SLIPROBE] init_sliprobe_histo sli_mem_lat_buckets failed\n");
        status = -1;
    }
    return status;
}

void destroy_sliprobe_histo()
{
    free_histo_buckets(&g_sli_probe.sli_cpu_lat_buckets, SLI_CPU_LAT_NR);
    free_histo_buckets(&g_sli_probe.sli_mem_lat_buckets, SLI_MEM_LAT_NR);
    free_histo_buckets(&g_sli_probe.sli_io_lat_buckets, SLI_IO_LAT_NR);
}

static int sliprobe_load_bpf(struct sli_probe_s *sli_probe, struct ipc_body_s *ipc_body)
{
    int ret;
    u8 is_load = 0;

    sli_probe->is_load_cpu = ipc_body->probe_range_flags & PROBE_RANGE_SLI_CPU;
    sli_probe->is_load_mem = ipc_body->probe_range_flags & PROBE_RANGE_SLI_MEM;
    sli_probe->is_load_io = ipc_body->probe_range_flags & PROBE_RANGE_SLI_IO;
    sli_probe->is_report_node = ipc_body->probe_range_flags & PROBE_RANGE_SLI_NODE;
    sli_probe->is_report_container = ipc_body->probe_range_flags & PROBE_RANGE_SLI_CONTAINER;
    sli_probe->is_report_histogram = ipc_body->probe_range_flags & PROBE_RANGE_SLI_HISTOGRAM_METRICS;

    is_load = (sli_probe->is_load_cpu || sli_probe->is_load_mem || sli_probe->is_load_io) && 
        (sli_probe->is_report_node || sli_probe->is_report_container);
    if (!is_load) {
        return 0;
    }

    sli_probe->prog = alloc_bpf_prog();
    if (sli_probe->prog == NULL) {
        ERROR("[SLIPROBE] alloc bpf prog failed.\n");
        return -1;
    }

    if (sli_probe->is_load_cpu) {
        ret = load_sli_cpu_probe(sli_probe, sli_probe->prog);
        if (ret) {
            ERROR("[SLIPROBE] load cpu probe failed.\n");
            goto err;
        }
    }

    if (sli_probe->is_load_mem) {
        ret = load_sli_mem_probe(sli_probe, sli_probe->prog);
        if (ret) {
            ERROR("[SLIPROBE] load mem probe failed.\n");
            goto err;
        }
    }

    if (sli_probe->is_load_io) {
        ret = load_sli_io_probe(sli_probe, sli_probe->prog);
        if (ret) {
            ERROR("[SLIPROBE] load io probe failed.\n");
            goto err;
        }
    }

    ret = load_default_container(sli_probe);
    if (ret) {
        ERROR("[SLIPROBE] load default container failed.\n");
        goto err;
    }
    return 0;

err:
    sliprobe_unload_bpf(sli_probe);
    return ret;
}

static int __get_cpu_busy(struct sli_probe_s *probe, struct sli_container_s *container_cache, time_t secs)
{
    if (container_cache == NULL || container_cache->cpu_usage_path == NULL) {
        ERROR("[SLIPROBE] get cpu usage path failed.\n");
        return 0;
    }

    FILE *f = fopen(container_cache->cpu_usage_path, "r");
    if (f == NULL) {
        ERROR("[SLIPROBE] open file %s failed.\n", container_cache->cpu_usage_path);
        return 0;
    }

    char line[LINE_BUF_LEN];
    int cpu_busy = 0;
    line[0] = 0;
    if (fgets(line, sizeof(line), f) != NULL) {
        u64 cur_ns = strtoull(line, NULL, 10);
        // if last_cpu_usage_ns equals 0, it means this is the first collection
        // and we will not to report cpu_busy this time.
        if (container_cache->last_cpu_usage_ns != 0) {
            cpu_busy = (cur_ns - container_cache->last_cpu_usage_ns) * 100
                / NSEC_PER_SEC / secs / probe->host_cpu_cores; // 100 means 100%
            if (cpu_busy < 0) {
                ERROR("[SLIPROBE] cpu_busy < 0. cpu_usage_path is %s.\n", container_cache->cpu_usage_path);
            }
        }
        container_cache->last_cpu_usage_ns = cur_ns;
    } else {
        ERROR("[SLIPROBE] Error reading line from %s\n", container_cache->cpu_usage_path);
    }

    (void)fclose(f);

    return cpu_busy;
}

static time_t get_time_since_last_report(struct sli_probe_s *probe)
{
    time_t current = (time_t)time(NULL);
    time_t secs;

    if (probe->last_report == 0 || current <= probe->last_report) {
        probe->last_report = current;
        return 0;
    }

    secs = current - probe->last_report;
    if (secs >= probe->ipc_body.probe_param.period) {
        probe->last_report = current;
        return secs;
    }

    return 0;
}

static void report_cpu_stat(struct sli_probe_s *probe)
{
    int cpu_busy;
    time_t secs = get_time_since_last_report(probe);
    if (secs == 0) {
        return;
    }

    struct sli_container_s *cache, *tmp;
    H_ITER(probe->container_caches, cache, tmp) {
        cpu_busy = __get_cpu_busy(probe, cache, secs);
        if (cpu_busy < 0) {
            continue;
        }

        if (cache->ino == CPUACCT_GLOBAL_CGPID && probe->is_report_node) {
            (void)fprintf(stdout,
                "|%s|%s"
                "|%d|%d|\n",
                SLI_CPU_NODE_STAT,
                SLI_TBL_NODE_KEY,
                cpu_busy,
                cache->cpu_cores);
            (void)fflush(stdout);
        } else if (probe->is_report_container) {
            (void)fprintf(stdout,
                "|%s|%s"
                "|%d|%d|\n",
                SLI_CPU_CONTAINER_STAT,
                cache->container_id,
                cpu_busy,
                cache->cpu_cores);
            (void)fflush(stdout);
        }
    }
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
        ERROR("[SLIPROBE]: can't set signal handler: %s\n", strerror(errno));
        goto err;
    }

    if (probe_init(sli_probe)) {
        ERROR("[SLIPROBE]: probe init failed.\n");
        goto err;
    }

    INFO("[SLIPROBE]: Successfully started!\n");

    INIT_BPF_APP(sliprobe, EBPF_RLIM_LIMITED);
    if (init_sliprobe_histo()) {
        ERROR("[SLIPROBE]: init sliprobe histogram failed\n");
        goto err;
    }

    while (!g_stop) {
        ret = recv_ipc_msg(msq_id, (long)PROBE_SLI, &ipc_body);
        if (ret == 0) {
            if (sli_probe->ipc_body.probe_range_flags != ipc_body.probe_range_flags || ipc_body.probe_flags == 0) {
                unload_bpf_prog(&(sli_probe->prog));
                if (sliprobe_load_bpf(sli_probe, &ipc_body)) {
                    break;
                }
            }

            /* Probe range was changed to 0 */
            if (sli_probe->prog == NULL) {
                sleep(1);
                continue;
            }
        
            destroy_ipc_body(&(sli_probe->ipc_body));
            (void)memcpy(&(sli_probe->ipc_body), &ipc_body, sizeof(ipc_body));

            if (ipc_body.probe_flags & IPC_FLAGS_PARAMS_CHG || ipc_body.probe_flags == 0) {
                ret = load_sli_args(sli_probe->sli_args_fd, &ipc_body);
                if (ret) {
                    ERROR("[SLIPROBE] load sli args failed.\n");
                    goto err;
                }
            }

            if (ipc_body.probe_flags & IPC_FLAGS_SNOOPER_CHG || ipc_body.probe_flags == 0) {
                reload_sli_container_tbl(sli_probe);
            }
        }

        for (int i = 0; i < sli_probe->prog->num; i++) {
            if (sli_probe->prog->buffers[i]
                && ((ret = bpf_buffer__poll(sli_probe->prog->buffers[i], THOUSAND)) < 0)
                && ret != -EINTR) {
                ERROR("[SLIPROBE]: perf poll prog_%d failed.\n", i);
                break;
            }
        }
    
        if (sli_probe->is_load_cpu) {
            report_cpu_stat(sli_probe);
        }
    }

err:
    destroy_sliprobe_histo();
    deinit_sli_container_tbl(sli_probe);
    sliprobe_unload_bpf(sli_probe);
    destroy_ipc_body(&(sli_probe->ipc_body));

    return ret;
}

