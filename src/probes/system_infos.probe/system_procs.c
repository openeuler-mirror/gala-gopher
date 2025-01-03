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
 * Author: dowzyx
 * Create: 2022-05-23
 * Description: system proc probe
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include "common.h"
#include "nprobe_fprintf.h"
#include "system_procs.h"

#define METRICS_PROC_NAME   "system_proc"
#define PROC_STAT           "/proc/%u/stat"
#define FULL_PER            100
#define PROC_FD             "/proc/%u/fd"
#define PROC_IO             "/proc/%u/io"
#define PROC_SMAPS          "/proc/%u/smaps_rollup"
#define PROC_ID_CMD         "ps -eo pid,ppid,pgid,comm | /usr/bin/awk '{if($1==\"%u\"){print $2 \"|\" $3}}'"
#define PROC_CPUSET         "/proc/%u/cpuset"
#define PROC_CPUSET_CMD     "/usr/bin/cat /proc/%u/cpuset 2>/dev/null | awk -F '/' '{print $NF}'"
#define PROC_LIMIT          "/proc/%u/limits"

static proc_hash_t *g_procmap = NULL;
static proc_info_t g_pre_proc_info;

static void hash_add_proc(proc_hash_t *one_proc)
{
    HASH_ADD(hh, g_procmap, key, sizeof(proc_key_t), one_proc);
    return;
}

static proc_hash_t *hash_find_proc(u32 pid, const char *stime)
{
    proc_hash_t *p = NULL;
    proc_hash_t temp = {0};

    temp.key.pid = pid;
    temp.key.start_time = strtoull(stime, NULL, 10);
    HASH_FIND(hh, g_procmap, &temp.key, sizeof(proc_key_t), p);

    return p;
}

static void hash_clear_all_proc(void)
{
    if (g_procmap == NULL) {
        return;
    }
    proc_hash_t *r, *tmp;
    HASH_ITER(hh, g_procmap, r, tmp) {
        HASH_DEL(g_procmap, r);
        if (r != NULL) {
            (void)free(r);
        }
    }
}

static inline int is_proc_subdir(const char *d_name)
{
    if (*d_name >= '1' && *d_name <= '9') {
        return 0;
    }
    return -1;
}

static void get_proc_id(u32 pid, proc_info_t *proc_info)
{
    FILE *f = NULL;
    char cmd[LINE_BUF_LEN];
    char line[LINE_BUF_LEN];

    if (strlen(proc_info->comm) == 0) {
        /* comm is NULL, return */
        return;
    }

    cmd[0] = 0;
    (void)snprintf(cmd, LINE_BUF_LEN, PROC_ID_CMD, pid);
    f = popen(cmd, "r");
    if (f == NULL) {
        goto out;
    }
    while (!feof(f)) {
        line[0] = 0;
        if (fgets(line, LINE_BUF_LEN, f) == NULL) {
            goto out;
        }
        SPLIT_NEWLINE_SYMBOL(line);

        (void)sscanf(line, "%d %*c %d", &proc_info->ppid, &proc_info->pgid);
    }

out:
    if (f != NULL) {
        pclose(f);
    }
    return;
}

static FILE *get_proc_file(u32 pid, const char *file_fmt)
{
    FILE *f = NULL;
    char fname[PATH_LEN];

    fname[0] = 0;
    (void)snprintf(fname, sizeof(fname), file_fmt, pid);
    f = fopen(fname, "r");
    return f;
}

static int get_proc_max_fdnum(u32 pid, proc_info_t *proc_info)
{
    FILE *f = NULL;
    char buffer[LINE_BUF_LEN];
    const char *prefix = "Max open files";
    size_t prefixLen = strlen(prefix);
    int ret;

    f = get_proc_file(pid, PROC_LIMIT);
    if (f == NULL) {
        return -1;
    }

    while (!feof(f)) {
        buffer[0] = 0;
        if (fgets(buffer, sizeof(buffer), f) == NULL) {
            (void)fclose(f);
            return -1;
        }
        if (strncmp(prefix, buffer, prefixLen) != 0) {
            continue;
        }
        ret = sscanf(buffer + prefixLen, "%u", &proc_info->max_fd_limit);
        if (ret <= 0) {
            (void)fclose(f);
            return -1;
        }
        break;
    }

    (void)fclose(f);
    return 0;
}

static int get_proc_fdcnt(u32 pid, proc_info_t *proc_info)
{
    char fname[PATH_LEN];
    DIR *dir;
    struct dirent *entry;
    u32 fd_count = 0;

    fname[0] = 0;
    (void)snprintf(fname, sizeof(fname), PROC_FD, pid);
    dir = opendir(fname);
    if (!dir) {
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        fd_count++;
    }

    closedir(dir);
    proc_info->fd_count = fd_count;
    return 0;
}

static void do_set_proc_stat(proc_info_t *proc_info, char *buf, int index)
{
    u64 value = strtoull(buf, NULL, 10);
    switch (index)
    {
        case PROC_STAT_MIN_FLT:
            proc_info->proc_stat_min_flt = value;
            break;
        case PROC_STAT_MAJ_FLT:
            proc_info->proc_stat_maj_flt = value;
            break;
        case PROC_STAT_UTIME:
            proc_info->proc_stat_utime = value;
            break;
        case PROC_STAT_STIME:
            proc_info->proc_stat_stime = value;
            break;
        case PROC_STAT_CUTIME:
            proc_info->proc_stat_cutime = value;
            break;
        case PROC_STAT_CSTIME:
            proc_info->proc_stat_cstime = value;
            break;
        case PROC_STAT_PRIORITY:
            proc_info->proc_stat_priority = value;
            break;
        case PROC_STAT_NICE:
            proc_info->proc_stat_nice = value;
            break;
        case PROC_STAT_NUM_THREADS:
            proc_info->proc_stat_num_threads = value;
            break;
        case PROC_STAT_STARTTIME:
            proc_info->proc_start_time = value;
            break;
        case PROC_STAT_VSIZE:
            proc_info->proc_stat_vsize = value;
            break;
        case PROC_STAT_RSS:
            proc_info->proc_stat_rss = value;
            break;
        case PROC_STAT_CPU:
            proc_info->proc_stat_cpu = value;
            break;
        case PROC_STAT_GUEST_TIME:
            proc_info->proc_stat_guest_time = value;
            break;
        default:
            break;
    }
}

static int get_proc_stat(u32 pid, proc_info_t *proc_info)
{
    FILE *f = NULL;
    char buffer[LINE_BUF_LEN];
    char *p = NULL;
    int index = 1;

    f = get_proc_file(pid, PROC_STAT);
    if (f == NULL) {
        return -1;
    }

    buffer[0] = 0;
    if (fgets(buffer, sizeof(buffer), f) == NULL) {
        (void)fclose(f);
        return -1;
    }
    SPLIT_NEWLINE_SYMBOL(buffer);

    p = strtok(buffer, " \t");
    while (p != NULL && index < PROC_STAT_MAX) {
        do_set_proc_stat(proc_info, p, index);
        p = strtok(NULL, " \t");
        index++;
    }
    if (index != PROC_STAT_MAX) {
        DEBUG("[SYSTEM_PROC] get proc stats incompletely, last position is:%d\n", index);
    }

    (void)fclose(f);
    return 0;
}

static void do_set_proc_io(proc_info_t *proc_info, u64 value, int index)
{
    switch (index)
    {
        case PROC_IO_RCHAR:
            proc_info->proc_rchar_bytes = value;
            break;
        case PROC_IO_WCHAR:
            proc_info->proc_wchar_bytes = value;
            break;
        case PROC_IO_SYSCR:
            proc_info->proc_syscr_count = value;
            break;
        case PROC_IO_SYSCW:
            proc_info->proc_syscw_count = value;
            break;
        case PROC_IO_READ_BYTES:
            proc_info->proc_read_bytes = value;
            break;
        case PROC_IO_WRITE_BYTES:
            proc_info->proc_write_bytes = value;
            break;
        case PROC_IO_CANCEL_WRITE_BYTES:
            proc_info->proc_cancelled_write_bytes = value;
            break;
        default:
            break;
    }
}

static int get_proc_io(u32 pid, proc_info_t *proc_info)
{
    FILE *f = NULL;
    int index = 0;
    u64 value = 0;
    char line[LINE_BUF_LEN];

    f = get_proc_file(pid, PROC_IO);
    if (f == NULL) {
        return -1;
    }

    while (!feof(f) && (index < PROC_IO_MAX)) {
        line[0] = 0;
        if (fgets(line, LINE_BUF_LEN, f) == NULL) {
            goto out;
        }
        value = 0;
        if (sscanf(line, "%*s %llu", &value) < 1) {
            goto out;
        }
        do_set_proc_io(proc_info, value, index);
        index++;
    }
out:
    (void)fclose(f);
    return 0;
}

static void do_set_proc_mss(proc_info_t *proc_info, u32 value, int index)
{
    switch (index)
    {
        case PROC_MSS_SHARED_CLEAN:
            proc_info->proc_shared_clean = value;
            break;
        case PROC_MSS_SHARED_DIRTY:
            proc_info->proc_shared_dirty = value;
            break;
        case PROC_MSS_PRIVATE_CLEAN:
            proc_info->proc_private_clean = value;
            break;
        case PROC_MSS_PROVATE_DIRTY:
            proc_info->proc_private_dirty = value;
            break;
        case PROC_MSS_REFERENCED:
            proc_info->proc_referenced = value;
            break;
        case PROC_MSS_LAZYFREE:
            proc_info->proc_lazyfree = value;
            break;
        case PROC_MSS_SWAP:
            proc_info->proc_swap = value;
            break;
        case PROC_MSS_SWAP_PSS:
            proc_info->proc_swappss = value;
            break;
        default:
            break;
    }
}

static int get_proc_mss(u32 pid, proc_info_t *proc_info)
{
    FILE *f = NULL;
    int index = 0;
    u32 value = 0;
    char line[LINE_BUF_LEN];
    char key[LINE_BUF_LEN];
    char format[SSCANF_FORMAT_LEN];
    char smap_key_list[PROC_MSS_MAX][LINE_BUF_LEN] = {"Shared_Clean:", "Shared_Dirty:", "Private_Clean:",
        "Private_Dirty:", "Referenced:", "LazyFree:", "Swap:", "SwapPss:"};
    int smap_index = 0;

    f = get_proc_file(pid, PROC_SMAPS);
    if (f == NULL) {
        return -1;
    }

    (void)snprintf(format, sizeof(format), "%%%lus %%u %%*s", sizeof(key) - 1);
    while (!feof(f)) {
        line[0] = 0;
        key[0] = 0;
        if (fgets(line, LINE_BUF_LEN, f) == NULL) {
            goto out;
        }
        if (index == 0) {   // filter out the first line
            index++;
            continue;
        }
        value = 0;
        int ret = sscanf(line, format, key, &value);
        if (ret < 2) {
            goto out;
        }
        if (strcmp(smap_key_list[smap_index], key) != 0) {
            continue;
        }
        do_set_proc_mss(proc_info, value, smap_index);
        smap_index++;
        if (smap_index >= PROC_MSS_MAX) {
            break;
        }
    }
out:
    (void)fclose(f);
    return 0;
}

static int update_proc_infos(u32 pid, proc_info_t *proc_info)
{
    int ret = 0;

    (void)memcpy(&g_pre_proc_info, proc_info, sizeof(proc_info_t));

    ret = get_proc_stat(pid, proc_info);
    if (ret < 0) {
        DEBUG("[SYSTEM_PROC] failed to get process stat\n");
        return -1;
    }

    ret = get_proc_fdcnt(pid, proc_info);
    if (ret < 0) {
        DEBUG("[SYSTEM_PROC] failed to get process fd info\n");
        return -1;
    }

    ret = get_proc_io(pid, proc_info);
    if (ret < 0) {
        DEBUG("[SYSTEM_PROC] failed to get process io info\n");
        return -1;
    }

    ret = get_proc_mss(pid, proc_info);
    if (ret < 0) {
        DEBUG("[SYSTEM_PROC] failed to get process mss info\n");
        return -1;
    }

    return 0;
}

static void output_proc_infos(proc_hash_t *one_proc, unsigned int period)
{
    u32 fd_free = one_proc->info.max_fd_limit - one_proc->info.fd_count;
    float fd_free_per = fd_free / (float)one_proc->info.max_fd_limit * 100;

    u64 sys_clock_ticks = (u64)sysconf(_SC_CLK_TCK);

    float proc_cpu_util = (float)((one_proc->info.proc_stat_utime + one_proc->info.proc_stat_stime) -
        (g_pre_proc_info.proc_stat_utime + g_pre_proc_info.proc_stat_stime)) / (period * sys_clock_ticks) * FULL_PER;

    float proc_cpu_user_util = 0.0;
    float cur_proc_user_ticks = (one_proc->info.proc_stat_utime - one_proc->info.proc_stat_guest_time);
    float prev_proc_user_ticks = (g_pre_proc_info.proc_stat_utime - g_pre_proc_info.proc_stat_guest_time);
    if (cur_proc_user_ticks > prev_proc_user_ticks) {
        proc_cpu_user_util = (float)(cur_proc_user_ticks - prev_proc_user_ticks) / (period * sys_clock_ticks) * FULL_PER;
    }

    float proc_cpu_system_util = (float)(one_proc->info.proc_stat_stime - g_pre_proc_info.proc_stat_stime) /
        (period * sys_clock_ticks) * FULL_PER;

    nprobe_fprintf(stdout,
        "|%s|%lu|%d|%d|%u|%.2f|%llu|%llu|%u|%u|%llu|%llu|%llu|%lu|%lu|%lu|%lu|%lu|%lu|%lu|%lu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%.2f|%llu|%.2f|%.2f|%.2f|\n",
        METRICS_PROC_NAME,
        one_proc->key.pid,
        one_proc->info.pgid,
        one_proc->info.ppid,
        one_proc->info.fd_count,
        fd_free_per,
        one_proc->info.proc_rchar_bytes - g_pre_proc_info.proc_rchar_bytes,
        one_proc->info.proc_wchar_bytes - g_pre_proc_info.proc_wchar_bytes,
        one_proc->info.proc_syscr_count - g_pre_proc_info.proc_syscr_count,
        one_proc->info.proc_syscw_count - g_pre_proc_info.proc_syscw_count,
        one_proc->info.proc_read_bytes - g_pre_proc_info.proc_read_bytes,
        one_proc->info.proc_write_bytes - g_pre_proc_info.proc_write_bytes,
        one_proc->info.proc_cancelled_write_bytes - g_pre_proc_info.proc_cancelled_write_bytes,
        one_proc->info.proc_shared_clean,
        one_proc->info.proc_shared_dirty,
        one_proc->info.proc_private_clean,
        one_proc->info.proc_private_dirty,
        one_proc->info.proc_referenced,
        one_proc->info.proc_lazyfree,
        one_proc->info.proc_swap,
        one_proc->info.proc_swappss,
        one_proc->info.proc_stat_min_flt - g_pre_proc_info.proc_stat_min_flt,
        one_proc->info.proc_stat_maj_flt - g_pre_proc_info.proc_stat_maj_flt,
        one_proc->info.proc_stat_utime - g_pre_proc_info.proc_stat_utime,
        one_proc->info.proc_stat_stime - g_pre_proc_info.proc_stat_stime,
        one_proc->info.proc_stat_cutime - g_pre_proc_info.proc_stat_cutime,
        one_proc->info.proc_stat_cstime - g_pre_proc_info.proc_stat_cstime,
        one_proc->info.proc_stat_priority,
        one_proc->info.proc_stat_nice,
        one_proc->info.proc_stat_num_threads,
        one_proc->info.proc_stat_vsize,
        one_proc->info.proc_stat_rss * (u64)sysconf(_SC_PAGESIZE),
        one_proc->info.proc_stat_rss * 1.0 * FULL_PER / (u64)sysconf(_SC_PHYS_PAGES),
        one_proc->info.proc_stat_cpu,
        proc_cpu_util,
        proc_cpu_user_util,
        proc_cpu_system_util);
    return;
}

static proc_hash_t* init_one_proc(u32 pid, char *stime, char *comm)
{
    proc_hash_t *item;

    item = (proc_hash_t *)malloc(sizeof(proc_hash_t));
    if (item == NULL) {
        return NULL;
    }
    (void)memset(item, 0, sizeof(proc_hash_t));

    item->key.pid = pid;
    item->key.start_time = strtoull(stime, NULL, 10);

    (void)snprintf(item->info.comm, sizeof(item->info.comm), "%s", comm);
    item->flag = PROC_IN_PROBE_RANGE;

    (void)get_proc_max_fdnum(pid, &item->info);

    get_proc_id(pid, &item->info);

    (void)update_proc_infos(pid, &item->info);

    return item;
}

int system_proc_probe(struct ipc_body_s *ipc_body)
{
    proc_hash_t *proc, *tmp;

    HASH_ITER(hh, g_procmap, proc, tmp) {
        if (!is_valid_proc(proc->key.pid)) {
            HASH_DEL(g_procmap, proc);
            free(proc);
            continue;
        }
        if (proc->flag == PROC_IN_PROBE_RANGE) {
            (void)update_proc_infos(proc->key.pid, &proc->info);
            if (proc->key.start_time != proc->info.proc_start_time) {
                HASH_DEL(g_procmap, proc);
                free(proc);
                continue;
            }

            output_proc_infos(proc, ipc_body->probe_param.period);
        }
    }

    return 0;
}

int refresh_proc_filter_map(struct ipc_body_s *ipc_body)
{
    u32 pid;
    char comm[PROC_NAME_MAX];
    char stime[PROC_NAME_MAX];
    proc_hash_t *item, *p;

    hash_clear_all_proc();

    for (int i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        if (ipc_body->snooper_objs[i].type != SNOOPER_OBJ_PROC) {
            continue;
        }
        comm[0] = 0;
        pid = ipc_body->snooper_objs[i].obj.proc.proc_id;
        (void)get_proc_comm(pid, comm, PROC_NAME_MAX);
        stime[0] = 0;
        (void)get_proc_start_time(pid, stime, PROC_NAME_MAX);

        p = hash_find_proc(pid, stime);
        if (p == NULL) {
            item = init_one_proc(pid, stime, comm);
            hash_add_proc(item);
        }
    }
    return 0;
}
