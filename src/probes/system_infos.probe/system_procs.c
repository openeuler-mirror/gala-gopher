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
#include <dirent.h>
#include <errno.h>
#include "object.h"
#include "nprobe_fprintf.h"
#include "whitelist_config.h"
#include "system_procs.h"

#define METRICS_PROC_NAME   "system_proc"
#define PROC_PATH           "/proc"
#define PROC_COMM           "/proc/%s/comm"
#define PROC_COMM_CMD       "/usr/bin/cat /proc/%s/comm"
#define PROC_STAT           "/proc/%s/stat"
#define PROC_START_TIME_CMD "/usr/bin/cat /proc/%s/stat | awk '{print $22}'"
#define PROC_CMDLINE_CMD    "/proc/%s/cmdline"
#define PROC_FD             "/proc/%s/fd"
#define PROC_FD_CNT_CMD     "/usr/bin/ls -l /proc/%s/fd 2>/dev/null | wc -l 2>/dev/null"
#define PROC_IO             "/proc/%s/io"
#define PROC_IO_CMD         "/usr/bin/cat /proc/%s/io"
#define PROC_SMAPS          "/proc/%s/smaps_rollup"
#define PROC_SMAPS_CMD      "/usr/bin/cat /proc/%s/smaps_rollup 2> /dev/null"
#define PROC_STAT_CMD       "/usr/bin/cat /proc/%s/stat | awk '{print $10\":\"$12\":\"$14\":\"$15\":\"$23\":\"$24}'"
#define PROC_ID_CMD         "ps -eo pid,ppid,pgid,comm | /usr/bin/awk '{if($1==\"%s\"){print $2 \"|\" $3}}'"
#define PROC_CPUSET         "/proc/%s/cpuset"
#define PROC_CPUSET_CMD     "/usr/bin/cat /proc/%s/cpuset | awk -F '/' '{print $NF}'"
#define PROC_LIMIT          "/proc/%s/limits"
#define PROC_LIMIT_CMD      "/usr/bin/cat /proc/%s/limits | grep \"open files\" | awk '{print $4}'"

static proc_hash_t *g_procmap = NULL;
static proc_info_t g_pre_proc_info;

static struct proc_match_s proc_range[PROC_MAX_RANGE] = {0};
static int g_proc_range_len = 0;

static void add_proc_obj(const int pid)
{
    struct proc_s obj;
    obj.proc_id = pid;

    (void)proc_add(&obj);
}

static void put_proc_obj(const int pid)
{
    struct proc_s obj;
    obj.proc_id = pid;

    (void)proc_put(&obj);
}

static void hash_add_proc(proc_hash_t *one_proc)
{
    HASH_ADD(hh, g_procmap, key, sizeof(proc_key_t), one_proc);
    add_proc_obj(one_proc->key.pid);
    return;
}

static proc_hash_t *hash_find_proc(const char *pid, const char *stime)
{
    proc_hash_t *p = NULL;
    proc_hash_t temp = {0};

    temp.key.pid = (u32)atoi(pid);
    temp.key.start_time = (u64)atoll(stime);
    HASH_FIND(hh, g_procmap, &temp.key, sizeof(proc_key_t), p);

    return p;
}

static char is_proc_exited(const int pid)
{
    FILE *f = NULL;
    char fname[LINE_BUF_LEN];

    fname[0] = 0;
    (void)snprintf(fname, LINE_BUF_LEN, "/proc/%d", pid);
    if (access((const char *)fname, 0) != 0) {
        return 1;
    }
    return 0;
}

static void hash_clear_invalid_proc(void)
{
    if (g_procmap == NULL) {
        return;
    }
    proc_hash_t *r, *tmp;
    HASH_ITER(hh, g_procmap, r, tmp) {
        if (!is_proc_exited(r->key.pid)) {
            continue;
        }
        put_proc_obj(r->key.pid);
        HASH_DEL(g_procmap, r);
        if (r != NULL) {
            if (r->info.cmdline != NULL) {
                (void)free(r->info.cmdline);
            }
            (void)free(r);
        }
    }
}

static inline int is_proc_subdir(const char *pid)
{
    if (*pid >= '1' && *pid <= '9') {
        return 0;
    }
    return -1;
}

static int do_read_line(const char* pid, const char *command, const char *fname, char *buf, u32 buf_len)
{
    FILE *f = NULL;
    char fname_or_cmd[LINE_BUF_LEN];
    char line[LINE_BUF_LEN];

    fname_or_cmd[0] = 0;
    (void)snprintf(fname_or_cmd, LINE_BUF_LEN, fname, pid);
    if (access((const char *)fname_or_cmd, 0) != 0) {
        return -1;
    }

    fname_or_cmd[0] = 0;
    line[0] = 0;
    (void)snprintf(fname_or_cmd, LINE_BUF_LEN, command, pid);
    f = popen(fname_or_cmd, "r");
    if (f == NULL) {
        ERROR("[SYSTEM_PROBE] proc cat fail, popen error.\n");
        return -1;
    }
    if (fgets(line, LINE_BUF_LEN, f) == NULL) {
        (void)pclose(f);
        ERROR("[SYSTEM_PROBE] proc get_info fail, line is null.\n");
        return -1;
    }
    
    SPLIT_NEWLINE_SYMBOL(line);
    (void)strncpy(buf, line, buf_len - 1);
    (void)pclose(f);
    return 0;
}

static int get_proc_comm(const char* pid, char *buf)
{
    return do_read_line(pid, PROC_COMM_CMD, PROC_COMM, buf, PROC_NAME_MAX);
}

static int get_proc_start_time(const char* pid, char *buf)
{
    return do_read_line(pid, PROC_START_TIME_CMD, PROC_STAT, buf, PROC_NAME_MAX);
}

static void get_proc_id(const char* pid, proc_info_t *proc_info)
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

#define JINFO_NOT_INSTALLED 0
#define JINFO_IS_INSTALLED  1

static int is_jinfo_installed()
{
    FILE *f = NULL;
    char cmd[LINE_BUF_LEN];
    char line[LINE_BUF_LEN];
    int is_installed = JINFO_NOT_INSTALLED;

    cmd[0] = 0;
    (void)snprintf(cmd, LINE_BUF_LEN, "which jinfo");
    f = popen(cmd, "r");
    if (f == NULL) {
        goto out;
    }
    if (fgets(line, LINE_BUF_LEN, f) == NULL) {
        goto out;
    }
    if (strstr(line, "no jinfo in") == NULL) {
        is_installed = JINFO_IS_INSTALLED;
    }
out:
    if (f != NULL) {
        (void)pclose(f);
    }
    return is_installed;
}

#define TASK_PROBE_JAVA_COMMAND "sun.java.command"
static void get_java_proc_cmd(const char* pid, proc_info_t *proc_info)
{
    FILE *f = NULL;
    char cmd[LINE_BUF_LEN];
    char line[LINE_BUF_LEN];
    if (is_jinfo_installed() == JINFO_NOT_INSTALLED) {
        ERROR("[SYSTEM_PROBE] jinfo not installed, please check.\n");
        return;
    }
    cmd[0] = 0;
    (void)snprintf(cmd, LINE_BUF_LEN, "jinfo %s | grep %s | awk '{print $3}'", pid, TASK_PROBE_JAVA_COMMAND);
    f = popen(cmd, "r");
    if (f == NULL) {
        goto out;
    }
    line[0] = 0;
    if (fgets(line, LINE_BUF_LEN, f) == NULL) {
        goto out;
    }
    SPLIT_NEWLINE_SYMBOL(line);
    proc_info->cmdline = (char *)malloc(LINE_BUF_LEN);
    (void)memset(proc_info->cmdline, 0, LINE_BUF_LEN);
    (void)strncpy(proc_info->cmdline, line, LINE_BUF_LEN - 1);
out:
    if (f != NULL) {
        (void)pclose(f);
    }
    return;
}

static char *get_proc_cmdline(const char *pid, int buf_len)
{
    FILE *f = NULL;
    char path[LINE_BUF_LEN];
    char *line = NULL;
    int index = 0;

    line = malloc(sizeof(char) * buf_len);
    if (line == NULL) {
        ERROR("[SYSTEM_PROC] get cmdline failed, malloc failed.\n");
        return NULL;
    }
    (void)memset(line, 0, sizeof(char) * buf_len);

    path[0] = 0;
    (void)snprintf(path, LINE_BUF_LEN, PROC_CMDLINE_CMD, pid);
    f = fopen(path, "r");
    if (f == NULL) {
        (void)free(line);
        return NULL;
    }
    /* parse line */
    while (!feof(f)) {
        if (index >= buf_len - 1) {
            line[index] = '\0';
            break;
        }
        line[index] = fgetc(f);
        if (line[index] == '\"') {
            if (index > buf_len - 2) {
                line[index] = '\0';
                break;
            } else {
                line[index] = '\\';
                line[index + 1] = '\"';
                index++;
            }
        } else if (line[index] == '\0') {
            line[index] = ' ';
        } else if (line[index] == EOF) {
            line[index] = '\0';
        }
        index++;
    }

    (void)fclose(f);
    return line;
}

static int get_proc_container_id(const char* pid, proc_info_t *proc_info)
{
    char buffer[LINE_BUF_LEN];
    buffer[0] = 0;
    int ret = do_read_line(pid, PROC_CPUSET_CMD, PROC_CPUSET, buffer, LINE_BUF_LEN);
    if (ret < 0) {
        return -1;
    }
    (void)memcpy(proc_info->container_id, buffer, CONTAINER_ABBR_ID_LEN);
    proc_info->container_id[CONTAINER_ABBR_ID_LEN] = 0;
    return 0;
}

static int get_proc_max_fdnum(const char* pid, proc_info_t *proc_info)
{
    char buffer[LINE_BUF_LEN];
    buffer[0] = 0;
    int ret = do_read_line(pid, PROC_LIMIT_CMD, PROC_LIMIT, buffer, LINE_BUF_LEN);
    if (ret < 0) {
        return -1;
    }
    proc_info->max_fd_limit = (u32)atoi(buffer);
    return 0;
}

static int get_proc_fdcnt(const char *pid, proc_info_t *proc_info)
{
    char buffer[LINE_BUF_LEN];
    buffer[0] = 0;
    int ret = do_read_line(pid, PROC_FD_CNT_CMD, PROC_FD, buffer, LINE_BUF_LEN);
    if (ret < 0) {
        return -1;
    }
    proc_info->fd_count = (u32)atoi(buffer);
    return 0;
}

static void do_set_proc_stat(proc_info_t *proc_info, char *buf, int index)
{
    u64 value = (u64)atoll(buf);
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
        case PROC_STAT_VSIZE:
            proc_info->proc_stat_vsize = value;
            break;
        case PROC_STAT_RSS:
            proc_info->proc_stat_rss = value;
            break;
        default:
            break;
    }
}

static int get_proc_stat(const char *pid, proc_info_t *proc_info)
{
    char buffer[LINE_BUF_LEN];
    char *p = NULL;
    int index = 0;
    buffer[0] = 0;
    int ret = do_read_line(pid, PROC_STAT_CMD, PROC_STAT, buffer, LINE_BUF_LEN);

    if (ret < 0) {
        return -1;
    }
    p = strtok(buffer, ":");
    while (p != NULL && index < PROC_STAT_MAX) {
        do_set_proc_stat(proc_info, p, index);
        p = strtok(NULL, ":");
        index++;
    }

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

static int get_proc_io(const char *pid, proc_info_t *proc_info)
{
    FILE *f = NULL;
    int index = 0;
    u64 value = 0;
    char fname_or_cmd[LINE_BUF_LEN];
    char line[LINE_BUF_LEN];

    fname_or_cmd[0] = 0;
    (void)snprintf(fname_or_cmd, LINE_BUF_LEN, PROC_IO, pid);
    if (access((const char *)fname_or_cmd, 0) != 0) {
        goto out;
    }
    fname_or_cmd[0] = 0;
    (void)snprintf(fname_or_cmd, LINE_BUF_LEN, PROC_IO_CMD, pid);
    f = popen(fname_or_cmd, "r");
    if (f == NULL) {
        goto out;
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
    if (f != NULL) {
        (void)pclose(f);
    }
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

static int get_proc_mss(const char *pid, proc_info_t *proc_info)
{
    FILE *f = NULL;
    int index = 0;
    u32 value = 0;
    char fname_or_cmd[LINE_BUF_LEN];
    char line[LINE_BUF_LEN];

    fname_or_cmd[0] = 0;
    (void)snprintf(fname_or_cmd, LINE_BUF_LEN, PROC_SMAPS, pid);
    if (access((const char *)fname_or_cmd, 0) != 0) {
        goto out;
    }
    fname_or_cmd[0] = 0;
    (void)snprintf(fname_or_cmd, LINE_BUF_LEN, PROC_SMAPS_CMD, pid);
    f = popen(fname_or_cmd, "r");
    if (f == NULL) {
        goto out;
    }
    while (!feof(f) && (index < PROC_MSS_MAX)) {
        line[0] = 0;
        if (fgets(line, LINE_BUF_LEN, f) == NULL) {
            goto out;
        }
        if (index == 0) {   // filter out the first line
            index++;
            continue;
        }
        value = 0;
        int ret = sscanf(line, "%*s %lu %*s", &value);
        if (ret < 1) {
            goto out;
        }
        do_set_proc_mss(proc_info, value, index);
        index++;
    }
out:
    if (f != NULL) {
        (void)pclose(f);
    }
    return 0;
}

static int update_proc_infos(const char *pid, proc_info_t *proc_info)
{
    int ret = 0;

    (void)memcpy(&g_pre_proc_info, proc_info, sizeof(proc_info_t));

    ret = get_proc_fdcnt(pid, proc_info);
    if (ret < 0) {
        return -1;
    }

    ret = get_proc_io(pid, proc_info);
    if (ret < 0) {
        return -1;
    }

    ret = get_proc_mss(pid, proc_info);
    if (ret < 0) {
        return -1;
    }

    ret = get_proc_stat(pid, proc_info);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

static int check_proc_probe_flag(const char *pid, const char *comm)
{
    int index;
    char *cmdline = NULL;

    for (index = 0; index < g_proc_range_len; index++) {
        // 如果comm匹配失败，继续下一轮检验
        if (strcmp(comm, proc_range[index].name) != 0) {
            continue;
        }
        // 如果comm匹配成功，且不需要匹配cmdline，返回1
        if(proc_range[index].cmd_line == NULL) {
            return 1;
        }
        // 如果comm匹配成功，而且需要匹配cmdline
        cmdline = get_proc_cmdline(pid, PROC_CMDLINE_MAX);
        if (cmdline == NULL) {
            // 获取cmdline失败，系统错误
            ERROR("[SYSTEM_PROC] check proc probe flag failed, get (%s)'s cmdline failed.\n", pid);
            break;
        }
        if (strstr(cmdline, proc_range[index].cmd_line) != NULL) {
            // 如果cmdline部分匹配成功，返回1
            (void)free(cmdline);
            return 1;
        } else {
            // 否则返回0
            (void)free(cmdline);
            continue;
        }
    }
    return 0;
}

static void output_proc_infos(proc_hash_t *one_proc)
{
    u32 fd_free = one_proc->info.max_fd_limit - one_proc->info.fd_count;
    float fd_free_per = fd_free / (float)one_proc->info.max_fd_limit * 100;

    nprobe_fprintf(stdout,
        "|%s|%lu|%d|%d|%s|%s|%s|%u|%.2f|%llu|%llu|%u|%u|%llu|%llu|%llu|%lu|%lu|%lu|%lu|%lu|%lu|%lu|%lu|%llu|%llu|%llu|%llu|%llu|%llu|\n",
        METRICS_PROC_NAME,
        one_proc->key.pid,
        one_proc->info.pgid,
        one_proc->info.ppid,
        one_proc->info.comm,
        one_proc->info.cmdline == NULL ? "" : one_proc->info.cmdline,
        one_proc->info.container_id,
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
        one_proc->info.proc_stat_vsize,
        one_proc->info.proc_stat_rss);
    return;
}

static proc_hash_t* init_one_proc(char *pid, char *stime, char *comm)
{
    proc_hash_t *item;

    item = (proc_hash_t *)malloc(sizeof(proc_hash_t));
    (void)memset(item, 0, sizeof(proc_hash_t));

    item->key.pid = (u32)atoi(pid);
    item->key.start_time = (u64)atoll(stime);

    (void)strncpy(item->info.comm, comm, PROC_NAME_MAX - 1);
    item->flag = PROC_IN_PROBE_RANGE;
    if (strcmp(comm, "java") == 0) {
        get_java_proc_cmd(pid, &item->info);
    } else {
        item->info.cmdline = get_proc_cmdline((const char *)pid, PROC_CMD_LINE_MAX);
    }
    (void)get_proc_container_id(pid, &item->info);

    (void)get_proc_max_fdnum(pid, &item->info);

    get_proc_id(pid, &item->info);

    (void)update_proc_infos(pid, &item->info);

    return item;
}

int system_proc_probe(void)
{
    DIR *dir = NULL;
    struct dirent *entry;
    char comm[PROC_NAME_MAX];
    char stime[PROC_NAME_MAX];
    proc_hash_t *l, *p = NULL;

    dir = opendir(PROC_PATH);
    if (dir == NULL) {
        return -1;
    }
    while (entry = readdir(dir)) {
        if (is_proc_subdir(entry->d_name) == -1) {
            continue;
        }
        /* proc start time(avoid repetition of pid) */
        stime[0] = 0;
        (void)get_proc_start_time(entry->d_name, stime);

        /* if the proc(pid+start_time) is finded in g_procmap, it means
           the proc was probed before and output proc_infos directly */
        p = hash_find_proc(entry->d_name, stime);
        if (p != NULL && p->flag == PROC_IN_PROBE_RANGE) {
            (void)update_proc_infos(entry->d_name, &p->info);
            output_proc_infos(p);
            continue;
        }

        comm[0] = 0;
        (void)get_proc_comm(entry->d_name, comm);

        /* check proc whether in proc_range */
        if (check_proc_probe_flag(entry->d_name, comm) != PROC_IN_PROBE_RANGE) {
            continue;
        }
        l = init_one_proc(entry->d_name, stime, comm);

        /* add new_proc to hashmap and output */
        hash_add_proc(l);
    }
    closedir(dir);
    hash_clear_invalid_proc();
    return 0;
}

void system_proc_destroy(void)
{
    obj_module_exit();
}

void system_proc_init(char *task_whitelist)
{
    int i;
    ApplicationsConfig *conf;

    obj_module_init();
    // if proc_obj_map's fd is 0, create obj_map
    if (!(obj_module_init_ok() & PROC_MAP_INIT_OK)) {
        DEBUG("[SYSTEM_PROC] proc_obj_map init pok, create map here.\n");
        (void)obj_module_create_map("proc_obj_map");
        obj_module_set_maps_fd();
    }

    if (parse_whitelist_config(&conf, task_whitelist) < 0) {
        ERROR("[SYSTEM_PROC] parse whitelist failed.\n");
        return;
    }

    for (i = 0; i < conf->apps_num; i++) {
        ApplicationConfig *_app = conf->apps[i];
        strncpy(proc_range[i].name, _app->comm, PROC_NAME_MAX - 1);
        strncpy(proc_range[i].cmd_line, _app->cmd_line, PROC_CMD_LINE_MAX - 1);
    }
    g_proc_range_len = i;

    whitelist_config_destroy(conf);

    return;
}
