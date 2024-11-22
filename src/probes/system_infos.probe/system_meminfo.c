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
 * Author: Siki
 * Create: 2022-09-05
 * Description: system probe just in 1 thread, include tcp/net/iostat/inode
 ******************************************************************************/
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "common.h"
#include "event.h"
#include "nprobe_fprintf.h"
#include "system_meminfo.h"

#define METRICS_MEMINFO_NAME "system_meminfo"
#define METRICS_MEMINFO_PATH "/proc/meminfo"
#define METRTCS_DENTRY_NAME  "system_dentry"
#define METRICS_DENTRY_ORIGIN  "fs.dentry-state"
#define SYSTEM_FS_DENTRY_STATE "cat /proc/sys/fs/dentry-state"
/* VmallocUsed in /proc/meminfo is inaccurate because it include VM_MALLOC VM_IOREMAP VM_MAP */
#define METRICS_VMLLLOC_PATH  "/proc/vmallocinfo"
#define METRICS_VMALLOC_SIZE  "grep vmalloc /proc/vmallocinfo | awk '{total+=$2}; END {print total}'"
static struct system_meminfo_field* meminfo_fields = NULL;
static struct dentry_stat dentry_state = {0};

int system_meminfo_init(void)
{
    meminfo_fields = (struct system_meminfo_field*)malloc(TOTAL_DATA_INDEX * sizeof(struct system_meminfo_field));
    if (meminfo_fields == NULL) {
        return -1;
    }
    (void)memset(meminfo_fields, 0, TOTAL_DATA_INDEX * sizeof(struct system_meminfo_field));
    // assign key to indicators.
    char key_[TOTAL_DATA_INDEX][KEY_BUF_LEN] = {"MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached",
        "Active", "Inactive", "Active(anon)", "Inactive(anon)", "Active(file)", "Inactive(file)", "Mlocked",
        "SwapTotal", "SwapFree", "Shmem", "Slab", "SReclaimable", "SUnreclaim", "KernelStack", "PageTables",
        "VmallocUsed", "HugePages_Total", "Hugepagesize"};
    for (int i = MEM_TOTAL; i < TOTAL_DATA_INDEX; i++) {
        snprintf(meminfo_fields[i].key, sizeof(meminfo_fields[i].key), "%s", key_[i]);
        meminfo_fields[i].value = 0;
    }
    return 0;
}

// destroy the memory space for meminfos.
void system_meminfo_destroy(void)
{
    if (meminfo_fields != NULL) {
        (void)free(meminfo_fields);
        meminfo_fields = NULL;
    }
}

// get key & value from the line text, and assign to the target key.
static int set_meminfosp_fields(const char* line, const int cur_index)
{
    char* colon = strchr(line, ':');
    if (colon == NULL) {
        return -1;
    }

    *colon = '\0';

    if (strcmp(line, meminfo_fields[cur_index].key) == 0) {
        // strtoull() turns digit chars to longlong ignoring the letter chars.
        meminfo_fields[cur_index].value = strtoull(colon + 1, NULL, 10);
        return 0;
    }

    return -1;
}

static int update_total_vmalloc(unsigned long long *value)
{
    char cmd[LINE_BUF_LEN];
    char line[LINE_BUF_LEN];
    cmd[0] = 0;
    line[0] = 0;

    if (access(METRICS_VMLLLOC_PATH, R_OK) != 0) {
        return 0;
    }

    (void)snprintf(cmd, LINE_BUF_LEN, METRICS_VMALLOC_SIZE);
    if (exec_cmd(cmd, line, LINE_BUF_LEN) != 0) {
        ERROR("[SYSTEM_PROBE] get vmallocinfo failed.\n");
        return -1;
    }

    unsigned long long total_b = strtoull(line, NULL, 10);

    *value = total_b / 1024;    // KB
    return 0;
}

static void report_meminfo_status(struct ipc_body_s *ipc_body, double mem_util, double swap_util)
{
#ifdef ENABLE_REPORT_EVENT
    char entityId[INT_LEN];
    char entityName[INT_LEN];
    struct event_info_s evt = {0};
    if (ipc_body->probe_param.logs == 0) {
        return;
    }

    entityId[0] = 0;
    entityName[0] = 0;
    (void)snprintf(entityId, sizeof(entityId), "%s", "/proc/meminfo");
    (void)snprintf(entityName, sizeof(entityName), "%s", "mem");

    evt.entityName = entityName;
    evt.entityId = entityId;
    // mem util
    if (ipc_body->probe_param.res_percent_upper > 0 && mem_util > ipc_body->probe_param.res_percent_upper) {
        evt.metrics = "util";
        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "Too high mem utilization(%.2f%%).",
                    mem_util);
    }
    // swap util
    if (ipc_body->probe_param.res_percent_upper > 0 && swap_util > ipc_body->probe_param.res_percent_upper) {
        evt.metrics = "swap_util";
        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "Too high swap utilization(%.2f%%).",
                    swap_util);
    }
#endif
    return;
}

static void output_meminfo(struct ipc_body_s *ipc_body)
{
    //  v3.2.8 used = total - free; v3.3.10 used = total - free - cache - buffers; cur_ver=v5.10
    // alculate memusage
    double mem_usage = 0;
    if (meminfo_fields[MEM_TOTAL].value > 0) {
        mem_usage = (double)(meminfo_fields[MEM_TOTAL].value - meminfo_fields[MEM_FREE].value - \
                    meminfo_fields[BUFFERS].value - meminfo_fields[CACHED].value) / meminfo_fields[MEM_TOTAL].value * 100.0;
    }
    // calculate swapusage
    double swap_usage = 0;
    if (meminfo_fields[SWAP_TOTAL].value > 0) {
        swap_usage = (double)((meminfo_fields[SWAP_TOTAL].value - \
				meminfo_fields[SWAP_FREE].value)) / meminfo_fields[SWAP_TOTAL].value * 100.0;
    }
    report_meminfo_status(ipc_body, mem_usage, swap_usage);
    // report data
    (void)nprobe_fprintf(stdout, "|%s|%s|%llu|%llu|%llu|%.2f|%llu|%llu|%llu|%llu|%llu|%llu|%.2f|\
        %llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|\n",
        METRICS_MEMINFO_NAME,
        METRICS_MEMINFO_PATH,
        meminfo_fields[MEM_TOTAL].value,
        meminfo_fields[MEM_FREE].value,
        meminfo_fields[MEM_AVAILABLE].value,
        mem_usage,
        meminfo_fields[BUFFERS].value,
        meminfo_fields[CACHED].value,
        meminfo_fields[ACTIVE].value,
        meminfo_fields[INACTIVE].value,
        meminfo_fields[SWAP_TOTAL].value,
        meminfo_fields[SWAP_FREE].value,
        swap_usage,
        meminfo_fields[SLAB].value,
        meminfo_fields[S_RECLAIMABLE].value,
        meminfo_fields[S_UNRECLAIM].value,
        meminfo_fields[PAGE_TABLES].value,
        meminfo_fields[VMALLOC_USED].value,
        meminfo_fields[KERNEL_STACK].value,
        meminfo_fields[ACTIVE_ANON].value,
        meminfo_fields[INACTIVE_ANON].value,
        meminfo_fields[ACTIVE_FILE].value,
        meminfo_fields[INACTIVE_FILE].value,
        meminfo_fields[MLOCKED].value,
        meminfo_fields[HUGEPAGES_TOTAL].value * meminfo_fields[HUGEPAGE_SIZE].value,
        meminfo_fields[SHMEM].value);
}

// /proc/meminfo
static int get_meminfo(struct ipc_body_s *ipc_body)
{
    FILE* f = NULL;
    char line[LINE_BUF_LEN];
    int ret = 0;

    f = fopen(METRICS_MEMINFO_PATH, "r");
    if (f == NULL) {
        return -1;
    }
    int cur_index = 0;
    while (!feof(f)) {
        line[0] = 0;
        if (fgets(line, LINE_BUF_LEN, f) == NULL) {
            break;
        }
        ret = set_meminfosp_fields(line, cur_index);
        if (!ret) {
            cur_index++;
        }

        // reading file ends when index = TOTAL_DATA_INDEX
        if (cur_index == TOTAL_DATA_INDEX) {
            break;
        }
    }
    ret = update_total_vmalloc(&meminfo_fields[VMALLOC_USED].value);
    if (ret < 0) {
        (void)fclose(f);
        return -1;
    }
    output_meminfo(ipc_body);

    (void)fclose(f);
    return 0;
}

// fs.dentry-state
#define DENTRY_STATE_VALID_FIELD_NUM    3
static int get_dentry_state(void)
{
    FILE *f = NULL;
    char line[LINE_BUF_LEN];

    f = popen(SYSTEM_FS_DENTRY_STATE, "r");
    if (f == NULL) {
        return -1;
    }
    line[0] = 0;
    if (fgets(line, LINE_BUF_LEN, f) == NULL) {
        pclose(f);
        return -1;
    }
    SPLIT_NEWLINE_SYMBOL(line);
    int ret = sscanf(line, "%d %d %d %*d %*d %*d",
        &dentry_state.dentry, &dentry_state.unused, &dentry_state.age_limit);
    if (ret < DENTRY_STATE_VALID_FIELD_NUM) {
        DEBUG("[SYSTEM_PROBE] get dentry_state fields fail.\n");
        pclose(f);
        return -1;
    }
    // report data
    (void)nprobe_fprintf(stdout, "|%s|%s|%d|%d|%d|\n",
        METRTCS_DENTRY_NAME,
        METRICS_DENTRY_ORIGIN,
        dentry_state.dentry,
        dentry_state.unused,
        dentry_state.age_limit);

    pclose(f);
    return 0;
}

// probes
int system_meminfo_probe(struct ipc_body_s *ipc_body)
{
    if (get_meminfo(ipc_body) < 0) {
        ERROR("[SYSTEM_PROBE] failed to collect proc meminfo.\n");
        return -1;
    }
    if (get_dentry_state() < 0) {
        ERROR("[SYSTEM_PROBE] failed to collect fs dentry_state.\n");
        return -1;
    }
    return 0;
}
