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
static struct system_meminfo_field* meminfo_fields = NULL;

int system_meminfo_init(void)
{
    meminfo_fields = (struct system_meminfo_field*)malloc(TOTAL_DATA_INDEX * sizeof(struct system_meminfo_field));
    if (meminfo_fields == NULL) {
        return -1;
    }
    (void)memset(meminfo_fields, 0, TOTAL_DATA_INDEX * sizeof(struct system_meminfo_field));
    // assign key to indicators.
    char key_[TOTAL_DATA_INDEX][KEY_BUF_LEN] = {"MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached",
        "Active", "Inactive", "SwapTotal", "SwapFree"};
    for (int i = MEM_TOTAL; i < TOTAL_DATA_INDEX; i++) {
        strcpy(meminfo_fields[i].key, key_[i]);
        meminfo_fields[i].value = 0;
    }
    return 0;
}

// destry the memory spce for meminfos.
void system_meminfo_destroy(void)
{
    if (meminfo_fields != NULL) {
        (void)free(meminfo_fields);
        meminfo_fields = NULL;
    }
}

// get key & value from the line text, and assign to the target key.
static int set_meminfosp_fileds(const char* line, const int cur_index)
{
    int ret = 0;

    char* colon = strchr(line, ':');
    if (colon == NULL) {
        return -1;
    }

    *colon = '\0';

    if (strcmp(line, meminfo_fields[cur_index].key) == 0) {
        // atoll() turns digit chars to longlong ignoring the letter chars.  
        meminfo_fields[cur_index].value = atoll(colon + 1);
        return 0;
    }

    return -1;
}

static void report_meminfo_status(struct probe_params *params, double mem_util, double swap_util)
{
    char entityId[INT_LEN];
    char entityName[INT_LEN];
    if (params->logs == 0) {
        return;
    }

    entityId[0] = 0;
    entityName[0] = 0;
    (void)strcpy(entityId, "/proc/meminfo");
    (void)strcpy(entityName, "mem");
    // mem util
    if (mem_util > params->res_percent_upper) {
        report_logs(entityName,
                    entityId,
                    "util",
                    EVT_SEC_WARN,
                    "Too high mem utilization(%.2f%%).",
                    mem_util);
    }
    // swap util
    if (swap_util > params->res_percent_upper) {
        report_logs(entityName,
                    entityId,
                    "swap_util",
                    EVT_SEC_WARN,
                    "Too high swap utilization(%.2f%%).",
                    swap_util);
    }
}

static void output_info(struct probe_params *params)
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
        swap_usage = (double)(meminfo_fields[SWAP_TOTAL].value - meminfo_fields[SWAP_FREE].value);
        swap_usage /= meminfo_fields[SWAP_TOTAL].value * 100.0;
    }
    report_meminfo_status(params, mem_usage, swap_usage);
    // report data
    (void)nprobe_fprintf(stdout, "|%s|%s|%llu|%llu|%llu|%.2f|%llu|%llu|%llu|%llu|%llu|%llu|%.2f|\n",
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
        swap_usage);
}

// probes
int system_meminfo_probe(struct probe_params *params)
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
        ret = set_meminfosp_fileds(line, cur_index);
        if (!ret) {
            cur_index++;
        }

        // reading file ends when index = TOTAL_DATA_INDEX
        if (cur_index == TOTAL_DATA_INDEX) {
            break;
        }
    }
	
    (void)fclose(f);
    
    output_info(params);
    return 0;
}
