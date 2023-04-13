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
 * Author: li-zhenxing
 * Create: 2023-04-11
 * Description: 
 ******************************************************************************/

#include <stdio.h>
#include "common.h"
#include "imdb.h"
#include "hash.h"

#define CONTAINER_POD_INFO_CMD "docker ps -q | xargs docker inspect --format "\
        " '{{.State.Pid}}%s{{.Id}}%s{{.Name}}%s{{.Config.Hostname}}' | /usr/bin/grep -w %s"

#define DELIM        ","

#define TOEKN0       0
#define TOEKN1       1
#define TOEKN2       2
#define TOEKN3       3


static int add_to_cache_with_LRU(TgidProcInfo_Table **tgid_infos, char *tgid, ProcInfo *info)
{
    TgidProcInfo_Table *entry;
    entry = malloc(sizeof(TgidProcInfo_Table));
    if (entry == NULL) {
        return -1;
    }

    memset(entry, 0, sizeof(TgidProcInfo_Table));
    memcpy(entry->tgid, tgid, strlen(tgid));
    memcpy(&entry->info, info, sizeof(ProcInfo));

    // delete all caches when exceeds the quota
    if (HASH_COUNT(*tgid_infos) > MAX_CACHE_SIZE) {
        TgidProcInfo_Table *current_entry, *tmp_entry;
        H_ITER(*tgid_infos, current_entry, tmp_entry) {
            H_DEL(*tgid_infos, current_entry);
            free(current_entry);
        }
    }

    H_ADD_S(*tgid_infos, tgid, entry);

    return 0;
}

static int find_in_cache_with_LRU(TgidProcInfo_Table **tgid_infos, char *tgid, ProcInfo *info)
{
    TgidProcInfo_Table *entry;

    H_FIND_S(*tgid_infos, tgid, entry);
    if (entry) {
        memcpy(info, &entry->info, sizeof(ProcInfo));
        return 0;
    }

    return -1;
}

static int get_proc_info_by_tgid(char *tgid, ProcInfo *info)
{
    char command[COMMAND_LEN] = {0};
    char line[LINE_BUF_LEN] = {0};
    char *token = NULL;

    (void)snprintf(command, COMMAND_LEN, CONTAINER_POD_INFO_CMD, DELIM, DELIM, DELIM, tgid);

    int ret = exec_cmd((const char *)command, line, LINE_BUF_LEN);
    if (ret < 0 || strlen(line) <= 0) {
        return 0;
    }

    int i = 0;
    token = strtok(line, DELIM);
    for (; i < 4 && token != NULL; i++) {
        switch (i) {
            case TOEKN0:
                break;
            case TOEKN1:
                (void)memcpy(info->container_id, token, CONTAINER_ID_LEN - 1);
                break;
            case TOEKN2:
                (void)memcpy(info->container_name, token, CONTAINER_NAME_LEN - 1);
                break;
            case TOEKN3:
                (void)memcpy(info->pod_name, token, POD_NAME_LEN - 1);
                break;

            default:
                return -1;
        }
        token = strtok(NULL, DELIM);
    }

    if (i != 4) {
        return -1;
    }

    return 0;
}

ProcInfo * look_up_proc_info_by_tgid(TgidProcInfo_Table **tgid_infos, char *tgid)
{
    ProcInfo *info = (ProcInfo *)malloc(sizeof(ProcInfo));
    if (info == NULL) {
        return NULL;
    }

    memset(info, 0, sizeof(ProcInfo));

    if (find_in_cache_with_LRU(tgid_infos, tgid, info) >= 0) {
        return info;
    } else {
        if (get_proc_info_by_tgid(tgid, info) >= 0) {
            if (add_to_cache_with_LRU(tgid_infos, tgid, info) >= 0) {
                return info;
            }
        }
    }

    return NULL;
}
