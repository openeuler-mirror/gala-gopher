
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
 * Create: 2023-04-20
 * Description: init thread blacklist of thread profiling probe
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "thrd_bl.h"

struct thrdBl {
    char procComm[TASK_COMM_LEN];
    int thrdNum;
    char (*thrdComms)[][TASK_COMM_LEN];
};

#define PROC_JAVA_COMM "java"
static char javaThrdBlComms[][TASK_COMM_LEN] = {
    "C1 CompilerThre",
    "C2 CompilerThre",
    "G1 Young RemSet",
    "VM Periodic Tas",
    "VM Thread"
};

static struct thrdBl thrdBlLocal[] = {
    {
        .procComm = PROC_JAVA_COMM,
        .thrdNum = sizeof(javaThrdBlComms) / sizeof(javaThrdBlComms[0]),
        .thrdComms = &javaThrdBlComms
    }
};

static void destroyThreadComms(char **thrdComms, int num)
{
    int i;

    if (thrdComms == NULL) {
        return;
    }
    
    for (i = 0; i < num; i++) {
        if (thrdComms[i] != NULL) {
            free(thrdComms[i]);
        }
    }
    free(thrdComms);
}

static char **createThreadComms(int num)
{
    char **thrdComms = NULL;
    int i;
    int ok = 1;

    thrdComms = (char **)calloc(num, sizeof(char *));
    if (thrdComms == NULL) {
        return NULL;
    }

    for (i = 0; i < num; i++) {
        thrdComms[i] = (char *)calloc(1, TASK_COMM_LEN);
        if (thrdComms[i] == NULL) {
            ok = 0;
            break;
        }
    }

    if (!ok) {
        destroyThreadComms(thrdComms, num);
        return NULL;
    }

    return thrdComms;
}

static void destroyBlacklistItems(BlacklistItem *blItems, int num)
{
    int i;

    if (blItems == NULL) {
        return;
    }
    
    for (i = 0; i < num; i++) {
        destroyThreadComms(blItems[i].thrdComms, blItems[i].thrdNum);
    }
    free(blItems);
}

static int initThreadBlacklistItem(struct thrdBl *thrdBlItem, BlacklistItem *blItem)
{
    int i;

    strncpy(blItem->procComm, thrdBlItem->procComm, TASK_COMM_LEN - 1);
    blItem->thrdNum = thrdBlItem->thrdNum;
    blItem->thrdComms = createThreadComms(blItem->thrdNum);
    if (blItem->thrdComms == NULL) {
        return -1;
    }
    for (i = 0; i < blItem->thrdNum; i++) {
        strncpy(blItem->thrdComms[i], (*thrdBlItem->thrdComms)[i], TASK_COMM_LEN - 1);
    }
    return 0;
}

int initThreadBlacklist(ThrdBlacklist *thrdBl)
{

    BlacklistItem *blItems;
    int blNum;
    int i;
    int ret;

    blNum = sizeof(thrdBlLocal) / sizeof(struct thrdBl);
    blItems = (BlacklistItem *)calloc(blNum, sizeof(BlacklistItem));
    if (blItems == NULL) {
        fprintf(stderr, "ERROR: create blacklist items failed: malloc memory failed\n");
        return -1;
    }

    for (i = 0; i < blNum; i++) {
        ret = initThreadBlacklistItem(&thrdBlLocal[i], &blItems[i]);
        if (ret) {
            destroyBlacklistItems(blItems, blNum);
            return -1;
        }
    }
    thrdBl->blItems = blItems;
    thrdBl->blNum = blNum;

    return 0;
}

void destroyThreadBlacklist(ThrdBlacklist *thrdBl)
{
    if (thrdBl->blItems != NULL) {
        destroyBlacklistItems(thrdBl->blItems, thrdBl->blNum);
        thrdBl->blNum = 0;
        thrdBl->blItems = NULL;
    }
}