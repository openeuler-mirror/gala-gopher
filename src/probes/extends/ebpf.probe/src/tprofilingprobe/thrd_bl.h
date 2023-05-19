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
 * Description: the thread blacklist header file of thread profiling probe
 ******************************************************************************/
#ifndef __THRD_BL_H__
#define __THRD_BL_H__

#include "common.h"

typedef struct {
    char procComm[TASK_COMM_LEN];
    int thrdNum;
    char **thrdComms;
} BlacklistItem;

typedef struct {
    int blNum;
    BlacklistItem *blItems;
} ThrdBlacklist;

int initThreadBlacklist(ThrdBlacklist *thrdBl);
void destroyThreadBlacklist(ThrdBlacklist *thrdBl);

#endif