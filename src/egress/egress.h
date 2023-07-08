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
 * Author: Hubble_Zhu 
 * Create: 2021-04-12
 * Description:
 ******************************************************************************/
#ifndef __EGRESS__
#define __EGRESS__

#include <stdint.h>
#include <pthread.h>

#include "fifo.h"
#include "kafka.h"

typedef struct {
    KafkaMgr *metric_kafkaMgr;
    KafkaMgr *event_kafkaMgr;

    uint32_t interval;
    uint32_t timeRange;

    Fifo *metric_fifo;
    Fifo *event_fifo;
    int epoll_fd;
    pthread_t tid;
} EgressMgr;

EgressMgr *EgressMgrCreate(void);
void EgressMgrDestroy(EgressMgr *mgr);

void EgressMain(EgressMgr *mgr);

#endif
