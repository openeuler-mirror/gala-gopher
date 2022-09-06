/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
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
#ifndef __INGRESS_H__
#define __INGRESS_H__

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include "base.h"
#include "fifo.h"
#include "meta.h"
#include "probe.h"
#include "extend_probe.h"
#include "imdb.h"
#include "egress.h"

typedef struct {
    FifoMgr *fifoMgr;
    MeasurementMgr *mmMgr;
    ProbeMgr *probeMgr;
    ExtendProbeMgr *extendProbeMgr;

    IMDB_DataBaseMgr *imdbMgr;

    // data export
    EgressMgr *egressMgr;
    OutChannelType event_out_channel;

    int epoll_fd;
    pthread_t tid;
} IngressMgr;

IngressMgr *IngressMgrCreate(void);
void IngressMgrDestroy(IngressMgr *mgr);

void IngressMain(IngressMgr *mgr);

#endif
