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
#ifndef __RESOURCE_H__
#define __RESOURCE_H__

#pragma once

#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "base.h"
#include "config.h"
#include "imdb.h"

#include "probe.h"
#include "extend_probe.h"
#include "probe_mng.h"
#include "meta.h"
#include "fifo.h"

#include "kafka.h"

#include "ingress.h"
#include "egress.h"

#include "web_server.h"
#include "rest_server.h"

#include "logs.h"

#include "event.h"

typedef struct {
    // config
    ConfigMgr *configMgr;

    // in-memory database
    IMDB_DataBaseMgr *imdbMgr;

    // inner component
    ProbeMgr *probeMgr;
    ExtendProbeMgr *extendProbeMgr;
    struct probe_mng_s *probe_mng;

    MeasurementMgr *mmMgr;
    FifoMgr *fifoMgr;

    // outer component
    KafkaMgr *metric_kafkaMgr;  // output metric's data

    KafkaMgr *meta_kafkaMgr;    // output metadata

    KafkaMgr *event_kafkaMgr;   // output abnormal event

    // thread handler
    IngressMgr *ingressMgr;
    EgressMgr *egressMgr;

    // web server
    WebServer *webServer;

    // rest api server
    RestServer *restServer;

    // logs
    LogsMgr *logsMgr;

    // ctl server
    pthread_t ctl_tid;

    // keep-live timer id
    timer_t keeplive_timer;
} ResourceMgr;

ResourceMgr *ResourceMgrCreate(void);
void ResourceMgrDestroy(ResourceMgr *resourceMgr);

int ResourceMgrInit(ResourceMgr *resourceMgr);
void ResourceMgrDeinit(ResourceMgr *resourceMgr);

#endif

