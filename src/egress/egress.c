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
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>

#include "base.h"
#include "common.h"
#include "egress.h"

EgressMgr *EgressMgrCreate(void)
{
    EgressMgr *mgr;
    mgr = (EgressMgr *)malloc(sizeof(EgressMgr));
    if (mgr == NULL) {
        return NULL;
    }

    (void)memset(mgr, 0, sizeof(EgressMgr));

    mgr->metric_fifo = FifoCreate(MAX_FIFO_SIZE);
    if (mgr->metric_fifo == NULL) {
        (void)free(mgr);
        return NULL;
    }

    mgr->event_fifo = FifoCreate(MAX_FIFO_SIZE);
    if (mgr->event_fifo == NULL) {
        (void)free(mgr->metric_fifo);
        (void)free(mgr);
        return NULL;
    }

    return mgr;
}

void EgressMgrDestroy(EgressMgr *mgr)
{
    if (mgr == NULL) {
        return;
    }

    if (mgr->metric_fifo != NULL) {
        FifoDestroy(mgr->metric_fifo);
    }

    if (mgr->event_fifo != NULL) {
        FifoDestroy(mgr->event_fifo);
    }

    if (mgr->epoll_fd > 0) {
        close(mgr->epoll_fd);
    }

    (void)free(mgr);
    return;
}

static int EgressInit(EgressMgr *mgr)
{
    struct epoll_event m_event;
    struct epoll_event e_event;
    int ret = 0;

    mgr->epoll_fd = epoll_create(MAX_EPOLL_SIZE);
    if (mgr->epoll_fd < 0) {
        return -1;
    }

    m_event.events = EPOLLIN;
    m_event.data.ptr = mgr->metric_fifo;
    ret = epoll_ctl(mgr->epoll_fd, EPOLL_CTL_ADD, mgr->metric_fifo->triggerFd, &m_event);
    if (ret < 0) {
        ERROR("[EGRESS] add EPOLLIN m_event failed.\n");
        return -1;
    }
    INFO("[EGRESS] add EGRESS METRIC FIFO trigger succeeded.\n");

    e_event.events = EPOLLIN;
    e_event.data.ptr = mgr->event_fifo;
    ret = epoll_ctl(mgr->epoll_fd, EPOLL_CTL_ADD, mgr->event_fifo->triggerFd, &e_event);
    if (ret < 0) {
        ERROR("[EGRESS] add EPOLLIN e_event failed.\n");
        return -1;
    }
    INFO("[EGRESS] add EGRESS EVENT FIFO trigger succeeded.\n");

    return 0;
}

static int EgressDataProcesssInput(Fifo *fifo, const EgressMgr *mgr)
{
    // read data from fifo
    char *dataStr = NULL;
    int ret = 0;
#ifdef KAFKA_CHANNEL
    KafkaMgr *mkafkaMgr = mgr->metric_kafkaMgr;
    KafkaMgr *ekafkaMgr = mgr->event_kafkaMgr;
#endif
    uint64_t val = 0;
    ret = read(fifo->triggerFd, &val, sizeof(val));
    if (ret < 0) {
        ERROR("[EGRESS] Read event from triggerfd failed.\n");
        return -1;
    }

    while (FifoGet(fifo, (void **)&dataStr) == 0) {
        // Add Egress data handlement.
#ifdef KAFKA_CHANNEL
        if ((mkafkaMgr != NULL) && (fifo->triggerFd == mgr->metric_fifo->triggerFd)) {
            if (KafkaMsgProduce(mkafkaMgr, dataStr, strlen(dataStr)) != 0) {
                continue;
            }
        }
        if ((ekafkaMgr != NULL) && (fifo->triggerFd == mgr->event_fifo->triggerFd)) {
            KafkaMsgProduce(ekafkaMgr, dataStr, strlen(dataStr));
        }
#endif
    }

    return 0;
}

static int EgressDataProcess(const EgressMgr *mgr)
{
    struct epoll_event events[MAX_EPOLL_EVENTS_NUM];
    int events_num;
    Fifo *fifo = NULL;
    int ret = 0;

    events_num = epoll_wait(mgr->epoll_fd, events, MAX_EPOLL_EVENTS_NUM, -1);
    if ((events_num < 0) && (errno != EINTR)) {
        ERROR("Egress Msg wait failed: %s.\n", strerror(errno));
        return events_num;
    }

    for (int i = 0; ((i < events_num) && (i < MAX_EPOLL_EVENTS_NUM)); i++) {
        if (events[i].events != EPOLLIN) {
            continue;
        }

        fifo = (Fifo *)events[i].data.ptr;
        if (fifo == NULL) {
            continue;
        }

        ret = EgressDataProcesssInput(fifo, mgr);
        if (ret != 0) {
            return -1;
        }
    }
    return 0;
}

void EgressMain(EgressMgr *mgr)
{
    int ret = 0;
    ret = EgressInit(mgr);
    if (ret != 0) {
        ERROR("[EGRESS] egress init failed.\n");
        return;
    }
    DEBUG("[EGRESS] egress init succeeded.\n");

    for (;;) {
        ret = EgressDataProcess(mgr);
        if (ret != 0) {
            ERROR("[EGRESS] egress data process failed.\n");
            return;
        }
    }
}
