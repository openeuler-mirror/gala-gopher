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
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "fifo.h"

#define IS_POWER_OF_TWO(n) ((n) != 0 && (((n) & ((n) - 1)) == 0))

static uint32_t FifoMin(uint32_t x1, uint32_t x2)
{
    return x1 < x2 ? x1 : x2;
}

Fifo *FifoCreate(uint32_t size)
{
    Fifo *fifo = NULL;

    if (!IS_POWER_OF_TWO(size)) {
        return NULL;
    }

    fifo = (Fifo *)malloc(sizeof(Fifo));
    if (fifo == NULL) {
        return NULL;
    }
    memset(fifo, 0, sizeof(Fifo));

    fifo->size = size;
    fifo->buffer = (void **)malloc(sizeof(void *) * size);
    if (fifo->buffer == NULL) {
        free(fifo);
        return NULL;
    }
    memset(fifo->buffer, 0, sizeof(void *) * size);

    fifo->triggerFd = eventfd(0, 0);
    if (fifo->triggerFd == -1) {
        free(fifo->buffer);
        free(fifo);
        return NULL;
    }

    return fifo;
}

void FifoDestroy(Fifo *fifo)
{
    if (fifo == NULL) {
        return;
    }

    if (fifo->buffer != NULL) {
        free(fifo->buffer);
    }

    if (fifo->triggerFd != 0) {
        (void)close(fifo->triggerFd);
        fifo->triggerFd = 0;
    }

    fifo->probe = NULL;

    free(fifo);
    return;
}

int FifoFull(const Fifo *fifo)
{
    return ((fifo->size - fifo->in + fifo->out) <= 1) ? 1 : 0;
}

uint32_t FifoPut(Fifo *fifo, void *element)
{
    uint32_t len = 1;
    uint32_t len2 = 0;

    len = FifoMin(len, fifo->size - fifo->in + fifo->out);

    __sync_synchronize();

    len2 = FifoMin(len, fifo->size - (fifo->in & (fifo->size - 1)));
    memcpy(fifo->buffer + (fifo->in & (fifo->size - 1)), &element, sizeof(void *) * len2);
    memcpy(fifo->buffer, &element, sizeof(void *) * (len - len2));

    __sync_synchronize();

    fifo->in += len;
    return len == 0 ? -1 : 0;
}

uint32_t FifoGet(Fifo *fifo, void **elements)
{
    uint32_t len = 1;
    uint32_t len2 = 0;

    len = FifoMin(len, fifo->in - fifo->out);

    __sync_synchronize();

    len2 = FifoMin(len, fifo->size - (fifo->out & (fifo->size - 1)));
    memcpy(elements, fifo->buffer + (fifo->out & (fifo->size - 1)), sizeof(void *) * len2);
    memcpy(elements, fifo->buffer, sizeof(void *) * (len - len2));

    __sync_synchronize();

    fifo->out += len;
    return len == 0 ? -1 : 0;
}

FifoMgr *FifoMgrCreate(uint32_t size)
{
    FifoMgr *mgr = NULL;
    mgr = (FifoMgr *)malloc(sizeof(FifoMgr));
    if (mgr == NULL) {
        return NULL;
    }
    memset(mgr, 0, sizeof(FifoMgr));

    mgr->fifos = (Fifo **)malloc(sizeof(Fifo *) * size);
    if (mgr->fifos == NULL) {
        free(mgr);
        return NULL;
    }
    memset(mgr->fifos, 0, sizeof(Fifo *) * size);
    mgr->size = size;
    return mgr;
}

void FifoMgrDestroy(FifoMgr *mgr)
{
    if (mgr == NULL) {
        return;
    }

    if (mgr->fifos != NULL) {
        free(mgr->fifos);
    }

    free(mgr);
    return;
}

int FifoMgrAdd(FifoMgr *mgr, Fifo *fifo)
{
    if (mgr->fifoNum == mgr->size) {
        return -1;
    }

    mgr->fifos[mgr->fifoNum] = fifo;
    mgr->fifoNum++;
    return 0;
}

