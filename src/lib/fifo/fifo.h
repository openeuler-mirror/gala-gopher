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
#ifndef __FIFO_H__
#define __FIFO_H__

#include <stdint.h>

typedef struct {
    void **buffer;
    uint32_t size;
    uint32_t in;
    uint32_t out;

    int triggerFd;
} Fifo;

typedef struct {
    uint32_t size;
    uint32_t fifoNum;
    Fifo **fifos;
} FifoMgr;

Fifo *FifoCreate(uint32_t size);
void FifoDestroy(Fifo *fifo);

uint32_t FifoPut(Fifo *fifo, void *element);
uint32_t FifoGet(Fifo *fifo, void **elements);

FifoMgr *FifoMgrCreate(uint32_t size);
void FifoMgrDestroy(FifoMgr *mgr);
int FifoMgrAdd(FifoMgr *mgr, Fifo *fifo);

#endif

