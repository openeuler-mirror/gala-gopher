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
 * Create: 2021-04-26
 * Description: provide gala-gopher test
 ******************************************************************************/
#include <stdint.h>
#include <CUnit/Basic.h>

#include "fifo.h"
#include "test_fifo.h"

#define FIFO_SIZE  8

static void TestFifoCreate(void)
{
    Fifo *fifo = FifoCreate(FIFO_SIZE);

    CU_ASSERT(fifo != NULL);
    CU_ASSERT(fifo->buffer != NULL);
    CU_ASSERT(fifo->in == 0);
    CU_ASSERT(fifo->out == 0);
    CU_ASSERT(fifo->size == FIFO_SIZE);
    FifoDestroy(fifo);

    fifo = FifoCreate(7); // fifo size must be the power of 2
    CU_ASSERT(fifo == NULL);
}


static void TestFifoPut(void)
{
    uint32_t ret = 0;
    uint32_t elem = 1;
    Fifo *fifo = FifoCreate(FIFO_SIZE);

    CU_ASSERT(fifo != NULL);
    for (int i = 0; i < FIFO_SIZE; i++) {
        ret = FifoPut(fifo, &elem);
        CU_ASSERT(ret == 0);
        CU_ASSERT(fifo->in == (i + 1));
    }

    ret = FifoPut(fifo, &elem);
    CU_ASSERT(ret == -1);
    CU_ASSERT(fifo->in == FIFO_SIZE);
    FifoDestroy(fifo);
}

static void TestFifoGet(void)
{
    uint32_t ret = 0;
    uint32_t elem = 1;
    uint32_t *elemP = NULL;
    Fifo *fifo = FifoCreate(FIFO_SIZE);

    CU_ASSERT(fifo != NULL);
    ret = FifoPut(fifo, &elem);
    CU_ASSERT(ret == 0);
    ret = FifoGet(fifo, (void **) &elemP);
    CU_ASSERT(ret == 0);
    CU_ASSERT(fifo->out == 1);
    FifoDestroy(fifo);
}


void TestFifoMain(CU_pSuite suite)
{
    CU_ADD_TEST(suite, TestFifoCreate);
    CU_ADD_TEST(suite, TestFifoPut);
    CU_ADD_TEST(suite, TestFifoGet);
}

