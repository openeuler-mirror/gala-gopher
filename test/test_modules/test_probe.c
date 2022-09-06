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

#include "probe.h"
#include "test_probe.h"

#define PROBE_MGR_SIZE 1024

static void TestProbeMgrCreate(void)
{
    ProbeMgr *mgr = ProbeMgrCreate(PROBE_MGR_SIZE);

    CU_ASSERT(mgr != NULL);
    CU_ASSERT(mgr->probes != NULL);
    CU_ASSERT(mgr->probesNum == 0);
    CU_ASSERT(mgr->size == PROBE_MGR_SIZE);
    ProbeMgrDestroy(mgr);
}

static void TestProbeMgrPut(void)
{
    uint32_t ret = 0;
    ProbeMgr *mgr = ProbeMgrCreate(PROBE_MGR_SIZE);
    Probe *probe = ProbeCreate();

    CU_ASSERT(mgr != NULL);
    CU_ASSERT(probe != NULL);

    (void)snprintf(probe->name, MAX_PROBE_NAME_LEN - 1, "test_probe");

    ret = ProbeMgrPut(mgr, probe);
    CU_ASSERT(ret == 0);
    CU_ASSERT(mgr->probesNum == 1);
    CU_ASSERT(mgr->probes[0] == probe);
    CU_ASSERT(strcmp(mgr->probes[0]->name, "test_probe") == 0);
    ProbeMgrDestroy(mgr);
}

static void TestProbeMgrGet(void)
{
    uint32_t ret = 0;
    ProbeMgr *mgr = ProbeMgrCreate(PROBE_MGR_SIZE);
    Probe *probe = ProbeCreate();
    Probe *probe1 = NULL;

    CU_ASSERT(mgr != NULL);
    CU_ASSERT(probe != NULL);

    (void)snprintf(probe->name, MAX_PROBE_NAME_LEN - 1, "test_probe");

    ret = ProbeMgrPut(mgr, probe);
    CU_ASSERT(ret == 0);

    probe1 = ProbeMgrGet(mgr, "test_probe");
    CU_ASSERT(probe1 != NULL);
    CU_ASSERT(probe1->fifo != NULL);
    ProbeMgrDestroy(mgr);
}

static void TestProbeCreate(void)
{
    Probe *probe = ProbeCreate();

    CU_ASSERT(probe != NULL);
    CU_ASSERT(probe->fifo != NULL);
    ProbeDestroy(probe);
}

void TestProbeMain(CU_pSuite suite)
{
    CU_ADD_TEST(suite, TestProbeMgrCreate);
    CU_ADD_TEST(suite, TestProbeMgrPut);
    CU_ADD_TEST(suite, TestProbeMgrGet);
    CU_ADD_TEST(suite, TestProbeCreate);
}

