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

#include "meta.h"
#include "test_meta.h"

#define MEASUREMENT_MGR_SIZE    1024
#define META_PATH   "test_modules/test.meta"

static void TestMeasurementMgrCreate(void)
{
    MeasurementMgr *mgr = MeasurementMgrCreate(MEASUREMENT_MGR_SIZE, MEASUREMENT_MGR_SIZE);

    CU_ASSERT(mgr != NULL);
    CU_ASSERT(mgr->measurements != NULL);
    CU_ASSERT(mgr->measurementsNum == 0);
    CU_ASSERT(mgr->measurementsCapability == MEASUREMENT_MGR_SIZE);
    MeasurementMgrDestroy(mgr);
}

static void TestMeasurementMgrLoad(void)
{
    uint32_t ret = 0;
    MeasurementMgr *mgr = MeasurementMgrCreate(MEASUREMENT_MGR_SIZE, MEASUREMENT_MGR_SIZE);
    CU_ASSERT(mgr != NULL);

    ret = MeasurementMgrLoadSingleMeta(mgr, META_PATH);
    CU_ASSERT(ret == 0);
    CU_ASSERT(mgr->measurementsNum == 1);
    CU_ASSERT(strcmp(mgr->measurements[0]->name, "test") == 0);
    CU_ASSERT(mgr->measurements[0]->fieldsNum == 8);

    MeasurementMgrDestroy(mgr);
}

void TestMetaMain(CU_pSuite suite)
{
    CU_ADD_TEST(suite, TestMeasurementMgrCreate);
    CU_ADD_TEST(suite, TestMeasurementMgrLoad);
}

