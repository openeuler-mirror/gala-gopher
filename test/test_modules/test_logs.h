/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: dowzyx
 * Create: 2022-08-22
 * Description: provide gala-gopher test for logs
 ******************************************************************************/
#ifndef __TEST_LOGS_H__
#define __TEST_LOGS_H__

#define TEST_SUITE_LOGS \
    {   \
        .suiteName = "TEST_LOGS",   \
        .suiteMain = TestLogsMain   \
    }

extern void TestLogsMain(CU_pSuite suite);

#endif

