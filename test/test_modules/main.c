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
 * Description: provide gala-gopher test framework
 ******************************************************************************/
#include <stdlib.h>
#include <stdint.h>
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include <CUnit/Console.h>

#include "test_fifo.h"
#include "test_kafka.h"
#include "test_meta.h"
#include "test_probe.h"
#include "test_imdb.h"
#include "test_logs.h"

typedef struct {
    char *suiteName;
    void (*suiteMain)(CU_pSuite);
    CU_InitializeFunc initFunc;
    CU_CleanupFunc cleanupFunc;
} TestSuite;

TestSuite gTestSuites[] = {
    TEST_SUITE_FIFO,
#ifdef KAFKA_CHANNEL
    TEST_SUITE_KAFKA,
#endif
    TEST_SUITE_META,
    //TEST_SUITE_PROBE,
    TEST_SUITE_IMDB,
    TEST_SUITE_LOGS
};

int main(int argc, char *argv[])
{
    CU_pSuite suite;
    unsigned int num_failures;

    if (CU_initialize_registry() != CUE_SUCCESS) {
        return CU_get_error();
    }

    int suiteNum = sizeof(gTestSuites) / sizeof(gTestSuites[0]);
    for (int i = 0; i < suiteNum; i++) {
        suite = CU_add_suite(gTestSuites[i].suiteName, gTestSuites[i].initFunc, gTestSuites[i].cleanupFunc);
        if (suite == NULL) {
            CU_cleanup_registry();
            return CU_get_error();
        }

        gTestSuites[i].suiteMain(suite);
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    num_failures = CU_get_number_of_failures();
    CU_cleanup_registry();
    return (int)num_failures;
}

