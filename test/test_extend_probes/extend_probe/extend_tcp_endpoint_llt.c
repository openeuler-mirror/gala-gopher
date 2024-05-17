#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>
#include <CUnit/Console.h>

#include "common_interface.h"
#include "test_endpoint.h"
#include "test_tcp.h"

typedef struct {
    char *suiteName;
    void (*suiteMain)(CU_pSuite);
    CU_InitializeFunc initFunc;
    CU_CleanupFunc cleanupFunc;
} TestSuite;

TestSuite gTestSuites[] = {
        TEST_SUITE_ENDPOINT,
        TEST_SUITE_TCP
};

int main(int argc, char *argv[])
{
    CU_pSuite suite;
    unsigned int num_failures;

    if (CU_initialize_registry() != CUE_SUCCESS) {
        return CU_get_error();
    }

    int suiteNum = sizeof(gTestSuites) / sizeof(gTestSuites[0]);
    for (int i = 0; i < suiteNum; ++i) {
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
