#ifndef __TEST_ENDPOINT_H__
#define __TEST_ENDPOINT_H__

#include "common_interface.h"

#define TEST_SUITE_ENDPOINT \
    {   \
        .suiteName = "TEST_ENDPOINT",   \
        .suiteMain = TestEndPointMain   \
    }

extern void TestEndPointMain(CU_pSuite suite);

#endif