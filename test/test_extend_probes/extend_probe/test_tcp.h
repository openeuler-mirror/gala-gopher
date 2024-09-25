#ifndef __TEST_TCP_H__
#define __TEST_TCP_H__
#include "common_interface.h"

#define TEST_SUITE_TCP \
    {   \
        .suiteName = "TEST_TCP",   \
        .suiteMain = TestTcpMain   \
    }


extern void TestTcpMain(CU_pSuite suite);

#endif