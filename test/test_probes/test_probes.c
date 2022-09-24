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
#include <stdlib.h>
#include <stdint.h>
#include <CUnit/Basic.h>
#include "probe.h"
#include "../../probes/system_infos.probe/system_cpu.h"

static void TestSystemMeminfoInit(void)
{
    // init meminfo_fileds[]
    uint32_t ret = system_meminfo_init();
    CU_ASSERT(ret == 0);
    
    // destroy meminfo_fileds[]
    system_meminfo_destroy();
}

static void TestSystemCpuInit(void)
{
    uint32_t ret = 0;
    ret = system_cpu_init();
    CU_ASSERT(ret == 0);
    system_cpu_destroy();
}

static void TestSystemMeminfoProbe(void)
{
    uint32_t ret = system_meminfo_init();
    CU_ASSERT_FATAL(ret == 0);
    
    struct probe_params params = {.period = DEFAULT_PERIOD};

    // sample test for nprobe_fprintf
    g_probe = ProbeCreate();
    CU_ASSERT(g_probe != NULL);
    CU_ASSERT(g_probe->fifo != NULL);
    (void)snprintf(g_probe->name, MAX_PROBE_NAME_LEN - 1, "test_meminfo_probe");

    // probe reads the data in file
    ret = system_meminfo_probe(&params);
    CU_ASSERT(ret == 0);
    // test the nprintf function
    uint32_t *elements = NULL;
    ret = FifoGet(g_probe->fifo, (void**) &elements);
    CU_ASSERT(g_probe->fifo->out == 1);

    ProbeDestroy(g_probe);
    system_meminfo_destroy();
}

static void TestSystemCpuProbe(void)
{
    uint32_t ret = 0;
    uint32_t *elemP = NULL;
    struct probe_params params = {.period = DEFAULT_PERIOD};
    ret = system_cpu_init();
    CU_ASSERT(ret == 0);

    ret = system_cpu_probe(&params);
    CU_ASSERT(ret == 0);

    // nprobe_fprintf的g_probe是null，需要初始化 
    // 按照代码逻辑，第二次上报指标信息，需要检测两次
    g_probe = ProbeCreate();
    CU_ASSERT(g_probe != NULL);

    if (g_probe != NULL) {
        CU_ASSERT(g_probe->fifo != NULL);
        (void)snprintf(g_probe->name, MAX_PROBE_NAME_LEN - 1, "test_cpu_probe");
    
        ret = system_cpu_probe(&params);
        CU_ASSERT(ret == 0);

        ret = FifoGet(g_probe->fifo, (void **) &elemP);
        CU_ASSERT(ret == 0);
        CU_ASSERT(g_probe->fifo->out == 1);

        ProbeDestroy(g_probe);
    }
    system_cpu_destroy();
}

static void TestSystemCpu(void)
{
    TestSystemCpuInit();
    TestSystemCpuProbe();
}

static void TestSystemMeminfo(void)
{
    TestSystemMeminfoInit();
    TestSystemMeminfoProbe();
}

void testProbesMain(void)
{
    TestSystemCpu();
    TestSystemMeminfo();
}

