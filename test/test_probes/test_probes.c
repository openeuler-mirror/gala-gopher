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
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <CUnit/Basic.h>
#include "probe.h"
#include "../../probes/system_infos.probe/system_cpu.h"


#define EVENT_ERR_CODE "code=[13]"

static int is_contain_physical_device(void)
{
    DIR *dir = NULL;
    struct dirent *entry;
    char fpath[COMMAND_LEN];

    dir = opendir("/sys/class/net");
    if (dir == NULL) {
        return -1;
    }
    while (entry = readdir(dir)) {
        fpath[0] = 0;
        (void)snprintf(fpath, COMMAND_LEN, "/sys/devices/virtual/net/%s", entry->d_name);
        if (access((const char *)fpath, 0) < 0) {
            closedir(dir);
            return 0;
        }
    }
    closedir(dir);
    return -1;
}

void TestSystemMeminfoProbe(void)
{
    char *substr = NULL;
    uint32_t ret = system_meminfo_init();
    CU_ASSERT_FATAL(ret == 0);
    
    struct probe_params params = {.period = DEFAULT_PERIOD};

    // sample test for nprobe_fprintf
    g_probe = ProbeCreate();
    CU_ASSERT(g_probe != NULL);
    CU_ASSERT(g_probe->fifo != NULL);
    (void)snprintf(g_probe->name, MAX_PROBE_NAME_LEN - 1, "test_meminfo_probe");

    // cover  report_log the function
    params.logs = 1;
    // call the mem probe
    ret = system_meminfo_probe(&params);
    CU_ASSERT(ret == 0);
    // test the nprintf function
    uint32_t *elements = NULL;
    ret = FifoGet(g_probe->fifo, (void**) &elements);
    CU_ASSERT(g_probe->fifo->out == 1);
    substr = strstr(elements, "system_meminfo");
    CU_ASSERT(substr != NULL);

    ProbeDestroy(g_probe);
    system_meminfo_destroy();
}

void TestSystemCpuProbe(void)
{
    uint32_t ret = 0;
    uint32_t *elemP = NULL;
    char *substr = NULL;
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

        // logs = 1, 上报
        params.logs = 1;
        ret = system_cpu_probe(&params);
        CU_ASSERT(ret == 0);

        ret = FifoGet(g_probe->fifo, (void **) &elemP);
        CU_ASSERT(ret == 0);
        CU_ASSERT(g_probe->fifo->out == 1);
        substr = strstr(elemP, "system_cpu");
        CU_ASSERT(substr != NULL);

        g_probe->fifo->in = 0;
        g_probe->fifo->out = 0;

        // logs = 0, 未上报
        params.logs = 0;
        ret = system_cpu_probe(&params);
        CU_ASSERT(ret == 0);
        elemP = NULL;
        ret = FifoGet(g_probe->fifo, (void **) &elemP);
        CU_ASSERT(ret == 0);
        CU_ASSERT(g_probe->fifo->out == 1);
        substr = strstr(elemP, "system_cpu");
        CU_ASSERT(substr != NULL);

        ProbeDestroy(g_probe);
    }
    system_cpu_destroy();
}

void TestSystemDiskIOStatProbe(void)
{
    uint32_t ret = 0;
    uint32_t *elemP = NULL;
    char *substr = NULL;
    struct probe_params params = {.period = DEFAULT_PERIOD};
    ret = system_iostat_init();
    CU_ASSERT(ret == 0);

    g_probe = ProbeCreate();
    CU_ASSERT(g_probe != NULL);

    ret = system_iostat_probe(&params);
    CU_ASSERT(ret == 0);

    if (g_probe != NULL) {
        CU_ASSERT(g_probe->fifo != NULL);
        (void)snprintf(g_probe->name, MAX_PROBE_NAME_LEN - 1, "test_disk_iostats_probe");
    
        // logs = 1, 上报
        params.logs = 1;
        ret = system_iostat_probe(&params);
        CU_ASSERT(ret == 0);

        ret = FifoGet(g_probe->fifo, (void **) &elemP);
        CU_ASSERT(ret == 0);
        CU_ASSERT(g_probe->fifo->out == 1);
        substr = strstr(elemP, "system_iostat");
        CU_ASSERT(substr != NULL);

        g_probe->fifo->in = 0;
        g_probe->fifo->out = 0;

        // logs = 0, 未上报
        params.logs = 0;
        ret = system_iostat_probe(&params);
        CU_ASSERT(ret == 0);
        elemP = NULL;
        ret = FifoGet(g_probe->fifo, (void **) &elemP);
        CU_ASSERT(ret == 0);
        CU_ASSERT(g_probe->fifo->out == 1);
        substr = strstr(elemP, "system_iostat");
        CU_ASSERT(substr != NULL);

        ProbeDestroy(g_probe);
    }
    system_iostat_destroy();
}

void TestSystemDiskProbe(void)
{
    uint32_t ret = 0;
    uint32_t *elemP = NULL;
    char *substr = NULL;
    struct probe_params params;
    ret = system_iostat_init();
    CU_ASSERT(ret == 0);

    g_probe = ProbeCreate();
    CU_ASSERT(g_probe != NULL);

    ret = system_disk_probe(&params);
    CU_ASSERT(ret == 0);

    if (g_probe != NULL) {
        CU_ASSERT(g_probe->fifo != NULL);
        (void)snprintf(g_probe->name, MAX_PROBE_NAME_LEN - 1, "test_disk_probe");

        // logs = 1, 上报
        params.logs = 1;
        ret = system_disk_probe(&params);
        CU_ASSERT(ret == 0);

        ret = FifoGet(g_probe->fifo, (void **) &elemP);
        CU_ASSERT(ret == 0);
        CU_ASSERT(g_probe->fifo->out == 1);
        substr = strstr(elemP, "system_df");
        CU_ASSERT(substr != NULL);

        g_probe->fifo->in = 0;
        g_probe->fifo->out = 0;

        // logs = 0, 未上报
        params.logs = 0;
        ret = system_disk_probe(&params);
        CU_ASSERT(ret == 0);
        elemP = NULL;
        ret = FifoGet(g_probe->fifo, (void **) &elemP);
        CU_ASSERT(ret == 0);
        CU_ASSERT(g_probe->fifo->out == 1);
        substr = strstr(elemP, "system_df");
        CU_ASSERT(substr != NULL);

        ProbeDestroy(g_probe);
    }
    system_iostat_destroy();
}

void TestSystemNetProbe(void)
{
    uint32_t ret = 0;
    uint32_t *elemP = NULL;
    char *substr = NULL;
    struct probe_params params = {.period = DEFAULT_PERIOD};

    if (is_contain_physical_device() != 0) {
        ret = system_net_init();
        CU_ASSERT(ret != 0);
        return;
    }

    ret = system_net_init();
    CU_ASSERT(ret == 0);

    g_probe = ProbeCreate();
    CU_ASSERT(g_probe != NULL);

    ret = system_net_probe(&params);
    CU_ASSERT(ret == 0);

    if (g_probe != NULL) {
        CU_ASSERT(g_probe->fifo != NULL);
        (void)snprintf(g_probe->name, MAX_PROBE_NAME_LEN - 1, "test_net_probe");

        // logs = 1, 上报
        params.logs = 1;
        ret = system_net_probe(&params);
        CU_ASSERT(ret == 0);

        ret = FifoGet(g_probe->fifo, (void **) &elemP);
        CU_ASSERT(ret == 0);
        CU_ASSERT(g_probe->fifo->out == 1);
        substr = strstr(elemP, "nic");
        CU_ASSERT(substr != NULL);

        g_probe->fifo->in = 0;
        g_probe->fifo->out = 0;

        // logs = 0, 未上报
        params.logs = 0;
        ret = system_net_probe(&params);
        CU_ASSERT(ret == 0);

        elemP = NULL;
        ret = FifoGet(g_probe->fifo, (void **) &elemP);
        CU_ASSERT(ret == 0);
        CU_ASSERT(g_probe->fifo->out == 1);
        substr = strstr(elemP, "nic");
        CU_ASSERT(substr != NULL);

        ProbeDestroy(g_probe);
    }
    system_net_destroy();
}

void TestSystemdNetTcpProbe(void)
{
    uint32_t ret = 0;
    uint32_t *elemP = NULL;
    char *substr = NULL;

    if (is_contain_physical_device() != 0) {
        ret = system_net_init();
        CU_ASSERT(ret != 0);
        return;
    }

    ret = system_net_init();
    CU_ASSERT(ret == 0);

    g_probe = ProbeCreate();
    CU_ASSERT(g_probe != NULL);
    CU_ASSERT(g_probe->fifo != NULL);
    (void)snprintf(g_probe->name, MAX_PROBE_NAME_LEN - 1, "test_net_probe");

    ret = system_tcp_probe();
    CU_ASSERT(ret == 0);
    ret = FifoGet(g_probe->fifo, (void **) &elemP);
    CU_ASSERT(ret == 0);
    CU_ASSERT(g_probe->fifo->out == 1);
    substr = strstr(elemP, "system_tcp");
    CU_ASSERT(substr != NULL);

    ProbeDestroy(g_probe);
    system_net_destroy();
}

void TestSystemProcProbe(void)
{
    uint32_t ret = 0;
    uint32_t *elemP = NULL;
    FILE *f = NULL;
    char cmd[COMMAND_LEN];
    struct probe_params params = {.period = DEFAULT_PERIOD, .task_whitelist="/tmp/gala-gopher-app.conf"};

    /* prepare create proc_map */
    ret = mkdir("/sys/fs/bpf/gala-gopher", 0775);
    /* bpf may not be enabled in ci environment */
    if (ret != 0) {
        return;
    }

    snprintf(cmd, COMMAND_LEN - 1, "touch /tmp/gala-gopher-app.conf");
    f = popen(cmd, "r");
    CU_ASSERT(f != NULL);

    snprintf(cmd, COMMAND_LEN - 1, "echo \'application = ({ comm = \"sleep\", cmdline = \"\"})\'  >/tmp/gala-gopher-app.conf");
    f = popen(cmd, "r");
    CU_ASSERT(f != NULL);

    snprintf(cmd, COMMAND_LEN - 1, "sleep 60 &");
    f = popen(cmd, "r");
    CU_ASSERT(f != NULL);

    system_proc_init(&params.task_whitelist);
    CU_ASSERT(&params.task_whitelist != NULL);

    g_probe = ProbeCreate();
    CU_ASSERT(g_probe != NULL);

    ret = system_proc_probe(&params);
    CU_ASSERT(ret == 0);

    snprintf(cmd, COMMAND_LEN - 1, "rm -rf /tmp/gala-gopher-app.conf");
    f = popen(cmd, "r");
    CU_ASSERT(f != NULL);

    snprintf(cmd, COMMAND_LEN - 1, "rm -rf /sys/fs/bpf/gala-gopher");
    f = popen(cmd, "r");
    CU_ASSERT(f != NULL);

    ProbeDestroy(g_probe);
    system_proc_destroy();
}

void TestVirtInfoProbe(void)
{
    int ret;
    char *dataStr = NULL;
    virt_proc_init();

    g_probe = ProbeCreate();
    CU_ASSERT(g_probe != NULL);
    CU_ASSERT(g_probe->fifo != NULL);

    ret = virt_proc_probe();
    CU_ASSERT(ret == 0);
}


void TestEventProbe(void)
{
    char cmd[COMMAND_LEN];
    char *dataStr;
    char *substr;
    FILE *f = NULL;
    uint32_t ret;

    snprintf(cmd, COMMAND_LEN - 1, "echo \"%s\" >> /var/log/messages", EVENT_ERR_CODE);
    f = popen(cmd, "r");
    CU_ASSERT(f != NULL);

    g_probe = ProbeCreate();
    CU_ASSERT(g_probe != NULL);
    CU_ASSERT(g_probe->fifo != NULL);

    ret = probe_main_event();
    CU_ASSERT(ret == 0);

    ret = FifoGet(g_probe->fifo, (void **)&dataStr);
    CU_ASSERT(ret == 0);
    substr = strstr(dataStr, EVENT_ERR_CODE);
    CU_ASSERT(substr != NULL);

    ProbeDestroy(g_probe);
}