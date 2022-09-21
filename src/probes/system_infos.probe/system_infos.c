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
 * Create: 2022-03-01
 * Description: system probe just in 1 thread, include tcp/net/iostat/inode
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "args.h"
#include "system_disk.h"
#include "system_net.h"
#include "system_procs.h"
#include "system_cpu.h"
#include "system_meminfo.h"

static int system_probe_init(struct probe_params * params)
{
    /* system meminfo init */
    if (system_meminfo_init() < 0) {
        return -1;
    }

    /* system cpu init */
    if (system_cpu_init() < 0) {
        return -1;
    }

    /* system net init */
    system_tcp_init();
    if (system_net_init() < 0) {
        return -1;
    }

    /* system proc init */
    system_proc_init(params->task_whitelist);

    /* system_iostat init */
    if (system_iostat_init() < 0) {
        return -1;
    }

    return 0;
}

static void system_probe_destroy(void)
{
    /* system meminfo destroy */
    system_meminfo_destroy();

    /* system cpu destroy */
    system_cpu_destroy();

    /* system net destroy */
    system_net_destroy();

    /* system iostat destroy */
    system_iostat_destroy();

    /* system proc destroy */
    system_proc_destroy();
}

int main(struct probe_params * params)
{
    int ret;

    /* system probes init */
    if (system_probe_init(params) < 0) {
        goto err;
    }

    for (;;) {
        ret = system_meminfo_probe(params);
        if (ret < 0) {
            ERROR("[SYSTEM_PROBE] system meminfo probe fail.\n");
            goto err;
        }
        ret = system_cpu_probe(params);
        if (ret < 0) {
            ERROR("[SYSTEM_PROBE] system cpu probe fail.\n");
            goto err;
        }
        ret = system_tcp_probe();
        if (ret < 0) {
            ERROR("[SYSTEM_PROBE] system tcp probe fail.\n");
            goto err;
        }
        ret = system_net_probe(params);
        if (ret < 0) {
            ERROR("[SYSTEM_PROBE] system net probe fail.\n");
            goto err;
        }
        ret = system_disk_probe(params);
        if (ret < 0) {
            ERROR("[SYSTEM_PROBE] system disk probe fail.\n");
            goto err;
        }
        ret = system_iostat_probe(params);
        if (ret < 0) {
            ERROR("[SYSTEM_PROBE] system iostat probe fail.\n");
            goto err;
        }
        ret = system_proc_probe();
        if (ret < 0) {
            ERROR("[SYSTEM_PROBE] system proc probe fail.\n");
            goto err;
        }
        sleep(params->period);
    }

err:
    system_probe_destroy();
    return -1;
}
