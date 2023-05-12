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
 * Create: 2022-11-14
 * Description: system virt probe, include virt_proc
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include "args.h"
#include "virt_proc.h"

static volatile sig_atomic_t stop;
static void sig_int(int signo)
{
    stop = 1;
}

static int virt_probe_init(struct probe_params * params)
{
    /* virt_proc init */
    virt_proc_init();

    return 0;
}

static void virt_probe_destroy(void)
{
    return;
}

int main(struct probe_params * params)
{
    int ret;

    /* system probes init */
    if (virt_probe_init(params) < 0) {
        goto err;
    }

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        ERROR("[VIRT_PROBE] can't set signal handler: %s\n", strerror(errno));
        goto err;
    }

    while(!stop) {
        ret = virt_proc_probe();
        if (ret < 0) {
            ERROR("[VIRT_PROBE] system virt proc probe fail.\n");
            goto err;
        }
        sleep(params->period);
    }

err:
    virt_probe_destroy();
    return -1;
}
