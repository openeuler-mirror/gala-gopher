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
#include "ipc.h"
#include "probe_mng.h"
#include "virt_proc.h"

static struct ipc_body_s g_ipc_body;

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

int main(struct probe_s * probe)
{
    int ret;
    struct ipc_body_s ipc_body;

    (void)memset(&g_ipc_body, 0, sizeof(struct ipc_body_s));

    int msq_id = create_ipc_msg_queue(IPC_EXCL);
    if (msq_id < 0) {
        ERROR("[VIRT_PROBE] Get ipc msg queue failed.\n");
        return -1;
    }

    /* system probes init */
    if (virt_probe_init(&(probe->probe_param)) < 0) {
        goto err;
    }

    while(IS_RUNNING_PROBE(probe)) {
        ret = recv_ipc_msg(msq_id, (long)PROBE_VIRT, &ipc_body);
        if (ret == 0) {
            destroy_ipc_body(&g_ipc_body);
            (void)memcpy(&g_ipc_body, &ipc_body, sizeof(g_ipc_body));
        }
        ret = virt_proc_probe();
        if (ret < 0) {
            ERROR("[VIRT_PROBE] system virt proc probe fail.\n");
            goto err;
        }
        sleep(g_ipc_body.probe_param.period);
    }

err:
    virt_probe_destroy();
    destroy_ipc_body(&g_ipc_body);
    return -1;
}
