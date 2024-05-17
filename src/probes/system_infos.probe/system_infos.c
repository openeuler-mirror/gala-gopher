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
#include <time.h>

#include "ipc.h"
#include "system_disk.h"
#include "system_net.h"
#include "system_procs.h"
#include "system_cpu.h"
#include "system_meminfo.h"
#include "system_os.h"
#include "system_cons.h"

static struct ipc_body_s g_ipc_body;
time_t last_report;

static int system_probe_init(void)
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

    /* system disk destroy */
    system_disk_destroy();

    /* system iostat destroy */
    system_iostat_destroy();
}

static char is_load_probe(unsigned int ipc_probe_flags, unsigned int probe)
{
    if (ipc_probe_flags & probe) {
        return 1;
    }
    return 0;
}

static char is_report_tmout()
{
    time_t current = time(NULL);
    time_t secs;

    // skip when no ipc msg is received
    if (g_ipc_body.probe_param.period == 0) {
        return 0;
    }

    if (current > last_report) {
        secs = current -last_report;
        if (secs >= g_ipc_body.probe_param.period) {
            last_report = current;
            return 1;
        }
    }

    return 0;
}

int main(void)
{
    int ret;
    struct ipc_body_s ipc_body;
    char is_load_cpu = 0, is_load_mem = 0, is_load_nic = 0, is_load_net = 0;
    char is_load_disk = 0, is_load_fs = 0, is_load_proc = 0, is_load_host = 0, is_load_con = 0;
    char is_need_refresh_proc = 0;
    char is_need_refresh_con = 0;
    (void)memset(&g_ipc_body, 0, sizeof(struct ipc_body_s));

    int msq_id = create_ipc_msg_queue(IPC_EXCL);
    if (msq_id < 0) {
        ERROR("[SYSTEM_PROBE] Get ipc msg queue failed.\n");
        return -1;
    }

    /* system probes init */
    if (system_probe_init() < 0) {
        goto err;
    }

    while(1) {
        ret = recv_ipc_msg(msq_id, (long)PROBE_BASEINFO, &ipc_body);
        if (ret == 0) {
            destroy_ipc_body(&g_ipc_body);
            (void)memcpy(&g_ipc_body, &ipc_body, sizeof(g_ipc_body));
            is_load_cpu = is_load_probe(g_ipc_body.probe_range_flags, PROBE_RANGE_SYS_CPU);
            is_load_mem = is_load_probe(g_ipc_body.probe_range_flags, PROBE_RANGE_SYS_MEM);
            is_load_nic = is_load_probe(g_ipc_body.probe_range_flags, PROBE_RANGE_SYS_NIC);
            is_load_net = is_load_probe(g_ipc_body.probe_range_flags, PROBE_RANGE_SYS_NET);
            is_load_disk = is_load_probe(g_ipc_body.probe_range_flags, PROBE_RANGE_SYS_DISK);
            is_load_fs = is_load_probe(g_ipc_body.probe_range_flags, PROBE_RANGE_SYS_FS);
            is_load_proc = is_load_probe(g_ipc_body.probe_range_flags, PROBE_RANGE_SYS_PROC);
            is_load_host = is_load_probe(g_ipc_body.probe_range_flags, PROBE_RANGE_SYS_HOST);
            is_load_con = is_load_probe(g_ipc_body.probe_range_flags, PROBE_RANGE_SYS_CON);
            is_need_refresh_proc = 1;
            is_need_refresh_con = 1;
        }

        if (!is_report_tmout()) {
            sleep(1);
            continue;
        }

        if (is_load_cpu && system_cpu_probe(&g_ipc_body) < 0) {
            ERROR("[SYSTEM_PROBE] system cpu probe fail.\n");
            goto err;
        }
        if (is_load_mem && system_meminfo_probe(&g_ipc_body) < 0) {
            ERROR("[SYSTEM_PROBE] system meminfo probe fail.\n");
            goto err;
        }
        if (is_load_net && system_tcp_probe() < 0) {
            ERROR("[SYSTEM_PROBE] system tcp probe fail.\n");
            goto err;
        }
        if (is_load_nic && system_net_probe(&g_ipc_body) < 0) {
            ERROR("[SYSTEM_PROBE] system net probe fail.\n");
            goto err;
        }
        if (is_load_fs && system_disk_probe(&g_ipc_body) < 0) {
            ERROR("[SYSTEM_PROBE] system disk probe fail.\n");
            goto err;
        }
        if (is_load_disk && system_iostat_probe(&g_ipc_body) < 0) {
            ERROR("[SYSTEM_PROBE] system iostat probe fail.\n");
            goto err;
        }
        if (is_load_proc) {
            if (is_need_refresh_proc && refresh_proc_filter_map(&g_ipc_body) < 0) {
                ERROR("[SYSTEM_PROBE] system proc refresh failed.\n");
                goto err;
            }
            is_need_refresh_proc = 0;   // refresh proc_map at first time after recv_ipc_msg
            if (system_proc_probe(&g_ipc_body) < 0) {
                ERROR("[SYSTEM_PROBE] system proc probe failed.\n");
                goto err;
            }
        }
        if (is_load_con) {
            if (is_need_refresh_con && refresh_con_filter_map(&g_ipc_body) < 0) {
                ERROR("[SYSTEM_PROBE] system con refresh failed.\n");
                goto err;
            }
            is_need_refresh_con = 0;   // refresh con_map at first time after recv_ipc_msg
            if (system_con_probe(&g_ipc_body) < 0) {
                ERROR("[SYSTEM_PROBE] system con probe failed.\n");
                goto err;
            }
        }
        if (is_load_host && system_os_probe(&g_ipc_body) < 0) {
            ERROR("[SYSTEM_PROBE] system os probe fail.\n");
            goto err;
        }
    }

err:
    system_probe_destroy();
    destroy_ipc_body(&g_ipc_body);
    return -1;
}
