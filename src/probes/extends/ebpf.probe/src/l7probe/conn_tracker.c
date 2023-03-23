/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wo_cow
 * Create: 2023-03-07
 * Description: L7 Traffic Tracking
 ******************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "args.h"
#include "include/conn_tracker.h"


static void __print_libssl_metrics(struct ssl_msg_t *msg_data)
{
    fprintf(stdout,
            "|%s|%d|%d|%d|%d|%llu|%s|\n",
            "libssl_msg",
            msg_data->msg_type,
            msg_data->tgid,
            msg_data->fd,
            msg_data->count,
            msg_data->ts_nsec,
            msg_data->msg);

    (void)fflush(stdout);
}

void l7_libssl_msg_handler(void *ctx, int cpu, void *data, unsigned int size)
{
    struct ssl_msg_t *msg_data = (struct ssl_msg_t *)data;

    __print_libssl_metrics(msg_data);

    return;
}
