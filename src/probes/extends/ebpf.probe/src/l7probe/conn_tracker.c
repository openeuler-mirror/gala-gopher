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

// TODO: complete print
void l7_sock_data_msg_handler(void *ctx, int cpu, void *data, unsigned int size)
{
    struct conn_data_s *msg_data = (struct conn_data_s *)data;

    fprintf(stdout,
            "|%s|%d|%d|%llu|%d|%d|%d|%llu|%lu|%s|\n",
            "l7probe",
            msg_data->conn_id.tgid,
            msg_data->conn_id.tgid,
            msg_data->timestamp_ns,
            msg_data->proto,
            msg_data->l7_role,
            msg_data->direction,
            msg_data->offset_pos,
            msg_data->data_size,
            msg_data->data);

    (void)fflush(stdout);

    return;
}

void l7_conn_control_msg_handler(void *ctx, int cpu, void *data, unsigned int size)
{
    struct conn_ctl_s *msg_data = (struct conn_ctl_s *)data;

    fprintf(stdout,
            "|%s|%d|%d|%llu|%d|\n",
            "l7probe",
            msg_data->conn_id.tgid,
            msg_data->conn_id.tgid,
            msg_data->timestamp_ns,
            msg_data->type);

    (void)fflush(stdout);

    return;
}

void l7_conn_stats_msg_handler(void *ctx, int cpu, void *data, unsigned int size)
{
    struct conn_stats_s *msg_data = (struct conn_stats_s *)data;

    fprintf(stdout,
            "|%s|%d|%d|%llu|\n",
            "l7probe",
            msg_data->conn_id.tgid,
            msg_data->conn_id.tgid,
            msg_data->timestamp_ns);

    (void)fflush(stdout);

    return;
}

