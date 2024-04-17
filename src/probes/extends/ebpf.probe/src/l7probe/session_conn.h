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
 * Create: 2023-07-01
 * Description: user session connection header
 ******************************************************************************/
#ifndef __SESSION_CONN_H__
#define __SESSION_CONN_H__

#include "hash.h"
#include "include/connect.h"

struct session_conn_id_s {
    int tgid;
    s64 session_id;
};

struct session_data_args_s {
    struct session_conn_id_s session_conn_id;
    int port;
    char ip[INET6_ADDRSTRLEN];
    enum l7_direction_t direct;
    enum l4_role_t role;
    char buf[CONN_DATA_MAX_SIZE];
    size_t bytes_count;
    char is_ssl;
};

void clean_pid_session_hash(int tgid);
void submit_sock_data_by_session(void *ctx, struct session_data_args_s* args);

#endif