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
 * Author: wo_cow
 * Create: 2024-02-28
 * Description: include file for system_cons
 ******************************************************************************/
#ifndef SYSTEM_CON_RPOBE__H
#define SYSTEM_CON_RPOBE__H

#pragma once

#include <uthash.h>
#include "common.h"
#include "ipc.h"

#define CON_IN_PROBE_RANGE 1

#define CONTAINER_ID_BUF_LEN (CONTAINER_ABBR_ID_LEN + 4)

typedef struct {
    const char *con_id;
    char flag;
    char cmd[PATH_LEN];
    u64 proc_write_bytes_to_dir;
    UT_hash_handle hh;
} con_hash_t;

int system_con_probe(struct ipc_body_s *ipc_body);
int refresh_con_filter_map(struct ipc_body_s *ipc_body);
#endif
