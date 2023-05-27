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
 * Create: 2022-09-20
 * Description: include file for system_os
 ******************************************************************************/
#ifndef SYSTEM_OS_RPOBE__H
#define SYSTEM_OS_RPOBE__H

#pragma once

#include "common.h"
#include "ipc.h"

#define MAX_FIELD_LEN       64
#define IPV4_STR_LEN        16
#define MAX_IP_ADDRS_LEN    1024

struct node_infos {
    char host_name[MAX_FIELD_LEN];
    char os_pretty_name[MAX_FIELD_LEN];
    char os_id[MAX_FIELD_LEN];
    char os_version[MAX_FIELD_LEN];
    char kernel_version[MAX_FIELD_LEN];
    char ip_addr[MAX_IP_ADDRS_LEN];
    u64 cpu_num;
    u64 total_memory;
    char is_host_vm;    // 1: vm / 0: pm
};

int system_os_probe(struct ipc_body_s * ipc_body);

#endif

