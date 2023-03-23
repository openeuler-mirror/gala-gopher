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
 * Create: 2023-03-22
 * Description: l7 common header
 ******************************************************************************/
#ifndef __L7_COMMON_H__
#define __L7_COMMON_H__

#include "include/filter.h"
#include "include/connect.h"

struct l7_param_s {
    u32 period;
    // To add ...
};

struct l7_mng_s {
    int proc_obj_map_fd; 
    int conn_tbl_fd;
    struct l7_param_s l7_params;       // l7probe args
    struct filter_args_s filter_args;  // bpf runnning args
    struct bpf_prog_s *bpf_progs;      // loaded bpf progs
    struct pods_hash_t *pod_head;      // all pods/containers info
    struct conns_hash_t *conn_head;    // all connections info
};

#endif