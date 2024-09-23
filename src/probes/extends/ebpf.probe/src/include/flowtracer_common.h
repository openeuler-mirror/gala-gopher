/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: ilyashakhat
 * Create: 2024-01-05
 * Description: FlowTracer plugin
 ******************************************************************************/
#ifndef __FLOWTRACER_COMMON_H__
#define __FLOWTRACER_COMMON_H__

#include <bpf/bpf_endian.h>

#define FLOWTRACER_DATA_MAP_PATH "/sys/fs/bpf/flowtracer_data"
#define FLOWTRACER_CGROUP2_PATH "/mnt/cgroup2"

struct flow_key {
    __be32 local_ip4;
    __be32 remote_ip4;
    __be16 local_port;
    __be16 remote_port;
    __u8 l4_proto;
};

struct flow_data {
    __be32 original_remote_ip4;
    __be16 original_remote_port;
};

#endif