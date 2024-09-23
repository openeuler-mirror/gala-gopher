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
#ifndef __FLOWTRACER_H
#define __FLOWTRACER_H

#include <bpf/bpf_endian.h>
#include "flowtracer_common.h"

// TCP option definition
#define TCP_OPT_SOURCE_INFO_KIND 0x55
struct tcp_opt_source_info {
    __u8 kind;
    __u8 len;
    struct address_info {
        __be32 ip4;
        __be16 port;
    } __attribute__((packed)) address;
} __attribute__((packed));

// debug event definition
enum flow_log_op {
    FLOW_LOG_ADD = 1,
    FLOW_LOG_DEL = 2
};

struct flow_log {
    enum flow_log_op op;
    struct flow_key key;
    struct flow_data data;
};

#endif /* __FLOWTRACER_H */