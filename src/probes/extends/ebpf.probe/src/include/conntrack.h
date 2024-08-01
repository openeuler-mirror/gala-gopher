/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: luzhihao
 * Create: 2023-08-17
 * Description: conntrack module header file
 ******************************************************************************/
#ifndef __GOPHER_CONNTRACK_H__
#define __GOPHER_CONNTRACK_H__

#include "common.h"

#define ADDR_TRANSFORM_NONE   0
#define ADDR_TRANSFORM_CLIENT 1
#define ADDR_TRANSFORM_SERVER 2

struct tcp_connect_s {
    union {
        u32 c_ip;
        unsigned char c_ip6[IP6_LEN];
    } cip_addr;
    union {
        u32 s_ip;
        unsigned char s_ip6[IP6_LEN];
    } sip_addr;
    u16 c_port;
    u16 s_port;
    u16 family;
    u16 role;     // role: client:1/server:0
};

int get_cluster_ip_backend(struct tcp_connect_s *connect, int *transform);

#endif
