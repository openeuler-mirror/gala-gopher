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
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include "common.h"
#include "flowtracer_common.h"
#include "flowtracer_reader.h"

static int g_flow_tracer_map_fd = -1;

int lookup_flowtracer(struct tcp_connect_s *connect) {
    __u32 local_ip4, remote_ip4;
    __u16 local_port, remote_port;
    int fd = g_flow_tracer_map_fd;

    __u32 s_ip, c_ip;
    if (connect->family == AF_INET) {
        // IPv4
        s_ip = connect->sip_addr.s_ip;
        c_ip = connect->cip_addr.c_ip;
    } else if (connect->family == AF_INET6 &&
                NIP6_IS_ADDR_V4MAPPED((unsigned short *)connect->sip_addr.s_ip6) && NIP6_IS_ADDR_V4MAPPED((unsigned short *)connect->cip_addr.c_ip6)) {
        // IPv4 address mapped to IPv6
        s_ip = *((__u32 *)(connect->sip_addr.s_ip6 + IP4_BYTE_1_IN_IP6));
        c_ip = *((__u32 *)(connect->cip_addr.c_ip6 + IP4_BYTE_1_IN_IP6));
        DEBUG("[lookup_flowtracer] mapped IPv4: server %x client %x\n", s_ip, c_ip);
    } else {
        // pure IPv6 is not supported
        return ADDR_TRANSFORM_NONE;
    }

    if (connect->role == 0) {
        // server: local is server, remote is client
        local_ip4 = s_ip;
        local_port = connect->s_port;
        remote_ip4 = c_ip;
        remote_port = connect->c_port;
    } else {
        // client: local is client, remote is server
        local_ip4 = c_ip;
        local_port = connect->c_port;
        remote_ip4 = s_ip;
        remote_port = connect->s_port;
    }

    if (g_flow_tracer_map_fd < 0) {
        // Try to retrieve map fd
        fd = bpf_obj_get(FLOWTRACER_DATA_MAP_PATH);
        if (fd <= 0) { // map doesn't exist
            DEBUG("[lookup_flowtracer] Failed to open FlowTracer map: %s\n", strerror(errno));
            return ADDR_TRANSFORM_NONE;
        }
        g_flow_tracer_map_fd = fd;
        DEBUG("[lookup_flowtracer] FlowTracer map is opened successfully, fd: %d\n", g_flow_tracer_map_fd);
    }

    struct flow_key key = {0}; // alignment gaps must be filled with 0
    key.local_ip4 = local_ip4;
    key.local_port = htons(local_port);
    key.remote_ip4 = remote_ip4;
    key.remote_port = htons(remote_port);
    key.l4_proto = IPPROTO_TCP;

    struct flow_data value = {0};

    DEBUG("[lookup_flowtracer] Lookup fd %d, local_ip4: %u (%x), local_port: %d, remote_ip4: %u (%x), remote_port: %d, l4_proto: %d, key_size: %d, value_size: %d\n",
                    g_flow_tracer_map_fd, key.local_ip4, key.local_ip4, key.local_port, key.remote_ip4, key.remote_ip4, key.remote_port, key.l4_proto, sizeof(key), sizeof(value));

    int err = bpf_map_lookup_elem(g_flow_tracer_map_fd, &key, &value);
    if (err) {
        DEBUG("[lookup_flowtracer] Lookup fd %d, err: %d (%s)\n", g_flow_tracer_map_fd, err, strerror(errno));
        return ADDR_TRANSFORM_NONE;
    }

    __u32 original_remote_ip4 = value.original_remote_ip4;
    __u16 original_remote_port = ntohs(value.original_remote_port);

    DEBUG("[lookup_flowtracer] Lookup original_remote_ip4: %x, original_remote_port: %d\n",
                    original_remote_ip4, original_remote_port);

    if (connect->family == AF_INET) {
        if (connect->role == 0) {
            connect->cip_addr.c_ip = original_remote_ip4;
            connect->c_port = original_remote_port;
            return ADDR_TRANSFORM_CLIENT;
        } else {
            connect->sip_addr.s_ip = original_remote_ip4;
            connect->s_port = original_remote_port;
            return ADDR_TRANSFORM_SERVER;
        }
    } else {
        if (connect->role == 0) {
            *((__u32 *)(connect->cip_addr.c_ip6 + IP4_BYTE_1_IN_IP6)) = original_remote_ip4;
            connect->c_port = original_remote_port;
            return ADDR_TRANSFORM_CLIENT;
        } else {
            *((__u32 *)(connect->sip_addr.s_ip6 + IP4_BYTE_1_IN_IP6)) = original_remote_ip4;
            connect->s_port = original_remote_port;
            return ADDR_TRANSFORM_SERVER;
        }
    }
}