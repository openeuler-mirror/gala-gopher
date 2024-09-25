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
 * Author: sky
 * Create: 2021-06-21
 * Description: nginx_probe include file
 ******************************************************************************/
#ifndef __NGX_PROBE_H__
#define __NGX_PROBE_H__
#include "nginx_1.12.1.h"

#define BIN_FILE_PATH_LEN 128

#define STATISTIC_MAX_ENTRIES 100000
#define MIN_PRINT_INTERVAL 1
#define MAX_PRINT_INTERVAL 3600
struct ip {
    union {
        __u32 ip4;
        unsigned char ip6[IP6_LEN];
    };
};

struct ip_addr {
    struct ip ipaddr;
    __u16 port;
    __u32 family;
};

struct ngx_metric {
    struct ip_addr src_ip;
    struct ip_addr ngx_ip;
    char dst_ip_str[INET6_ADDRSTRLEN];
    __u32 is_l7 : 1;
    __u32 is_finish : 1;
    __u32 resv : 30;
};

struct ngx_statistic_key {
    struct ip cip;
    char sip_str[INET6_ADDRSTRLEN];
    __u32 family : 31;
    __u32 is_l7 : 1;
};

struct ngx_statistic {
    struct ip_addr ngx_ip;
    unsigned int link_count;
};

#endif