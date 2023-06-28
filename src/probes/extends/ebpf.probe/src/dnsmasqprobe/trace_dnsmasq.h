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
 * Author: dowzyx
 * Create: 2021-06-10
 * Description: dnsmasq_probe include file
 ******************************************************************************/
#ifndef __TRACE_DNSMASQ__H
#define __TRACE_DNSMASQ__H


#define MAXDNAME            128 /* maximum presentation domain name */
#define LINK_MAX_ENTRIES    81920
#define METRIC_ENTRIES      8192

#define F_FORWARD   (1u<<3)
#define F_SERVER    (1u<<18)
#define F_QUERY     (1u<<19)

#define DNS_DEBUG(fmt, ...) DEBUG("[DNSPROBE] " fmt, ##__VA_ARGS__)
#define DNS_INFO(fmt, ...) INFO("[DNSPROBE] " fmt, ##__VA_ARGS__)
#define DNS_WARN(fmt, ...) WARN("[DNSPROBE] " fmt, ##__VA_ARGS__)
#define DNS_ERROR(fmt, ...) ERROR("[DNSPROBE] " fmt, ##__VA_ARGS__)

struct sockaddr {
    unsigned short  sa_family;
    char            sa_data[14];
};

struct sockaddr_in {
    unsigned short  sin_family;
    unsigned short  sin_port;
    unsigned int    sin4_addr;
    unsigned char   pad[8];
};

struct sockaddr_in6 {
    unsigned short  sin_family;
    unsigned short  sin_port;
    unsigned int    sin_flowinfo;
    unsigned char   sin6_addr[IP6_LEN];
    unsigned int    sin6_scope_id;
};

union mysockaddr {
    struct sockaddr     sa;
    struct sockaddr_in  in;
    struct sockaddr_in6 in6;
};

union all_addr {
    unsigned int    addr4;
    unsigned char   addr6[IP6_LEN];
};

struct ip {
    union {
        unsigned int    ip4;
        unsigned char   ip6[IP6_LEN];
    };
};

struct server {
    union mysockaddr    addr;
    union mysockaddr    source_addr;
    char                interface[20];
    unsigned int        ifindex;
};

struct frec {
    char            temp1[72];
    struct server   *sentto;
};

struct link_key {
    struct ip       c_addr;
    struct ip       dns_addr;
    unsigned short  c_port;
    unsigned short  family;
};

struct link_value {
    unsigned int    pid;
    char            comm[TASK_COMM_LEN];
    char            dname[MAXDNAME];
};

struct collect_key {
    struct ip       c_addr;
    struct ip       dns_addr;
    unsigned short  family;
};

struct collect_value {
    unsigned int    link_count;
    unsigned int    pid;
    char            comm[TASK_COMM_LEN];
};

#endif /* __TRACE_DNSMASQ__H */