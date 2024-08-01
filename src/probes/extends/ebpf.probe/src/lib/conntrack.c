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
 * Author: luzhihao
 * Create: 2023-08-16
 * Description: conntrack module
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "conntrack.h"

struct tcp_conntrack_s {
    char *src, *dst;
    char *reply_src, *reply_dst;
    int sport, dport;
    int reply_sport, reply_dport;
};

struct sock_addr_s {
    union {
        struct in_addr addr;
        struct in6_addr addr6;
    };
};

static void __free_conntrack_tcp(struct tcp_conntrack_s *conn_tcp)
{
    if (conn_tcp == NULL) {
        return;
    }

    if (conn_tcp->src) {
        free(conn_tcp->src);
    }
    if (conn_tcp->dst) {
        free(conn_tcp->dst);
    }
    if (conn_tcp->reply_src) {
        free(conn_tcp->reply_src);
    }
    if (conn_tcp->reply_dst) {
        free(conn_tcp->reply_dst);
    }
    free(conn_tcp);
    return;
}

static int __get_sub_str(const char *s, const char* start, const char *end,
                                 char* sub_str_buf, unsigned int buf_len)
{
    const char *p2, *p1;
    int len;

    if (s == NULL)
        return -1;

    // Point to end, if no terminator is specified
    if (end == NULL) {
        p2 = s + strlen(s);
    } else {
        p2 = strstr(s, end);
        if (p2 == NULL)
            return -1;
    }

    // Point to start, if no start character is specified
    if (start == NULL) {
        p1 = s;
    } else {
        p1 = strstr(s, start);
        if (p1 == NULL)
            return -1;

        p1 += strlen(start);
    }

    len = (int)(p2 - p1);
    if ((len <= 0) || (len >= buf_len))
        return -1;

    (void)memcpy(sub_str_buf, p1, len);
    sub_str_buf[len] = 0;
    return 0;
}

static struct tcp_conntrack_s *parse_conntrack_tcp(const char *s)
{
    char *p;
    char sub_str[INET6_ADDRSTRLEN];
    struct tcp_conntrack_s* conn_tcp = NULL;

    conn_tcp = (struct tcp_conntrack_s *)malloc(sizeof(struct tcp_conntrack_s));
    if (conn_tcp == NULL) {
        goto err;
    }
    memset(conn_tcp, 0, sizeof(struct tcp_conntrack_s));

    // parse conntrack tcp src ip address
    sub_str[0] = 0;
    if (__get_sub_str((const char *)s, "src=", " ", sub_str, INET6_ADDRSTRLEN)) {
        goto err;
    }
    conn_tcp->src = strdup((const char *)sub_str);

    // parse conntrack tcp dst ip address
    p = strstr((const char *)s, "dst=");
    if (p == NULL) {
        goto err;
    }
    sub_str[0] = 0;
    if (__get_sub_str((const char *)p, "dst=", " ", sub_str, INET6_ADDRSTRLEN)) {
        goto err;
    }
    conn_tcp->dst = strdup((const char *)sub_str);

    // parse conntrack tcp src port
    p = strstr((const char *)p, "sport=");
    if (p == NULL) {
        goto err;
    }
    sub_str[0] = 0;
    if (__get_sub_str((const char *)p, "sport=", " ", sub_str, INET6_ADDRSTRLEN)) {
        goto err;
    }
    conn_tcp->sport = strtol(sub_str, NULL, 10);

    // parse conntrack tcp dst port
    p = strstr((const char *)p, "dport=");
    if (p == NULL) {
        goto err;
    }
    sub_str[0] = 0;
    if (__get_sub_str((const char *)p, "dport=", " ", sub_str, INET6_ADDRSTRLEN)) {
        goto err;
    }
    conn_tcp->dport = strtol(sub_str, NULL, 10);

    // parse conntrack tcp reply src ip address
    p = strstr((const char *)p, "src=");
    if (p == NULL) {
        goto err;
    }
    sub_str[0] = 0;
    if (__get_sub_str((const char *)p, "src=", " ", sub_str, INET6_ADDRSTRLEN)) {
        goto err;
    }
    conn_tcp->reply_src = strdup((const char *)sub_str);

    // parse conntrack tcp reply dst ip address
    p = strstr((const char *)p, "dst=");
    if (p == NULL) {
        goto err;
    }
    sub_str[0] = 0;
    if (__get_sub_str((const char *)p, "dst=", " ", sub_str, INET6_ADDRSTRLEN)) {
        goto err;
    }
    conn_tcp->reply_dst = strdup((const char *)sub_str);

    // parse conntrack tcp reply src port
    p = strstr((const char *)p, "sport=");
    if (p == NULL) {
        goto err;
    }
    sub_str[0] = 0;
    if (__get_sub_str((const char *)p, "sport=", " ", sub_str, INET6_ADDRSTRLEN)) {
        goto err;
    }
    conn_tcp->reply_sport = strtol(sub_str, NULL, 10);

    // parse conntrack tcp reply dst port
    p = strstr((const char *)p, "dport=");
    if (p == NULL) {
        goto err;
    }
    sub_str[0] = 0;
    if (__get_sub_str((const char *)p, "dport=", " ", sub_str, INET6_ADDRSTRLEN)) {
        goto err;
    }
    conn_tcp->reply_dport = strtol(sub_str, NULL, 10);

    return conn_tcp;

err:
    __free_conntrack_tcp(conn_tcp);
    return NULL;
}

static int __dnat_op(const struct tcp_conntrack_s *conn_track, struct tcp_connect_s *connect)
{
    struct sock_addr_s src_addr, dst_addr, nat_dst_addr;

    if (inet_pton(connect->family, conn_track->src, (void *)&src_addr) != 1) {
        return -1;
    }

    if (inet_pton(connect->family, conn_track->dst, (void *)&dst_addr) != 1) {
        return -1;
    }

    if (memcmp(&(connect->cip_addr), &src_addr, (connect->family == AF_INET) ? IP_LEN : IP6_LEN) != 0) {
        return -1;
    }

    if (memcmp(&(connect->sip_addr), &dst_addr, (connect->family == AF_INET) ? IP_LEN : IP6_LEN) != 0) {
        return -1;
    }

    if (connect->c_port != conn_track->sport) {
        return -1;
    }

    if (connect->s_port != conn_track->dport) {
        return -1;
    }

    if (inet_pton(connect->family, conn_track->reply_src, (void *)&nat_dst_addr) != 1) {
        return -1;
    }

    if (connect->family == AF_INET) {
        connect->sip_addr.s_ip = nat_dst_addr.addr.s_addr;
    } else {
        memcpy(connect->sip_addr.s_ip6, &nat_dst_addr, IP6_LEN);
    }

    connect->s_port = conn_track->reply_sport;

    return 0;
}

#define CONNTRACK_DNAT_CMD  "conntrack -L -s %s -d %s -g -p tcp | grep ESTABLISHED"
int get_cluster_ip_backend(struct tcp_connect_s *connect, int *transform)
{
    int ret = 0;
    FILE *f;
    char cip[IP6_LEN], sip[IP6_LEN];
    struct tcp_conntrack_s *conntrack;
    char line[LINE_BUF_LEN];
    char command[COMMAND_LEN];

    *transform = ADDR_TRANSFORM_NONE;
    // Only transform Kubernetes cluster IP backend for the client TCP connection.
    if (connect->role == 0) {
        return 0;
    }

    cip[0] = 0;
    if (inet_ntop(connect->family, (const void *)&(connect->cip_addr), cip, IP6_LEN) == NULL) {
        ERROR("[CLUSTERIP] inet_ntop failed for src ip\n");
        return -1;
    }

    sip[0] = 0;
    if (inet_ntop(connect->family, (const void *)&(connect->sip_addr), sip, IP6_LEN) == NULL) {
        ERROR("[CLUSTERIP] inet_ntop failed for dst ip\n");
        return -1;
    }

    command[0] = 0;
    (void)snprintf(command, COMMAND_LEN, CONNTRACK_DNAT_CMD, cip, sip);

    // No net namespace switch is required.
    // K8S cluster IP conntrack entries are deployed in the node namespace.
    DEBUG("[CLUSTERIP] Begin to parse conntrack info:famliy(%u), src(%s:%u), dst(%s:%u)\n", connect->family, cip, connect->c_port, sip, connect->s_port);
    f = popen(command, "r");
    if (f == NULL) {
        return -1;
    }

    while (feof(f) == 0) {
        line[0] = 0;
        if (fgets(line, LINE_BUF_LEN, f) == NULL) {
            break;
        }

        conntrack = parse_conntrack_tcp((const char *)line);
        if (conntrack == NULL) {
            DEBUG("[CLUSTERIP] failed to parse conntrack info: %s\n", line);
            continue;
        }

        ret = __dnat_op((const struct tcp_conntrack_s *)conntrack, connect);
        if (ret == 0) {
            *transform = ADDR_TRANSFORM_SERVER;
            __free_conntrack_tcp(conntrack);
            break;
        }

        ret = 0;
        __free_conntrack_tcp(conntrack);
    }
    (void)pclose(f);
    return ret;
}

