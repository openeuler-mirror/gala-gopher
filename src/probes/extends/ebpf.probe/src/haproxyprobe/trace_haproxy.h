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
 * Create: 2021-06-08
 * Description: haproxy_probe include file
 ******************************************************************************/
#ifndef __TRACE_HAPROXY__H
#define __TRACE_HAPROXY__H

#define LINK_MAX_ENTRIES    81920
#define METRIC_ENTRIES      8192

#define	SIGINT      2   /* Interactive attention signal.  */
#define	SIGTERM     15  /* Termination request.  */

#define SI_ST_EST   8   /* connection established (resource exists) */
#define SI_ST_CLO   10  /* stream intf closed, might not existing anymore. Buffers shut. */

#define SS_PADSIZE \
  (128 - sizeof(unsigned short int) - sizeof (unsigned long int))

#define HAP_DEBUG(fmt, ...) DEBUG("[HAPPROBE] " fmt, ##__VA_ARGS__)
#define HAP_INFO(fmt, ...) INFO("[HAPPROBE] " fmt, ##__VA_ARGS__)
#define HAP_WARN(fmt, ...) WARN("[HAPPROBE] " fmt, ##__VA_ARGS__)
#define HAP_ERROR(fmt, ...) ERROR("[HAPPROBE] " fmt, ##__VA_ARGS__)

struct sockaddr_in {
    unsigned short  sin_family;
    unsigned short  sin_port;
    unsigned int    sin_addr;
    unsigned char   pad[8];
};

struct sockaddr_in6 {
    unsigned short  sin_family;
    unsigned short  sin_port;
    unsigned int    sin_flowinfo;
    unsigned char   sin6_addr[IP6_LEN];
    unsigned int    sin6_scope_id;
};

struct ssockaddr_s {
    unsigned short  ss_family;
    unsigned char   ss_padding[SS_PADSIZE];
    unsigned long   ss_align;
};

/* object types : these ones take the same space as a char */
enum obj_type {
    OBJ_TYPE_NONE = 0,     /* pointer is NULL by definition */
    OBJ_TYPE_LISTENER,     /* object is a struct listener */
    OBJ_TYPE_PROXY,        /* object is a struct proxy */
    OBJ_TYPE_SERVER,       /* object is a struct server */
    OBJ_TYPE_APPLET,       /* object is a struct applet */
    OBJ_TYPE_APPCTX,       /* object is a struct appctx */
    OBJ_TYPE_CONN,         /* object is a struct connection xxx */
    OBJ_TYPE_SRVRQ,        /* object is a struct dns_srvrq */
    OBJ_TYPE_CS,           /* object is a struct conn_stream */
    OBJ_TYPE_STREAM,       /* object is a struct stream */
    OBJ_TYPE_CHECK,        /* object is a struct check */
    OBJ_TYPE_ENTRIES       /* last one : number of entries */
} __attribute__((packed));

/* values for proxy->mode */
enum pr_mode {
    PR_MODE_TCP = 0,
    PR_MODE_HTTP,
    PR_MODE_CLI,
    PR_MODE_SYSLOG,
    PR_MODE_PEERS,
    PR_MODES
} __attribute__((packed));

struct proxy {
    char temp1[2];
    enum pr_mode mode;
    char temp2[1];
};

struct receiver {
    char    temp[56];
    struct ssockaddr_s  addr;
};

struct ha_listener {
    char    temp[144];
    struct receiver rx;
};

struct session {
    struct proxy        *fe;
    struct ha_listener  *listener;
    enum obj_type       *origin;
};

struct connection_s {
    enum obj_type obj_type;
    char temp1[3];
    char temp2[48];
    enum obj_type *target;
    char temp3[64];
    struct ssockaddr_s *src;
    struct ssockaddr_s *dst;
    char temp4[48];
};

struct server {
    char temp[3456];
};

struct stream_s {
    char temp1[8];
    enum obj_type *target;
    char temp2[200];
    struct session *sess;
    struct server *srv_conn;
    char temp3[134];
    enum obj_type obj_type;
    char temp4[122];
    struct ssockaddr_s *target_addr;
};

struct ip {
    union {
        unsigned int    ip4;
        unsigned char   ip6[IP6_LEN];
    };
};

struct link_key {
    struct ip       c_addr;
    struct ip       s_addr;
    struct ip       p_addr;
    unsigned short  c_port;
    unsigned short  s_port;
    unsigned short  p_port;
};

struct link_value {
    unsigned int    pid;
    char    comm[TASK_COMM_LEN];
    unsigned short  family;
    unsigned short  state;
    char            type;
};

struct collect_key {
    struct ip       c_addr;
    struct ip       p_addr;
    struct ip       s_addr;
    unsigned short  p_port;
    unsigned short  s_port;
};

struct collect_value {
    unsigned int        pid;
    char        comm[TASK_COMM_LEN];
    unsigned short      family;
    unsigned short      protocol;
    unsigned long long  link_count;
};

#endif /* __TRACE_HAPROXY__H */