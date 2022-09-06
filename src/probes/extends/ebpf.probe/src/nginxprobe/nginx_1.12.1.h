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
 * Description: nginx v1.12.1 include file
 ******************************************************************************/
#ifndef __NGX_VERSION_1_12_1_H__
#define __NGX_VERSION_1_12_1_H__

struct sockaddr {
    unsigned short sa_family;
    char sa_data[14];
};

struct in_addr {
    __be32 s_addr;
};

struct sockaddr_in {
    unsigned short sin_family; /* Address family		*/
    __be16 sin_port;           /* Port number			*/
    struct in_addr sin_addr;   /* Internet address		*/

    /* Pad to size of `struct sockaddr'. */
    unsigned char __pad[8];
};

struct in6_addr {
    union {
        __u8 u6_addr8[16];
#if __UAPI_DEF_IN6_ADDR_ALT
        __be16 u6_addr16[8];
        __be32 u6_addr32[4];
#endif
    } in6_u;
#define s6_addr in6_u.u6_addr8
#if __UAPI_DEF_IN6_ADDR_ALT
#define s6_addr16 in6_u.u6_addr16
#define s6_addr32 in6_u.u6_addr32
#endif
};

struct sockaddr_in6 {
    unsigned short int sin6_family; /* AF_INET6 */
    __be16 sin6_port;               /* Transport layer port # */
    __be32 sin6_flowinfo;           /* IPv6 flow information */
    struct in6_addr sin6_addr;      /* IPv6 address */
    __u32 sin6_scope_id;            /* scope id (new in RFC2553) */
};

typedef struct {
    unsigned int len;
    unsigned char data[32];
} ngx_str_addr_t;

typedef struct {
    unsigned int len;
    unsigned char *data;
} ngx_str_t;

struct ngx_connection_s {
    void *data;
    void *read;  /* ngx_event_t *read */
    void *write; /* ngx_event_t *write */
    int fd;
    unsigned char temp1[68];
    int type;                   // 96
    struct sockaddr *sockaddr;  // 104
    unsigned int socklen;          // 112
    unsigned char temp2[40];
    struct sockaddr *local_sockaddr;  // 160
    unsigned int local_socklen;          // 168
    unsigned char temp3[48];
};

struct ngx_peer_connection_s {
    struct ngx_connection_s *connection;
    struct sockaddr *sockaddr;
    unsigned int socklen;
    ngx_str_t *name;
    unsigned char temp[80];
};

struct ngx_stream_upstream_s {
    struct ngx_peer_connection_s peer;
    unsigned char temp[272];
};

struct ngx_stream_session_s { /* 144 */
    unsigned char temp1[8];
    struct ngx_connection_s *connection;
    unsigned char temp2[56];
    struct ngx_stream_upstream_s *upstream; /* 72 */
    unsigned char temp3[64];
};

struct val_t {
    unsigned int pid;
    unsigned int type;
    unsigned char c_addr[14];
    unsigned char c_family[2];
    unsigned char l_addr[14];
    unsigned char l_family[2];
    unsigned char p_addr[14];
    unsigned char p_family[2];
    unsigned char s_addr[32];
};

typedef struct ngx_connection_s ngx_connection_t;

typedef struct ngx_peer_connection_s ngx_peer_connection_t;

struct ngx_event_s {
    void *data;
};
typedef void (*ngx_http_upstream_handler_pt)(void *r, void *u);

struct ngx_http_upstream_s {
    ngx_http_upstream_handler_pt read_event_handler;
    ngx_http_upstream_handler_pt write_event_handler;

    ngx_peer_connection_t peer;
};

typedef void (*ngx_http_event_handler_pt)(void *r);
struct ngx_http_request_s {
    __u32 signature; /* "HTTP" */

    ngx_connection_t *connection;

    void **ctx;
    void **main_conf;
    void **srv_conf;
    void **loc_conf;

    ngx_http_event_handler_pt read_event_handler;
    ngx_http_event_handler_pt write_event_handler;

    void *cache;

    struct ngx_http_upstream_s *upstream;
};
#endif