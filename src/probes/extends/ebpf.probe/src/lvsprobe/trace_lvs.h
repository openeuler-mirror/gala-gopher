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
 * Create: 2021-05-24
 * Description: ipvs_probe include file
 ******************************************************************************/
#ifndef __LVSPROBE__H
#define __LVSPROBE__H

#define IPPROTO_IP      0   /* Dummy protocol for TCP */
#define IPPROTO_TCP     6   /* Transmission Control Protocol */
#define IPPROTO_UDP     17  /* User Datagram Protocol */
#define IPPROTO_IPV6    41  /* IPv6-in-IPv4 tunnelling */

#define IPVS_MAX_ENTRIES      8192
#define IPVS_MIN_ENTRIES      1024
#define IPVS_FLAGS_KEY_VAL    0x10  /* be used to lvs_flag_map as key */

#define IP_VS_TCP_S_CLOSE   6

#define IP_VS_CONN_F_FWD_MASK   0x0007  /* mask for the fwd methods */
#define IP_VS_CONN_F_LOCALNODE  0x0001  /* local node */
#define IP_VS_CONN_FULLNAT      0x0005  /* full nat */

#define LVS_DEBUG(fmt, ...) DEBUG("[LVSPROBE] " fmt, ##__VA_ARGS__)
#define LVS_INFO(fmt, ...) INFO("[LVSPROBE] " fmt, ##__VA_ARGS__)
#define LVS_WARN(fmt, ...) WARN("[LVSPROBE] " fmt, ##__VA_ARGS__)
#define LVS_ERROR(fmt, ...) ERROR("[LVSPROBE] " fmt, ##__VA_ARGS__)

struct ip {
    union {
        __u32 in;
        unsigned char in6[IP6_LEN];
    };
};

struct link_key {
    struct ip   c_addr;
    struct ip   v_addr;
    struct ip   s_addr;
    __u16       c_port;
    __u16       v_port;
    __u16       s_port;
    __u16       family;
};

struct link_value {
    __u16       l_port;
    struct ip   l_addr;
    __u16       protocol;
    __u16       state;
    __u64       link_count;
};

struct collect_key {
    struct ip   c_addr;
    struct ip   v_addr;
    struct ip   s_addr;
    struct ip   l_addr;
    __u16       c_port;
    __u16       v_port;
    __u16       s_port;
    __u16       l_port;
    __u16       family;
};

struct collect_value {
    __u16  protocol;
    __u64  link_count;
};

#ifdef BPF_PROG_KERN
struct ip_vs_conn_fnat {
    char temp1[16];
    __u16 cport;
    __u16 dport;
    __u16 vport;
    __u16 lport;
    __u16 af;                  /* address family */
    union nf_inet_addr caddr; /* client address */
    union nf_inet_addr vaddr; /* virtual address */
    union nf_inet_addr daddr; /* destination address */
    union nf_inet_addr laddr; /* local address */
    __u32 flags;      /* status flags */
    __u16 protocol;   /* Which protocol (TCP/UDP) */
    __u16 daf;
    __u64 temp2;
    __u64 temp3;
    struct timer_list timer; /* Expiration timer */
};

struct ip_vs_conn {
    struct hlist_node c_list;
    __be16 cport;
    __be16 dport;
    __be16 vport;
    __u16 af;
    union nf_inet_addr caddr;
    union nf_inet_addr vaddr;
    union nf_inet_addr daddr;
    volatile __u32 flags;
    __u16 protocol;
    __u16 daf;
    __u64 temp1;
    __u64 temp2;
    struct timer_list timer;
};

struct ip_vs_dest {
    struct list_head n_list;
    struct hlist_node d_list;
    __u16 af;
    __be16 port;
    union nf_inet_addr addr;
    volatile unsigned int flags;
    atomic_t conn_flags;
};
#endif /* BPF_PROG_KERN */

#endif /* __LVSPROBE__H */
