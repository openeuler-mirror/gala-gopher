/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2024. All rights reserved.
 */

#ifndef __TOA__H
#define __TOA__H

#include <bpf/bpf_endian.h>
#include "bpf.h"
#include "vmlinux.h"

#define CONFIG_IP_VS_TOA_IPV6

#define TOA_DBG_FLAG        0
#define TCPOPT_TOA          254
#define TCPOPT_TOA_V6       253
#define TCPOLEN_TOA         8        /* |opcode|size|ip+port| = 1 + 1 + 6  */
#define TCPOLEN_TOA_V6      20       /* |opcode|size|ip+port| = 1 + 1 + 18 */
#define TOA_IP6_TAB_BITS    12
#define TOA_IP6_TAB_SIZE    (1 << TOA_IP6_TAB_BITS)
#define TOA_IP6_TAB_MASK    (TOA_IP6_TAB_SIZE - 1)
#define TCPOPT_EOL          0
#define TCPOPT_NOP          1
#define ETH_P_IP            0x0800
#define ETH_P_IPV6          0x86DD

struct toa_opt {
    u8 opcode;
    u8 opsize;
    u16 port;
    u32 ip;
};

struct toa_opt_v6 {
    u8 opcode;
    u8 opsize;
    u16 port;
    u32 ip6[4];
};

struct toa_v6_entry {
    struct list_head list;
    struct sock *sk;
    struct toa_opt_v6 toa_data;
};

struct toa_ip6_list_head {
    struct list_head toa_v6_head;
    spinlock_t lock;
};

enum {
    SYN_RECV_SOCK_TOA_CNT = 1,
    SYN_RECV_SOCK_NO_TOA_CNT,
    GETNAME_TOA_OK_CNT,
    GETNAME_TOA_MISMATCH_CNT,
    GETNAME_TOA_BYPASS_CNT,
    GETNAME_TOA_EMPTY_CNT,
    TOA_V6_FREE_CNT,
    TOA_V6_MALLOC_CNT,
    TOA_STATS_LAST
};

enum toa_type {
    TOA_NOT,
    TOA_IPV4,
    TOA_IPV6
};

#define TOA_STAT_END {    \
    NULL,        \
    0,        \
}

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

#define TOA_INC_STATS(stats, field)     \
    (per_cpu_ptr(stats, smp_processor_id())->counter[field]++)

#define TOA_NIP6_FMT "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"

static __always_inline uint16_t ntohs_toa(uint16_t netshort)
{
    uint16_t hostshort;
    uint8_t *p = (uint8_t * ) & netshort;

    hostshort = ((uint16_t) p[0] << 8) | (uint16_t) p[1];
    return hostshort;
}

#define TOA_NIP6(addr) \
    ntohs_toa((addr).s6_addr16[0]), \
    ntohs_toa((addr).s6_addr16[1]), \
    ntohs_toa((addr).s6_addr16[2]), \
    ntohs_toa((addr).s6_addr16[3]), \
    ntohs_toa((addr).s6_addr16[4]), \
    ntohs_toa((addr).s6_addr16[5]), \
    ntohs_toa((addr).s6_addr16[6]), \
    ntohs_toa((addr).s6_addr16[7])


#endif
