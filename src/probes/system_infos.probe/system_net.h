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
* Author: dowzyx
 * Create: 2022-06-19
 * Description: include file for system_net
 ******************************************************************************/
#ifndef SYSTEM_NET_RPOBE__H
#define SYSTEM_NET_RPOBE__H
#include "ipc.h"
#include "common.h"

#define NET_DEVICE_NAME_SIZE    16
#define MAX_NETDEV_NUM          64

/* the interval of time (@p) is given in second */
#define SPEED_VALUE(m,n,p)      (((double) ((n) - (m))) / 1024 / (p))

typedef struct net_snmp_stat {
    u64 tcp_curr_estab;
    u64 tcp_in_segs;
    u64 tcp_out_segs;
    u64 tcp_retrans_segs;
    u64 tcp_in_errs;
    u64 udp_in_datagrams;
    u64 udp_out_datagrams;
} net_snmp_stat;

typedef struct net_dev_stat {
    char dev_name[NET_DEVICE_NAME_SIZE];
    char net_status;    // 1:UP / 0:DOWN
    u64 rx_bytes;
    u64 rx_packets;
    u64 rx_dropped;
    u64 rx_errs;
    u64 rx_fifo_errs;
    u64 rx_frame_errs;
    u64 rx_compressed;
    u64 rx_multicast;
    u64 tx_packets;
    u64 tx_dropped;
    u64 tx_bytes;
    u64 tx_errs;
    u64 tx_fifo_errs;
    u64 tx_colls;
    u64 tx_carrier;
    u64 tx_compressed;
    u64 tc_sent_drop_count;
    u64 tc_sent_overlimits_count;
    u64 tc_backlog_count;
    u64 tc_ecn_mark;
} net_dev_stat;

int system_tcp_probe(void);
void system_tcp_init(void);
int system_net_probe(struct ipc_body_s *ipc_body);
int system_net_init(void);
void system_net_destroy(void);

#endif
