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
 * Create: 2021-06-22
 * Description: nsprobe include file
 ******************************************************************************/
#ifndef __QDISC__H
#define __QDISC__H

struct qdisc_stats {
    u32 qlen;                               // Length of queue
    u32 backlog;                            // Length of backlog
    u32 drops;                              // Drops count, counter type
    u32 requeues;                           // Requeues count, counter type
    u32 overlimits;                         // Over limit count, counter type
};

struct qdisc {
    u64 ts;                                 // Period of stats
    u32 handle;
    u32 ifindex;
    char kind[IFNAMSIZ];                    // kind of qdisc
    char dev_name[IFNAMSIZ];                // Name device, which qdisc belong to.
    u32 netns_id;                           // ID of net namespace
    struct qdisc_stats egress;              // Statistic of egress
};

#endif
