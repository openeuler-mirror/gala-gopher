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
 * Author: wo_cow
 * Create: 2022-06-23
 * Description: bps bpf header
 ******************************************************************************/
#ifndef __BPS__H
#define __BPS__H

#pragma once

#define EGRESS_MAP_PATH "/sys/fs/bpf/tc/globals/tc_bps_egress"

struct bps_msg_s {
    __u64 cg_classid;
    unsigned long long bps;
};

struct egress_bandwidth_s {
    unsigned long long total_tx_bytes;
    __u64 ts;
};

#define BPS_RET_ERR (-1)
#define BPS_RET_OK 0


#endif /* __BPS__H */
