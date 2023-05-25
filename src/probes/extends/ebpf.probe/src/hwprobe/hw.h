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
 * Author: lizhenxing
 * Create: 2023-05-18
 * Description: HW bpf prog
 ******************************************************************************/

#ifndef __HW_PROBE__H
#define __HW_PROBE__H

#pragma once

#define IS_LOAD_PROBE(LOAD_TYPE, PROG_TYPE) (LOAD_TYPE & PROG_TYPE)

#define BPF_F_INDEX_MASK    0xffffffffULL
#define BPF_F_ALL_CPU   BPF_F_INDEX_MASK

#ifndef __PERF_OUT_MAX
#define __PERF_OUT_MAX (64)
#endif

#define __HW_COUNT_MAX      100

#define MAX_MFR_LEN 10
#define DRIVER_NAME_LEN 10
#define ERROR_TYPE_LEN 10
#define ERROR_MSG_LEN 20
#define LABEL_LEN 10
#define DRIVER_DETAIL_LEN 20

struct hw_args_s {
    u64 report_period;      // unit: nanosecond
};

struct nic_entity_s {
    char dev_name[IFNAMSIZ];
    char driver[DRIVER_NAME_LEN];
    int queue_index;
};

struct report_ts_s {
    u64 ts;
};

struct nic_failure_s {
    struct report_ts_s report_ts;
    struct nic_entity_s entity;
    int xmit_timeout_count;
    int carrier_up_count;
    int carrier_down_count;
};

struct nic_evt_s {
    char nic_name[IFNAMSIZ];
    int evt_flags;
};

struct mem_entity_s {
    unsigned int err_type;
    char label[LABEL_LEN];
    char mc_index;
    char top_layer;
    char mid_layer;
};

struct mc_event_s
{
    struct report_ts_s report_ts;
    struct mem_entity_s entity;
    int error_count;
};

#endif
