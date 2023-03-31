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
 * Author: Mr.lu
 * Create: 2022-08-18
 * Description: stack defined
 ******************************************************************************/
#ifndef __GOPHER_STACK_H__
#define __GOPHER_STACK_H__

#pragma once

#include "common.h"

#define AGGRE_PERIOD    (1 * 30 * 1000) // 30s
#define TMOUT_PERIOD    (AGGRE_PERIOD / 1000) // Second as unit
#define PROC_CACHE_MAX_COUNT    100    // Cache 100 proc symbols
#define DIV_ROUND_UP(NUM, DEN) ((NUM + DEN - 1) / DEN)

#define MAX_PERCPU_SAMPLE_COUNT     (2 * DIV_ROUND_UP(AGGRE_PERIOD, 10)) // samplePeriod as 10ms

struct convert_data_t {
    u32 whitelist_enable;
    u64 convert_counter;
};

struct stack_pid_s {
    u64 real_start_time;
    int proc_id;
};

struct stack_id_s {
    char comm[TASK_COMM_LEN]; // thread comm
    int user_stack_id;
    int kern_stack_id;
    struct stack_pid_s pid;
};

struct raw_trace_s {
    s64 count;
    struct stack_id_s stack_id;
};

#endif
