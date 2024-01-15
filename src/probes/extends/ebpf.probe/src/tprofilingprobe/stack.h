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
#include "py_stack.h"

struct py_raw_trace_s {
    struct py_stack py_stack;
};

struct py_sample {
    u32 cpu_id;             // use to generate python symbol id
    u32 nr_cpus;
    u64 py_symbol_counter;  // use to generate python symbol id
    u64 py_stack_counter;   // use to generate python stack id
    struct py_raw_trace_s event;
};

#endif
