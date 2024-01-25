/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: algorithmofdish
 * Create: 2023-12-14
 * Description: defination of cpython(version 3.7) structure offsets
 ******************************************************************************/
#include "py_stack.h"

// https://github.com/python/cpython/tree/v3.7.16
struct py_offset py37_offset = {
    .tstate_curr = 1496,
    .state = {
        .frame = 24
    },
    .frame_obj = {
        .f_back = 24,
        .f_code = 32,
        .f_localsplus = 360
    },
    .code_obj = {
        .co_varnames = 64,
        .co_name = 104
    },
    .obj = {
        .obj_type = 8,
        .type_obj_name = 24,
        .tuple_obj_item = 24,
        .var_obj_size = 16,
        .string_data = 48
    }
};