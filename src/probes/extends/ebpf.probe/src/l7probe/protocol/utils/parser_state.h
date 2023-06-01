/*******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhaoguolin
 * Create: 2023-04-15
 * Description:
 ******************************************************************************/

#ifndef __PARSER_STATE_H__
#define __PARSER_STATE_H__

#pragma once

/**
 * The status of a single parse.
 */
typedef enum parse_state_t {
    // Parse succeeded. Raw data of buffer is consumed.
    STATE_SUCCESS = 0,

    // Parse failed. Raw data of buffer is not consumed. Output is invalid.
    STATE_INVALID,

    // Parse is partial. Raw data of buffer is partially consumed. The parsed output is not fully.
    STATE_NEEDS_MORE_DATA,

    // Parse succeeded. Raw data of buffer is consumed, but the output is ignored.
    STATE_IGNORE,

    // End of stream.
    // Parse succeeded. Row data of buffer is consumed, and output is valid.
    // Parser should stop parsing.
    STATE_EOS,

    STATE_NOT_FOUND,

    STATE_UNKNOWN
} parse_state_t;

#endif

