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
 * Author: eank
 * Create: 2023-04-20
 * Description:
 ******************************************************************************/
#ifndef __HTTP_PARSER_H__
#define __HTTP_PARSER_H__

#pragma once

#include "../../common/protocol_common.h"
#include "../model/http_msg_format.h"
#include "../../../include/l7.h"
#include "http_parse_wrapper.h"

// 定义DCHECK_LE函数，用于检查x<=y，下面EQ和GE同理
#define DCHECK_LE(x, y) assert((x) <= (y))
#define DCHECK_EQ(x, y) assert((x) == (y))
#define DCHECK_GE(x, y) assert((x) >= (y))
// note: pixie中定义这个宏从环境变量中获取值，默认使用1024，PX_STIRLING_HTTP_BODY_LIMIT_BYTES
#define FLAGS_http_body_limit_bytes 1024

/**
 * Parses a single HTTP message from the input string.
 *
 * @param msg_type
 * @param raw_data
 * @param frame_data
 * @return
 */
parse_state_t http_parse_frame(enum message_type_t msg_type, struct raw_data_s *raw_data, struct frame_data_s **frame_data);

/**
 * Find frame boundary for HTTP raw_data
 *
 * @param msg_type
 * @param raw_data
 * @return
 */
size_t http_find_frame_boundary(enum message_type_t msg_type, struct raw_data_s *raw_data);

#endif // __HTTP_PARSER_H__
