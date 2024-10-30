/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangshuyuan
 * Create: 2024-10-08
 * Description:
 ******************************************************************************/
#ifndef __MYSQL_PARSER_H__
#define __MYSQL_PARSER_H__

#pragma once

#include "../../include/data_stream.h"

/**
 * Parses a single MySQL message from the input string.
 *
 * @param msg_type
 * @param raw_data
 * @param frame_data
 * @return
 */
parse_state_t mysql_parse_frame(
    enum message_type_t msg_type, struct raw_data_s *raw_data, struct frame_data_s **frame_data);

/**
 * Find frame boundary for MySQL raw_data
 *
 * @param msg_type
 * @param raw_data
 * @return
 */
size_t mysql_find_frame_boundary(enum message_type_t msg_type, struct raw_data_s *raw_data);

#endif