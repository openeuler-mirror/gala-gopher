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
 * Author: shiaigang
 * Create: 2023-06-07
 * Description:
 *
 ******************************************************************************/

#ifndef __KAFKA_PARSER_H__
#define __KAFKA_PARSER_H__

#pragma once

#include "../../include/data_stream.h"
#include "kafka_msg_format.h"

size_t kafka_find_frame_boundary(enum message_type_t msg_type, struct raw_data_s *raw_data);

parse_state_t kafka_parse_frame(enum message_type_t msg_type, struct raw_data_s *raw_data, struct frame_data_s **frame);

#endif
