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
 * Description: wrap the common decoder methods for kafka.
 *
 ******************************************************************************/


#ifndef __KAFKA_DECODER_H__
#define __KAFKA_DECODER_H__
#pragma once

#include "../../include/data_stream.h"
#include "kafka_msg_format.h"

parse_state_t decode_tag_item(struct raw_data_s *data_stream_buf);

parse_state_t decode_tags(struct raw_data_s *data_stream_buf, enum kafka_api api, int16_t version);

parse_state_t decode_req_header(struct raw_data_s *data_stream_buf, struct kafka_request_s *req);

parse_state_t decode_resp_header(struct raw_data_s *data_stream_buf, struct kafka_response_s *resp,
                                 enum kafka_api api, int16_t api_version);

#endif