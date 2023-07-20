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

#ifndef __KAFKA_MATCHER_H__
#define __KAFKA_MATCHER_H__

#pragma once

#include "../common/protocol_common.h"
#include "kafka_msg_format.h"
#include "hash.h"

struct kafka_correlation_hash_t {
    H_HANDLE;
    int32_t correlation_id;
    struct kafka_frame_s *frame;
};

struct kafka_record_s *
match_req_resp(struct kafka_frame_s *req_frame, struct kafka_frame_s *resp_frame, size_t *error_count);

void kafka_match_frames(struct frame_buf_s *req_frames, struct frame_buf_s *resp_frames, struct record_buf_s *buf);

#endif
