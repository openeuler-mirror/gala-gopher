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
 * Create: 2023-04-04
 * Description:
 ******************************************************************************/

#ifndef __PROTOCOL_PARSER_H__
#define __PROTOCOL_PARSER_H__

#pragma once

#include <stddef.h>

#include "../../bpf/l7.h"
#include "../../include/data_stream.h"
#include "../utils/parser_state.h"
#include "../utils/binary_decoder.h"

// todo choose one protocol traits implement
// Protocol traits
#define L7_FRAME_TYPE(protocol) protocol##_FRAME_TYPE
#define L7_RECORD_TYPE(protocol) protocol##_RECORD_TYPE
#define L7_STATE_TYPE(protocol) protocol##_STATE_TYPE

/**
 * Traits of protocol.
 */
struct protocol_traits_s {
    void *record_type;
    void *frame_type;
    void *state_type;
};

/**
 * Record of matching request and response frames.
 */
struct record_data_s {
    void *record;
};

/**
 * Records of matching request and response frames.
 */
#define __RECORD_BUF_SIZE 1024
struct record_buf_s {
    struct record_data_s *records[__RECORD_BUF_SIZE];
    size_t current_pos;
    size_t record_buf_size;
    size_t err_count;
};

/**
 * The position information of the parsed frame.
 */
struct position_info_s {
    size_t start_pos;
    size_t end_pos;
};

/**
 * Parse results.
 */
struct parse_res_s {
    struct position_info_s *frame_pos[__RECORD_BUF_SIZE];
    enum parse_state_t parse_state;
    size_t end_pos;
    size_t valid_frame_bytes;
    size_t invalid_frame_count;
};

/**
 * Protocol parser.
 */
//struct protocol_parser_s {
//    /**
//     *
//     * @param msg_type
//     * @param raw_data
//     * @param start_pos
//     * @return
//     */
//    size_t *(find_frame_boundary)(message_type_t msg_type, struct raw_data_s *raw_data, size_t start_pos);
//
//    /**
//     *
//     * @param msg_type
//     * @param raw_data
//     * @param state_type
//     * @return
//     */
//    parse_state_t *(parse_frame)(message_type_t msg_type, struct raw_data_s *raw_data, void *state_type);
//
//    /**
//     *
//     * @param req_frames
//     * @param rsp_frames
//     * @return
//     */
//    record_buf_s *(match_frames)(frame_buf_s *req_frames, struct frame_buf_s *rsp_frames, void *state_type);
//};

//parse_res_s parse_frames();

#endif
