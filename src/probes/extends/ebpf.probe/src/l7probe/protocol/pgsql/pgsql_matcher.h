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

#ifndef __PGSQL_MATCHER_H__
#define __PGSQL_MATCHER_H__

#pragma once

#include "../common/protocol_parser.h"
#include "pgsql_msg_format.h"

struct record_buf_s *
pgsql_match_frames(struct frame_buf_s *req_frames, struct frame_buf_s *rsp_frames, void *state_type);

parse_state_t
pgsql_handle_query(struct pgsql_regular_msg_s *msg, struct frame_buf_s *req_frames, struct frame_buf_s *rsp_frames,
                   struct pgsql_query_req_resp_s *req_rsp);

parse_state_t pgsql_fill_query_resp(struct frame_buf_s *rsp_frames, struct pgsql_query_resp_s *query_rsp);

parse_state_t
pgsql_handle_parse(struct pgsql_regular_msg_s *msg, struct frame_buf_s *req_frames, struct frame_buf_s *rsp_frames,
                   struct pgsql_parse_req_resp_s *req_rsp);

parse_state_t pgsql_fill_stmt_desc_resp(struct frame_buf_s *rsp_frames, struct pgsql_describe_resp_s *desc_rsp);

parse_state_t pgsql_fill_portal_desc_resp(struct frame_buf_s *rsp_frames, struct pgsql_describe_resp_s *desc_rsp);

parse_state_t
pgsql_handle_describe(struct pgsql_regular_msg_s *msg, struct frame_buf_s *req_frames, struct frame_buf_s *rsp_frames,
                      struct pgsql_describe_req_resp_s *req_rsp);

parse_state_t
pgsql_handle_bind(struct pgsql_regular_msg_s *msg, struct frame_buf_s *req_frames, struct frame_buf_s *rsp_frames,
                  struct pgsql_bind_req_resp_s *req_rsp);

parse_state_t
pgsql_handle_execute(struct pgsql_regular_msg_s *msg, struct frame_buf_s *req_frames, struct frame_buf_s *rsp_frames,
                     struct pgsql_execute_req_resp_s *req_rsp);

#endif
