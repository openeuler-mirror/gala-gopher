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

#ifndef __PGSQL_PARSER_H__
#define __PGSQL_PARSER_H__

#pragma once

#include "../../include/data_stream.h"
#include "pgsql_msg_format.h"

size_t pgsql_find_frame_boundary(struct raw_data_s *raw_data);

parse_state_t pgsql_parse_frame(struct raw_data_s *raw_data, struct frame_data_s **frame_data);

parse_state_t pgsql_parse_regular_msg(struct raw_data_s *raw_data, struct pgsql_regular_msg_s *msg);

parse_state_t pgsql_parse_startup_msg(struct raw_data_s *raw_data, struct pgsql_startup_msg_s *msg);

parse_state_t pgsql_parse_cmd_complete(struct pgsql_regular_msg_s *msg, struct pgsql_cmd_complete_s *cmd_complete);

parse_state_t pgsql_parse_data_row(struct pgsql_regular_msg_s *msg, struct pgsql_data_row_s *data_row);

parse_state_t pgsql_parse_bind_req(struct pgsql_regular_msg_s *msg, struct pgsql_bind_req_s *bind_req);

parse_state_t pgsql_parse_param_desc(struct pgsql_regular_msg_s *msg, struct pgsql_param_description_s *param_desc);

parse_state_t pgsql_parse_parse_msg(struct pgsql_regular_msg_s *msg, struct pgsql_parse_req_s *parse_req);

parse_state_t pgsql_parse_row_desc(struct pgsql_regular_msg_s *msg, struct pgsql_row_description_s *row_desc);

parse_state_t pgsql_parse_err_resp(struct pgsql_regular_msg_s *msg, struct pgsql_err_resp_s *err_resp);

parse_state_t pgsql_parse_describe(struct pgsql_regular_msg_s *msg, struct pgsql_describe_req_s *desc_req);

#endif
