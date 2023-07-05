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
#include "http_matcher.h"

#define FLAGS_http_response_header_filters = "Content-Type:json,Content-Type:text/Comma-separated strings to specify the substrings should be included for a header. The format looks like <header-1>:<substr-1>,...,<header-n>:<substr-n>. The substrings cannot include comma(s). The filters are conjunctive, therefore the headers can be duplicate. For example, 'Content-Type:json,Content-Type:text' will select a HTTP response with a Content-Type header whose value contains 'json' *or* 'text'."

void pre_process_message(http_message* message)
{
}

void http_match_frames(struct frame_buf_s *req_frames, struct frame_buf_s *resp_frames, struct record_buf_s *record_buf)
{
}