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
#ifndef __MYSQL_MATCHER_H__
#define __MYSQL_MATCHER_H__

#pragma once

#include "mysql_msg_format.h"
// #include "mysql_matcher_wrapper.h"

/**
 * MySQL match frames
 *
 * @param req_frames
 * @param rsp_frames
 * @param record_buf
 * @return
 */
void mysql_match_frames(
    struct frame_buf_s *req_frames, struct frame_buf_s *rsp_frames, struct record_buf_s *record_buf);

#endif