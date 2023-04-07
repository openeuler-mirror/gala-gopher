/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: luzhihao
 * Create: 2023-02-22
 * Description: data stream define
 ******************************************************************************/
#ifndef __DATA_STREAM_H__
#define __DATA_STREAM_H__

#pragma once

#include "include/l7.h"

struct frame_data_s {
    enum message_type_t msg_type;
    void *frame;
    u64 timestamp_ns;
};


/*
  Used to cache L7 message frame from protocol parser
*/
#define __FRAME_BUF_SIZE   (1024)
struct frame_buf_s { 
    struct frame_data_s *frames[__FRAME_BUF_SIZE];
    size_t frame_buf_size;
};

/*
  Used to cache raw data from bpf
*/
struct raw_data_s {
    u64 timestamp_ns;
    char data[0];
};

/*
  Used to cache continuity data from bpf
*/
#define __RAW_BUF_SIZE   (50)
struct raw_buf_s {
    size_t raw_buf_size;
    struct raw_data_s* raw_buf[__RAW_BUF_SIZE];
};

/*
  Used to Manages data(raw and parsed) in tx OR rx direction on a connection.
*/
struct data_stream_s {
    void *proto_parse_ctx;      // Keep the context of protocol parser.
    struct raw_buf_s raw_bufs;
    struct frame_buf_s frame_bufs;

    enum proto_type_t type;
};

int parse_frames(struct data_stream_s *data_stream);

#endif
