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
#ifndef __HTTP_MSG_FORMAT_H__
#define __HTTP_MSG_FORMAT_H__

#pragma once

#include "multiple_map.h"
#include "../../../include/data_stream.h"

extern char KEY_CONTENT_ENCODING[17];
extern char KEY_CONTENT_LENGTH[15];
extern char KEY_CONTENT_TYPE[13];
extern char KEY_TRANSFER_ENCODING[18];
extern char KEY_UPGRADE[8];

/**
 * Http message structure, req or resp use the same
 */
typedef struct http_message {
    enum message_type_t type;
    u64 timestamp_ns;

    int minor_version;
    http_headers_map *headers;  // no used

    char *req_method;
    char *req_path;

    int resp_status;
    char *resp_message;

    char *body;
    size_t body_len;    // the length of body in raw_data
    size_t body_size;   // the real length of body, it is not the same as body_len in some scenario such as chunked

    // The number of bytes in the HTTP header, used in ByteSize(),
    // as an approximation of the size of the non-body fields.
    size_t headers_byte_size;
} http_message;

http_message *init_http_msg(void);

void free_http_msg(http_message *http_msg);

/**
 * Http Record structure, contains request and response
 */
typedef struct http_record {
    http_message *req;
    http_message *resp;
} http_record;

http_record *init_http_record(void);

void free_http_record(http_record *http_record);

#endif // __HTTP_MSG_FORMAT_H__
