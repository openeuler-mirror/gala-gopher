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
#include "../../../include/l7.h"

extern const char kContentEncoding[17];
extern const char kContentLength[15];
extern const char kContentType[13];
extern const char kTransferEncoding[18];
extern const char kUpgrade[8];

/**
 * Define Message type structure
 */
typedef struct http_message {
    enum message_type_t type;
    uint64_t timestamp_ns;

    int minor_version;
    http_headers_map *headers;

    char *req_method;
    char *req_path;

    int resp_status;
    char *resp_message;

    char *body;
    size_t body_size;

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

/**
 * byte size
 *
 * @param message
 * @return
 */
size_t byte_size(struct http_message *message);

#endif // __HTTP_MSG_FORMAT_H__
