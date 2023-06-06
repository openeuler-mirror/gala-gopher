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
#ifndef GALA_GOPHER_HTTP_MSG_FORMAT_H
#define GALA_GOPHER_HTTP_MSG_FORMAT_H

#pragma once

#include "multiple_map.h"
#include "../../../include/l7.h"

inline constexpr char kContentEncoding[] = "Content-Encoding";
inline constexpr char kContentLength[] = "Content-Length";
inline constexpr char kContentType[] = "Content-Type";
inline constexpr char kTransferEncoding[] = "Transfer-Encoding";
inline constexpr char kUpgrade[] = "Upgrade";

/**
 * Define Message type structure
 */
typedef struct http_message {
    message_type_t type;
    uint64_t timestamp_ns;

    int minor_version;
    http_headers_map headers;

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
    http_message req;
    http_message resp;

    char *dbg_info;
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

/**
 * ToString function of Message structure
 *
 * @param message
 * @return
 */
char *to_string(http_message *message);

/**
 * ToString function of HttpRecord structure
 *
 * @param httpRecord
 * @return string
 */
char *to_string(http_record *http_record);

#endif // GALA_GOPHER_HTTP_MSG_FORMAT_H
