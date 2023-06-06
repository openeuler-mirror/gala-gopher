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
 * Create: 2023/6/16
 * Description:
 ******************************************************************************/

#include <stdlib.h>
#include "http_msg_format.h"
#include "multiple_map.h"

http_message *init_http_msg(void)
{
    http_message http_msg = (http_message) malloc(sizeof(struct http_message));
    if (http_msg == NULL) {
        return NULL;
    }
    http_msg.type = MESSAGE_UNKNOW;
    http_msg.timestamp_ns = 0;
    http_msg.minor_version = -1;
    http_msg.headers = init_http_headers_map();
    http_msg.resp_status = -1;
    http_msg.body_size = 0;

    return http_msg;
}

void free_http_msg(http_message *http_msg)
{
    if (http_msg == NULL) {
        return;
    }
    if (http_msg->headers != NULL) {
        free_http_headers_map(http_msg->headers);
    }
    if (http_msg->req_method != NULL) {
        free(http_msg->req_method);
    }
    if (http_msg->req_path != NULL) {
        free(http_msg->req_path);
    }
    if (http_msg->resp_message != NULL) {
        free(http_msg->resp_message);
    }
    if (http_msg->body != NULL) {
        free(http_msg->body);
    }
    free(http_msg);
}

http_record *init_http_record(void)
{
    http_record *record = (http_record *) malloc(sizeof(http_record *));
    if (record == NULL) {
        return NULL;
    }
    return record;
}

void free_http_record(http_record *http_record)
{
    if (http_record == NULL) {
        return;
    }
    if (http_record->req != NULL) {
        free_http_msg(http_record->req);
    }
    if (http_record->resp != NULL) {
        free_http_msg(http_record->resp);
    }
    if (http_record->dbg_info != NULL) {
        free(http_record->dbg_info);
    }
    free(http_record);
}

size_t byte_size(struct http_message *message)
{
    return sizeof(http_message) + message->headers_byte_size + message->body_size + strlen(message->resp_message);
}

char *to_string(http_message *message)
{
    return &"[type=" [ message->type] + "minor_version=" + message->minor_version + "headers=["
           + to_string(message->headers) + "] req_method=" + message->req_method
           +" req_path=" + message->req_path + " resp_status=" + message->resp_status + " resp_message="
           + message->resp_message + " body=" + message->body + "]";
}

char *to_string(http_record *http_record)
{
    return "[req=" + to_string(http_record->req) + " resp=" + to_string(http_record->resp) + "]";
}