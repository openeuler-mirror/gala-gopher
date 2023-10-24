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

const char KEY_CONTENT_ENCODING[17] = "Content-Encoding";
const char KEY_CONTENT_LENGTH[15] = "Content-Length";
const char KEY_CONTENT_TYPE[13] = "Content-Type";
const char KEY_TRANSFER_ENCODING[18] = "Transfer-Encoding";
const char KEY_UPGRADE[8] = "Upgrade";

http_message *init_http_msg(void)
{
    http_message *http_msg = (http_message *) malloc(sizeof(struct http_message));
    if (http_msg == NULL) {
        return NULL;
    }
    memset(http_msg, 0, sizeof(http_message));
    http_msg->type = MESSAGE_UNKNOW;
    http_msg->minor_version = -1;
    http_msg->resp_status = -1;
    return http_msg;
}

void free_http_msg(http_message *http_msg)
{
    if (http_msg == NULL) {
        return;
    }
    if (http_msg->headers != NULL) {
        free_http_headers_map(&(http_msg->headers));
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
    http_record *record = (http_record *) malloc(sizeof(http_record));
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

    // NOTE: the req/resp of record reused the pointer of req/resp in frame_buf, so we do not free the req/resp pointer here
    free(http_record);
}