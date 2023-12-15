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
 * Author: niebin
 * Create: 2023-07-28
 * Description:
 ******************************************************************************/
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "redis_msg_format.h"

struct redis_msg_s *init_redis_msg()
{
    struct redis_msg_s *msg = (struct redis_msg_s *)malloc(sizeof(struct redis_msg_s));
    if (msg == NULL) {
        ERROR("[Redis Parse] redis_msg_s malloc failed.\n");
        return NULL;
    }
    memset(msg, 0, sizeof(struct redis_msg_s));
    return msg;
}

void free_redis_msg(struct redis_msg_s *msg)
{
    if (msg == NULL) {
        return;
    }
    if (msg->command != NULL) {
        free(msg->command);
        msg->command = NULL;
    }

    if (msg->payload != NULL) {
        free(msg->payload);
        msg->payload = NULL;
    }
    free(msg);
}

struct redis_record_s *init_redis_record()
{
    struct redis_record_s *record = (struct redis_record_s *)malloc(sizeof(struct redis_record_s));
    if (record == NULL) {
        ERROR("[Redis Parse] redis_record_s malloc failed.\n");
        return NULL;
    }
    memset(record, 0, sizeof(struct redis_record_s));
    return record;
}

void free_redis_record(struct redis_record_s *record)
{
    if (record == NULL) {
        return;
    }
    if (record->req_msg != NULL && record->req_msg->is_fake_msg) {
        free_redis_msg(record->req_msg);
    }
    if (record->resp_msg != NULL && record->resp_msg->is_fake_msg) {
        free_redis_msg(record->resp_msg);
    }
    free(record);
}