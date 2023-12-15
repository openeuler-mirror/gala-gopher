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
 * Create: 2023-04-12
 * Description:
 ******************************************************************************/

#ifndef __REDIS_MSG_FORMAT_H__
#define __REDIS_MSG_FORMAT_H__

#pragma once

#include <stdint.h>
#include <stdbool.h>

struct redis_msg_s {
    // For unilateral messages (such as heartbeat), we construct a fake req/resp msg and store it in the record.
    // This kind of msg does not come from frame_bufs and must be freed when the record is freed.
    bool is_fake_msg;

    uint64_t timestamp_ns;

    // Actual payload, not including the data type marker, and trailing \r\n.
    char *payload;

    // Redis command, see https://redis.io/commands.
    char *command;

    // If true, indicates this is a published message from the server to all of
    // the subscribed clients.
    bool is_pub_msg;

    // Count of redis single reply message; there are many single reply messages in pipeline.
    size_t single_reply_msg_count;

    // Count of redis single error reply message(eg. "-Error Message").
    size_t single_reply_error_msg_count;
};

// A pair of request and response messages
struct redis_record_s {
    struct redis_msg_s *req_msg;
    struct redis_msg_s *resp_msg;
    bool role_swapped;
};

/**
 * Malloc初始化struct redis_msg_s*
 *
 * @return struct redis_msg_s*
 */
struct redis_msg_s *init_redis_msg();

/**
 * 释放struct redis_msg_s*
 *
 * @param msg struct redis_msg_s指针
 */
void free_redis_msg(struct redis_msg_s *msg);

/**
 * Malloc初始化struct redis_record_s*
 *
 * @return struct redis_record_s*
 */
struct redis_record_s *init_redis_record();

/**
 * 释放struct redis_record_s*
 *
 * @param msg struct redis_record_s指针
 */
void free_redis_record(struct redis_record_s *msg);

#endif
