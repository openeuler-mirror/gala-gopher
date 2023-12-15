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
 * Create: 2023-04-19
 * Description:
 ******************************************************************************/

#include <stdint.h>
#include <string.h>
#include "redis_msg_format.h"
#include "redis_matcher.h"

static struct redis_record_s *handle_pub_resp_msg(struct redis_msg_s *resp)
{
    char *PUSH_PUB_CMD = "PUSH PUB";
    struct redis_record_s *unmatched_record = init_redis_record();
    if (unmatched_record == NULL) {
        ERROR("[Redis Match] Malloc unmatched_record failed.\n");
        return NULL;
    }
    unmatched_record->req_msg = init_redis_msg();
    if (unmatched_record->req_msg == NULL) {
        free_redis_record(unmatched_record);
        ERROR("[Redis Match] Malloc unmatched_record->req_msg failed.\n");
        return NULL;
    }

    unmatched_record->req_msg->timestamp_ns = resp->timestamp_ns;
    unmatched_record->req_msg->command = strdup(PUSH_PUB_CMD);
    unmatched_record->req_msg->is_fake_msg = true;
    unmatched_record->resp_msg = resp;
    return unmatched_record;
}

static struct redis_record_s *handle_follower_to_leader_ack_msg(struct redis_msg_s *req)
{
    struct redis_record_s *unmatched_record = init_redis_record();
    if (unmatched_record == NULL) {
        ERROR("[Redis Match] Malloc unmatched_record failed.\n");
        return NULL;
    }
    unmatched_record->resp_msg = init_redis_msg();
    if (unmatched_record->resp_msg == NULL) {
        free_redis_record(unmatched_record);
        ERROR("[Redis Match] Malloc unmatched_record->resp_msg failed.\n");
        return NULL;
    }
    unmatched_record->req_msg = req;
    unmatched_record->resp_msg->timestamp_ns = req->timestamp_ns;
    unmatched_record->resp_msg->single_reply_msg_count = 1;
    unmatched_record->resp_msg->is_fake_msg = true;
    return unmatched_record;
}

static struct redis_record_s *handle_leader_to_follower_msg(struct redis_msg_s *resp)
{
    struct redis_record_s *unmatched_record = init_redis_record();
    if (unmatched_record == NULL) {
        ERROR("[Redis Match] Malloc unmatched_record failed.\n");
        return NULL;
    }
    unmatched_record->resp_msg = init_redis_msg();
    if (unmatched_record->resp_msg == NULL) {
        free_redis_record(unmatched_record);
        ERROR("[Redis Match] Malloc unmatched_record->resp_msg failed.\n");
        return NULL;
    }
    unmatched_record->req_msg = resp;
    unmatched_record->resp_msg->timestamp_ns = resp->timestamp_ns;
    unmatched_record->resp_msg->single_reply_msg_count = 1;
    unmatched_record->resp_msg->is_fake_msg = true;
    unmatched_record->role_swapped = true;
    return unmatched_record;
}

static void add_redis_record_to_buf(struct record_buf_s *record_buf, struct redis_record_s *record)
{
    struct record_data_s *record_data = (struct record_data_s *) malloc(sizeof(struct record_data_s));
    if (record_data == NULL) {
        ERROR("[Redis Match] Malloc record_data failed.\n");
        return;
    }
    memset(record_data, 0, sizeof(struct record_data_s));
    record_data->record = record;
    record_buf->records[record_buf->record_buf_size] = record_data;
    ++record_buf->record_buf_size;
    record_buf->msg_error_count += record->resp_msg->single_reply_error_msg_count;
    record_buf->msg_total_count += record->resp_msg->single_reply_msg_count;
}

static struct redis_msg_s *get_redis_msg(struct frame_buf_s *frame_bufs, struct redis_msg_s *placeholder_msg)
{
    struct redis_msg_s *msg = NULL;

    if (frame_bufs->current_pos == frame_bufs->frame_buf_size) {
        msg = placeholder_msg;
    } else {
        if (frame_bufs->current_pos < __FRAME_BUF_SIZE) {
            struct frame_data_s * frame_tmp = (frame_bufs->frames)[frame_bufs->current_pos];
            if (frame_tmp == NULL) {
                return NULL;
            }
            msg = frame_tmp->frame;
        }
    }

    return msg;
}

static void match_frames_with_timestamp_order(struct record_buf_s *record_buf, struct redis_record_s *record,
    struct frame_buf_s *req_frames, struct frame_buf_s *resp_frames)
{
    struct redis_msg_s placeholder_msg = {0};
    placeholder_msg.timestamp_ns = INT64_MAX;

    while (req_frames->current_pos < req_frames->frame_buf_size ||
           resp_frames->current_pos < resp_frames->frame_buf_size) {

        struct redis_msg_s *req = get_redis_msg(req_frames, &placeholder_msg);
        if (req == NULL) {
            break;
        }
        struct redis_msg_s *resp = get_redis_msg(resp_frames, &placeholder_msg);
        if (resp == NULL) {
            break;
        }

        // Convert Redis pub/sub published messages which have no corresponding `request` into request-less record_buf.
        if (resp_frames->current_pos < resp_frames->frame_buf_size && resp->is_pub_msg) {
            add_redis_record_to_buf(record_buf, handle_pub_resp_msg(resp));
            ++resp_frames->current_pos;
            continue;
        }

        // Handle REPLCONF ACK command sent from follower to leader.
        const char *REPLCONF_ACK = "REPLCONF ACK";
        if (req->command != NULL && req_frames->current_pos < req_frames->frame_buf_size && (strcmp(req->command, REPLCONF_ACK) == 0) &&
            // Ensure the output order based on timestamps.
            (resp_frames->current_pos == resp_frames->frame_buf_size || req->timestamp_ns < resp->timestamp_ns)) {
            add_redis_record_to_buf(record_buf, handle_follower_to_leader_ack_msg(req));
            ++req_frames->current_pos;
            continue;
        }

        // Handle commands sent from leader to follower, which are replayed at the follower.
        if (resp->command != NULL && resp_frames->current_pos < resp_frames->frame_buf_size && strlen(resp->command) != 0) {
            add_redis_record_to_buf(record_buf, handle_leader_to_follower_msg(resp));
            ++resp_frames->current_pos;
            continue;
        }

        if (req->timestamp_ns < resp->timestamp_ns) {
            record->req_msg = req;
            ++req_frames->current_pos;
            continue;
        }
        if (record->req_msg != NULL && record->req_msg->timestamp_ns != 0) {
            record->resp_msg = resp;
            add_redis_record_to_buf(record_buf, record);

            // 重新初始化
            record = init_redis_record();
            if (record == NULL) {
                return;
            }
        }
        ++resp_frames->current_pos;
    }

    // 释放掉最后一个没有用的record 内存
    free_redis_record(record);
}

void redis_match_frames(struct frame_buf_s *req_frames, struct frame_buf_s *resp_frames, struct record_buf_s *record_buf)
{
    record_buf->err_count = 0;
    record_buf->record_buf_size = 0;
    record_buf->req_count = req_frames->frame_buf_size;
    record_buf->resp_count = resp_frames->frame_buf_size;

    struct redis_record_s *record = init_redis_record();
    if (record == NULL) {
        return;
    }
    match_frames_with_timestamp_order(record_buf, record, req_frames, resp_frames);
}