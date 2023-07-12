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
#include "http_matcher.h"
#include "../model/http_msg_format.h"

static void add_http_record_into_buf(http_record *record, struct record_buf_s *record_buf)
{
    struct record_data_s *record_data = (struct record_data_s *) malloc(sizeof(struct record_data_s));
    if (record_data == NULL) {
        ERROR("[HTTP1.x MATCHER] Failed to malloc record_data.");
        return;
    }
    record_data->record = record;
    record_data->latency = record->resp->timestamp_ns - record->req->timestamp_ns;

    // 计数错误个数，大于等于400均为错误，4xx为客户端错误，5xx为服务端错误
    if (record->resp->resp_status >= 400) {
        ++record_buf->err_count;
    }
    record_buf->records[record_buf->record_buf_size] = record_data;
    ++record_buf->record_buf_size;
}

// Note: http消息队列若中间丢失req或resp，导致不能match正确到record，则结果不准确，影响较大
void http_match_frames(struct frame_buf_s *req_frames, struct frame_buf_s *resp_frames, struct record_buf_s *record_buf)
{
    record_buf->err_count = 0;
    record_buf->record_buf_size = 0;
    record_buf->req_count = req_frames->frame_buf_size;
    record_buf->resp_count = resp_frames->frame_buf_size;

    http_record *record = (http_record *) malloc(sizeof(http_record));
    if (record == NULL) {
        ERROR("[HTTP1.x MATCHER] Failed to malloc http_record.");
        return;
    }

    // 占位message，时间戳设置为最大
    http_message placeholder_msg = {0};
    placeholder_msg.timestamp_ns = INT64_MAX;

    // 循环处理，resp的buf中还有frame则继续循环匹配
    while (resp_frames->current_pos < resp_frames->frame_buf_size) {
        http_message *req_msg = (req_frames->current_pos == req_frames->frame_buf_size) ? &placeholder_msg
                                                                      : (http_message *) ((req_frames->frames)[req_frames->current_pos]->frame);
        http_message *resp_msg = (resp_frames->current_pos == resp_frames->frame_buf_size) ? &placeholder_msg
                                                                         : (http_message *) ((resp_frames->frames)[resp_frames->current_pos]->frame);

        // 处理req，添加到record中
        if (req_msg->timestamp_ns < resp_msg->timestamp_ns) {
            // Requests always go into the record (though not pushed yet).
            // If the next oldest item is a request too, it will (correctly) clobber this one.
            // set req into record, not adding record into records yet, record pointer not changed.
            record->req = req_msg;
            ++req_frames->current_pos;
            continue;
        }

        // Two cases for a response:
        // 1) No older request was found: then we ignore the response.
        // 2) An older request was found: then it is considered a match. Push the record, and reset.
        if (record->req->timestamp_ns != 0) {
            record->resp = resp_msg;
            ++resp_frames->current_pos;
            add_http_record_into_buf(record, record_buf);

            record = (http_record *) malloc(sizeof(http_record));
            if (record == NULL) {
                ERROR("[HTTP1.x MATCHER] Failed to malloc http_record.");
                return;
            }
            continue;
        }
        ++resp_frames->current_pos;
    }
}