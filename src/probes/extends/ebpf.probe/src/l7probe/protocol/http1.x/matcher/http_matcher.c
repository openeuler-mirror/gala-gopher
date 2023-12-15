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
    // copy record replica
    http_record *rcd_cp;

    if (record_buf->record_buf_size >= RECORD_BUF_SIZE) {
        WARN("[HTTP1.x MATCHER] The record buffer is full.\n");
        return;
    }

    rcd_cp = (http_record *) malloc(sizeof(http_record));
    if (rcd_cp == NULL) {
        ERROR("[HTTP1.x MATCHER] Failed to malloc http_record.\n");
        return;
    }
    rcd_cp->req = record->req;
    rcd_cp->resp = record->resp;

    struct record_data_s *record_data = (struct record_data_s *) malloc(sizeof(struct record_data_s));
    if (record_data == NULL) {
        ERROR("[HTTP1.x MATCHER] Failed to malloc record_data.\n");
        free_http_record(rcd_cp);
        return;
    }
    record_data->record = rcd_cp;
    record_data->latency = rcd_cp->resp->timestamp_ns - rcd_cp->req->timestamp_ns;

    // Count the number of errors, the status code >= 400 means error, and 4xx means client error, 5xx means server error
    if (rcd_cp->resp->resp_status >= 400) {
        DEBUG("[HTTP1.x MATCHER] Response Status Code: %d, error count increase.\n", record->resp->resp_status);
        ++record_buf->err_count;
    }
    record_buf->records[record_buf->record_buf_size] = record_data;
    ++record_buf->record_buf_size;
}

// Note: the lack of req/resp occurred in the middle of the http message queue, would lead to match incorrectly into record, then the result is not exact
void http_match_frames(struct frame_buf_s *req_frames, struct frame_buf_s *resp_frames, struct record_buf_s *record_buf)
{
    DEBUG("[HTTP1.x MATCHER] Start to match http req and resp into record.\n");
    record_buf->err_count = 0;
    record_buf->record_buf_size = 0;
    record_buf->req_count = req_frames->frame_buf_size;
    record_buf->resp_count = resp_frames->frame_buf_size;

    http_record record = {0};

    // define the placeholder of message, and set the timestamp to the MAX
    http_message placeholder_msg = {0};
    placeholder_msg.timestamp_ns = INT64_MAX;

    // process circularly, continue matching while there is frame in resp buf
    while (resp_frames->current_pos < resp_frames->frame_buf_size) {
        http_message *req_msg = (req_frames->current_pos == req_frames->frame_buf_size) ? &placeholder_msg
                                                                      : (http_message *) ((req_frames->frames)[req_frames->current_pos]->frame);
        http_message *resp_msg = (resp_frames->current_pos == resp_frames->frame_buf_size) ? &placeholder_msg
                                                                         : (http_message *) ((resp_frames->frames)[resp_frames->current_pos]->frame);

        // add req into record
        if (req_msg->timestamp_ns < resp_msg->timestamp_ns) {
            DEBUG("[HTTP1.x MATCHER] Add req into record, req.timestamp: %lu, resp.timestamp: %lu\n",
                 req_msg->timestamp_ns, resp_msg->timestamp_ns);
            memset(&record, 0, sizeof(http_record));
            record.req = req_msg;
            ++req_frames->current_pos;
            continue;
        }

        // break the cycle if the req is NULL. We suppose the amount if req must be larger than (or equals to) the one of resp
        if (record.req == NULL) {
            DEBUG("[HTTP1.x MATCHER] There's no req in the record, break the cycle.\n");
            break;
        }

        // if the req in record is a real req, then matched, and memset for record
        if (record.req->timestamp_ns != 0) {
            DEBUG("[HTTP1.x MATCHER] Record->req->timestamp: %lu\n", record.req->timestamp_ns);
            record.resp = resp_msg;
            ++resp_frames->current_pos;
            add_http_record_into_buf(&record, record_buf);
            memset(&record, 0, sizeof(http_record));
            continue;
        }

        // if the req in record is placeholder, then go on the cycle
        ++resp_frames->current_pos;
    }
    DEBUG("[HTTP1.x MATCHER] match finished.\n");
}