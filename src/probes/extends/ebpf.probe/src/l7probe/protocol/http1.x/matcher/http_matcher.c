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
#include <stdio.h>
#include "http_matcher.h"
#include "../model/http_msg_format.h"
#include "../../../include/data_stream.h"

static void calc_l7_api_statistic(struct record_buf_s *record_buf, struct record_data_s *record_data, struct http_record *rcd_cp)
{
    // Calculate api-level metrics topology, put data into the map of l7_statistics
    struct api_stats_id stat_id = {0};

    // API Format: [Method] [Url] , example: GET /api/resource
    // URI Format: scheme:[//authority]path[?query][#fragment]
    // Example: http://127.0.0.1:8080/v1/api/sample?index=1&name=john#middle
    // Request Line Path Format: path[?query][#fragment]
    // Example: /v1/api/sample?index=1&name=john#middle
    // We take '/v1/api/sample' as path, and then take ‘GET /v1/api/sample‘ as api
    // todo: Aggregate uuid piece into * in path, such as: /v1/api/resource/{{UUID_resource_id}}/configuration -> /v1/api/resource/*/configuration
    if (rcd_cp->req->req_path == NULL) {
        return;
    }

    char path[MAX_API_LEN];
    (void) snprintf(path, MAX_API_LEN, "%s", rcd_cp->req->req_path);
    char* pos = strchr(path, '?');
    if (pos != NULL) {
        *pos = '\0';
    }

    (void) snprintf(stat_id.api, MAX_API_LEN, "%s %s", rcd_cp->req->req_method, path);

    struct api_stats* api_stats;
    H_FIND(record_buf->api_stats, &stat_id, sizeof(struct api_stats_id), api_stats);
    if (api_stats == NULL) {
        api_stats = create_api_stats(stat_id.api);
        if (api_stats == NULL) {
            return;
        }
        H_ADD_KEYPTR(record_buf->api_stats, &(api_stats->id), sizeof(struct api_stats_id), api_stats);
    }
    api_stats->records[api_stats->record_buf_size] = record_data;
    ++api_stats->record_buf_size;
    ++api_stats->req_count;
    ++api_stats->resp_count;

    // Specify error count. For HTTP, 4xx is client error/or request error, 5xx is server error/or response error
    if (rcd_cp->resp->resp_status >= 400) {
        if (rcd_cp->resp->resp_status < 500) {
            ++api_stats->client_err_count;
        } else {
            ++api_stats->server_err_count;
        }
        api_stats->err_records[api_stats->err_count] = record_data;
        ++api_stats->err_count;
    }
}

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

    calc_l7_api_statistic(record_buf, record_data, rcd_cp);
}

// Note: the lack of req/resp occurred in the middle of the http message queue, would lead to match incorrectly into record, then the result is not exact
void http_match_frames(struct frame_buf_s *req_frames, struct frame_buf_s *resp_frames, struct record_buf_s *record_buf)
{
    DEBUG("[HTTP1.x MATCHER] Start to match http req and resp into record.\n");
    http_record record = {0};

    // define the placeholder of message, and set the timestamp to the MAX
    http_message placeholder_msg = {0};
    placeholder_msg.timestamp_ns = UINT64_MAX;

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
    record_buf->req_count = req_frames->current_pos;
    record_buf->resp_count = resp_frames->current_pos;
    DEBUG("[HTTP1.x MATCHER] match finished.\n");
}