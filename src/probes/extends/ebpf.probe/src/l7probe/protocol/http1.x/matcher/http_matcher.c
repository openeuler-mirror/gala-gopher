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
    // 复制record内容
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

    // 计数错误个数，大于等于400均为错误，4xx为客户端错误，5xx为服务端错误
    if (rcd_cp->resp->resp_status >= 400) {
        DEBUG("[HTTP1.x MATCHER] Response Status Code: %d, error count increase.\n", record->resp->resp_status);
        ++record_buf->err_count;
    }
    record_buf->records[record_buf->record_buf_size] = record_data;
    ++record_buf->record_buf_size;
}

// Note: http消息队列若中间丢失req或resp，导致不能match正确到record，则结果不准确
void http_match_frames(struct frame_buf_s *req_frames, struct frame_buf_s *resp_frames, struct record_buf_s *record_buf)
{
    if (req_frames == NULL || req_frames->frame_buf_size == 0 || resp_frames == NULL || resp_frames->frame_buf_size == 0) {
        return;
    }
    DEBUG("[HTTP1.x MATCHER] Start to match http req and resp into record.\n");
    record_buf->err_count = 0;
    record_buf->record_buf_size = 0;
    record_buf->req_count = req_frames->frame_buf_size;
    record_buf->resp_count = resp_frames->frame_buf_size;

    http_record record = {0};

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
            DEBUG("[HTTP1.x MATCHER] Add req into record, req.timestamp: %lu, resq.timestamp: %lu\n",
                 req_msg->timestamp_ns, resp_msg->timestamp_ns);
            memset(&record, 0, sizeof(http_record));

            // req_msg一定放入record中，只要有就放入
            record.req = req_msg;
            ++req_frames->current_pos;
            continue;
        }

        // 循环默认假定req的数量一定大于等于resp，这也符合正常情况。此处异常分支处理跳出循环
        if (record.req == NULL) {
            DEBUG("[HTTP1.x MATCHER] There's no req in the record, break the cycle.\n");
            break;
        }

        // 两种情况分别处理
        // 如果现存record中的req是ok的，则匹配，放入record_buf中，并重新分配record内存
        if (record.req->timestamp_ns != 0) {
            DEBUG("[HTTP1.x MATCHER] Record->req->timestamp: %lu\n", record.req->timestamp_ns);
            record.resp = resp_msg;
            ++resp_frames->current_pos;
            add_http_record_into_buf(&record, record_buf);

            // 重新分配record的内容空间
            memset(&record, 0, sizeof(http_record));
            continue;
        }

        // 如果record中现存的req是个占位的，则直接忽略继续遍历
        ++resp_frames->current_pos;
    }
    DEBUG("[HTTP1.x MATCHER] match finished.\n");
}