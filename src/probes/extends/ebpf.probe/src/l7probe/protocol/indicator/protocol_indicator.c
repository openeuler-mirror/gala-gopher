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
 * Create: 2023/6/28
 * Description:
 ******************************************************************************/

#include <stdlib.h>
#include "protocol_indicator.h"

static int compare_with_record_latency(const struct record_data_s *rec1, const struct record_data_s *rec2)
{
    if (rec1.latency < rec2.latency) {
        return -1;
    } else if (rec1.latency > rec2.latency) {
        return 1;
    } else {
        return 0;
    }
}

float calculate_protocol_throughput(struct record_buf_s *record_buf, enum message_type_t msg_type, u64 time_win)
{
    float throughput = 0.0;
    float minute = 0.0;
    if (msg_type == MESSAGE_UNKNOWN || record_buf == NULL || time_win == 0) {
        return 0.0;
    }
    minute = (float) time_win / DECIMAL_BASE_THOUSAND / DECIMAL_BASE_THOUSAND / DECIMAL_BASE_THOUSAND /
            TIME_MINUTE_TO_SEC;
    if (minute == 0.0) {
        return 0.0;
    }

    if (msg_type == MESSAGE_REQUEST) {
        throughput = (float) (record_buf->req_count) / minute;
    }
    if (msg_type == MESSAGE_RESPONSE) {
        throughput = (float) (record_buf->resp_count) / minute;
    }
    return throughput;
}

float calculate_protocol_error_rate(struct record_buf_s *record_buf)
{
    float error_rate;
    if (record_buf == NULL || record_buf->err_count == 0 || record_buf->req_count == 0) {
        return 0.0f;
    }
    error_rate = (float) (record_buf->err_count) / record_buf->req_count;
    return error_rate;
}

float calculate_protocol_avg_latency(struct record_buf_s *record_buf)
{
    float avg_latency;
    u64 latency_sum = 0;
    if (record_buf == NULL) {
        return;
    }
    for (struct record_data_s record: record_buf->records) {
        latency_sum += record.latency;
    }

    avg_latency = (float) latency_sum / record_buf->record_buf_size;
    return avg_latency;
}

u64 calculate_protocol_p_latency(struct record_buf_s *record_buf, enum latency_type_t latency_type)
{
    u64 p_latency;
    size_t p_index = 0;
    qsort(record_buf->records, record_buf->record_buf_size, sizeof(struct record_data_s *),
          compare_with_record_latency);

    switch (latency_type) {
        case LATENCY_P50:
            p_index = (size_t)(record_buf->record_buf_size * p50);
            break;
        case LATENCY_P90:
            p_index = (size_t)(record_buf->record_buf_size * p90);
            break;
        case LATENCY_P99:
            p_index = (size_t)(record_buf->record_buf_size * p99);
            break;
        case LATENCY_UNKNOWN:
        default:
            return 0.0;
    }

    p_latency = record_buf->records[p_index]->latency;
    return p_latency;
}
