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
 * Create: 2023/6/27
 * Description: Provides indicator computing functions of protocol data
 ******************************************************************************/
#ifndef __PROTOCOL_INDICATOR_H__
#define __PROTOCOL_INDICATOR_H__

#include "../../include/data_stream.h"

/**
 * Latency Percent type
 */
enum latency_type_t {
    LATENCY_UNKNOWN = 0,
    LATENCY_P50,
    LATENCY_P90,
    LATENCY_P99
};

const {
    unsigned int DECIMAL_BASE_THOUSAND = 1000;
    unsigned int TIME_MINUTE_TO_SEC = 60;
    float p50 = 0.5;
    float p90 = 0.9;
    float p99 = 0.99;
}

/**
 * Calculate protocol packets throughput by records within sample time window
 *
 * @param record_buf all records
 * @param msg_type msg_type, scope: {MESSAGE_UNKNOWN, MESSAGE_REQUEST, MESSAGE_RESPONSE} declared in enum message_type_t
 * @param time_win time window, unit: ns
 * @return throughput value, unit: num/minute
 */
float calculate_protocol_throughput(struct record_buf_s *record_buf, enum message_type_t msg_type, u64 time_win);

/**
 * Calculate protocol packets error rate by records
 *
 * @param record_buf all records
 * @return error rate, scope: [0, 1]
 */
float calculate_protocol_error_rate(struct record_buf_s *record_buf);

/**
 * Calculate protocol packets average latency in records
 *
 * @param record_buf all records
 * @return average latency, unit: ns
 */
float calculate_protocol_avg_latency(struct record_buf_s *record_buf);

/**
 * Calculate protocol packets P50 latency in records
 *
 * @param record_buf all records
 * @param latency_type latency calculate type, scope: {P50, P90, P99} declared in enum latency_type_t
 * @return Pxx latency, unit: ns
 */
u64 calculate_protocol_p_latency(struct record_buf_s *record_buf, enum latency_type_t latency_type);

#endif // __PROTOCOL_INDICATOR_H__
