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

#include <stdlib.h>
#include <string.h>
#include "http_parser.h"
#include "../../utils/macros.h"
#include "http_parse_wrapper.h"

/**
 * parse request body
 *
 * @param raw_data
 * @param frame_data
 * @return
 */
static parse_state_t parse_request_body(struct raw_data_s *raw_data, struct http_message *frame_data)
{

    // todo:
    return STATE_UNKNOWN;
}

/**
 * parse response body
 *
 * @param raw_data
 * @param frame_data
 * @return
 */
static parse_state_t parse_response_body(struct raw_data_s *raw_data, struct http_message *frame_data)
{

    // todo:
    return STATE_UNKNOWN;
}

/**
 * parse request
 *
 * @param buf
 * @param result
 * @return
 */
static parse_state_t parse_request_frame(struct raw_data_s *raw_data, http_message *frame_data) {
    http_request *req = init_http_request();

    // 解析 request headers
    size_t offset = http_parse_request_headers(raw_data, req);

    // 返回的retval若为-2，则表示部分解析成功，但需要更多数据来完成解析，指针不偏移
    if (offset == -2) {
        INFO("[HTTP1.x PARSER] Parser needs more data.");
        return STATE_NEEDS_MORE_DATA;
    }

    // -1时为解析失败
    if (offset == -1 || offset < -2) {
        ERROR("[HTTP1.x PARSER] Failed to parse raw_data into request.");
        return STATE_INVALID;
    }

    // offset >= 0 时解析成功，偏移指针
    raw_data->current_pos = offset;

    // 组装frame
    frame_data->type = MESSAGE_REQUEST;
    frame_data->timestamp_ns = raw_data->timestamp_ns;
    frame_data->minor_version = req->minor_version;
    frame_data->headers = get_http_headers_map(req->headers, req->num_headers);
    strcpy(frame_data->req_method, req->method);
    strcpy(frame_data->req_path, req->path);
    frame_data->headers_byte_size = offset;

    // 解析request body
    return parse_request_body(raw_data, frame_data);
}

/**
 * parse response
 *
 * @param buf
 * @param result
 * @param state
 * @return
 */
static parse_state_t parse_response_frame(struct raw_data_s *raw_data, struct http_message *frame_data) {
    http_response *resp = init_http_response();

    // 解析 response header
    size_t offset = http_parse_response_headers(raw_data, resp);

    // 返回的offset若为-2，则表示部分解析成功，但需要更多数据来完成解析，指针不偏移
    if (offset == -2) {
        INFO("[HTTP1.x PARSER] Parser needs more data.");
        return STATE_NEEDS_MORE_DATA;
    }

    // -1时为解析失败
    if (offset == -1 || offset < -2) {
        ERROR("[HTTP1.x PARSER] Failed to parse raw_data into response.");
        return STATE_INVALID;
    }

    // offset >= 0 时解析成功，偏移指针
    raw_data->current_pos = offset;

    // 组装frame
    frame_data->type = MESSAGE_RESPONSE;
    frame_data->timestamp_ns = raw_data->timestamp_ns;
    frame_data->minor_version = resp->minor_version;
    frame_data->headers = get_http_headers_map(resp->headers, resp->num_headers);
    frame_data->resp_status = resp->status;
    strcpy(frame_data->resp_message, resp->msg);
    frame_data->headers_byte_size = offset;

    // 解析response body
    return parse_response_body(raw_data, frame_data);
}

/**
 * Parses a raw input buffer for HTTP messages.
 * HTTP headers are parsed by pico. Body is extracted separately.
 *
 * @param msg_type request or response
 * @param raw_data The source buffer to parse. The prefix of this buffer will be consumed to indicate
 * the point until which the parse has progressed.
 * @param frame_data A parsed HTTP message, if parse was successful (must consider return value).
 * @return parse_state
 */
parse_state_t http_parse_frame(enum message_type_t msg_type, struct raw_data_s *raw_data, struct frame_data_s **frame_data) {
    http_message *http_msg = init_http_msg();
    parse_state_t state;
    switch (msg_type) {
        case MESSAGE_REQUEST:
            state = parse_request_frame(raw_data, http_msg);
            (*frame_data)->frame = http_msg;
            (*frame_data)->msg_type = msg_type;
            (*frame_data)->timestamp_ns = http_msg->timestamp_ns;
            return state;
        case MESSAGE_RESPONSE:
            state = parse_response_frame(raw_data, http_msg);
            (*frame_data)->frame = http_msg;
            (*frame_data)->msg_type = msg_type;
            (*frame_data)->timestamp_ns = http_msg->timestamp_ns;
            return state;
        default:
            return STATE_INVALID;
    }
}

// NOTE: This function should use is_http_{response,request} inside
// bcc_bpf/socket_trace.c to check if a sequence of bytes are aligned on HTTP message boundary.
// ATM, they actually do not share the same logic. As a result, BPF events detected as HTTP traffic,
// can actually fail to find any valid boundary by this function. Unfortunately, BPF has many
// restrictions that likely make this a difficult or impossible goal.
size_t http_find_frame_boundary(enum message_type_t msg_type, struct raw_data_s *raw_data) {
    size_t start_pos = raw_data->current_pos;

    // List of all HTTP request methods. All HTTP requests start with one of these.
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
    static const char *kHTTPReqStartPatternArray[] = {
        "GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "CONNECT ", "OPTIONS ", "TRACE ", "PATCH ",
    };

    // List of supported HTTP protocol versions. HTTP responses typically start with one of these.
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages
    static const char *kHTTPRespStartPatternArray[] = {"HTTP/1.1 ", "HTTP/1.0 "};

    static const char *kBoundaryMarker = "\r\n\r\n";

    // Choose the right set of patterns for request or response.
    const char **start_patterns;
    switch (msg_type) {
        case MESSAGE_REQUEST:
            start_patterns = kHTTPReqStartPatternArray;
            break;
        case MESSAGE_RESPONSE:
            start_patterns = kHTTPRespStartPatternArray;
            break;
        case MESSAGE_UNKNOW:
            return PARSER_INVALID_BOUNDARY_INDEX;
    }

    // Search for a boundary marker, preceded with a message start.
    // Example, using HTTP Response:
    //   leftover body (from previous message)
    //   HTTP/1.1 ...
    //   headers
    //   \r\n\r\n
    //   body
    // We first search forwards for \r\n\r\n, then we search backwards from there for HTTP/1.1.
    //
    // Note that we don't search forwards for HTTP/1.1 directly, because it could result in matches
    // inside the request/response body.
    while (true) {
        // 1.find the first "\r\n\r\n" sub-string in the raw_data.data
        size_t marker_pos = find_str(raw_data->data, kBoundaryMarker, raw_data->current_pos);

        // 如果pos数值不正确，返回-1
        if (marker_pos == -1) {
            return PARSER_INVALID_BOUNDARY_INDEX;
        }

        // 2.寻找子字符串: start_pos ~ marker_pos
        // todo: 待优化，可以不用取子串来算，减少字符串复制操作，优化性能。直接用raw_data来匹配，用current_pos指针来控制遍历范围
        char *buf_substr = substr(raw_data->data, start_pos, marker_pos - start_pos);

        // 3.匹配start_pos ~ marker_pos之间子串中的start_pattern，取最后一个（最靠近 "\r\n\r\n" 标志的帧边界）
        size_t substr_pos = -1;
        for (int i = 0; i < get_array_len(start_patterns) - 1; i++) {
            char *start_pattern = start_patterns[i];
            size_t current_substr_pos = rfind_str(buf_substr, start_pattern);
            if (current_substr_pos != -1) {
                // Found a match. Check if it is closer to the marker than our previous match.
                // We want to return the match that is closest to the marker, so we aren't
                // matching to something in a previous message's body.
                size_t max_pos = substr_pos;
                if (max_pos < current_substr_pos) {
                    marker_pos = current_substr_pos;
                }
                substr_pos = (substr_pos == -1) ? current_substr_pos : max_pos;
            }
        }

        // 4.返回帧边界标志匹配到的位置
        if (substr_pos != -1) {
            return start_pos + substr_pos;
        }

        // 5.找不到帧边界时，将指针移至 "\r\n\r\n" 标志的末尾，进行下一个帧边界的寻找
        // Couldn't find a start position. Move to the marker, and search for another marker.
        raw_data->current_pos = marker_pos + strlen(kBoundaryMarker);
    }
}
