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
#include <stdlib.h>
#include <string.h>
#include "http_parser.h"
#include "../../utils/macros.h"
#include "http_parse_wrapper.h"

/**
 * parse chunked data and data length
 *
 * @param raw_data
 * @param offset
 * @param body
 * @return
 */
static parse_state_t parse_chunked(struct raw_data_s *raw_data, size_t *offset, char **body)
{
    const int search_window = 2048;
    const size_t delimiter_len = 2;
    char *data = raw_data->data + raw_data->current_pos;
    size_t data_len = raw_data->data_len - raw_data->current_pos;
    size_t total_size = 0;
    while(true) {
        size_t chunked_len = 0;

        size_t deli_pos = find_str(substr(data, 0,search_window), "\r\n", 0);
        if (deli_pos == data_len) {
            return data_len > search_window ? STATE_INVALID : STATE_NEEDS_MORE_DATA;
        }

        // chunked数据每个分片都在开头设置分片数据长度，用";"和数据隔开
        // 格式： chunked_data_len ; extension | \r\n | data
        char *chunked_str_len = substr(data, 0, deli_pos);
        size_t chunked_ext_pos = find_str(chunked_str_len, ";", 0);
        if (chunked_ext_pos != strlen(chunked_str_len) -1) {
            chunked_str_len = substr(chunked_str_len, 0, chunked_ext_pos);
        }

        chunked_len = simple_hex_atoi(chunked_str_len);

        // 指针偏移deli_pos + delimiter_len
        data += deli_pos + delimiter_len;

//        total_size += chunked_len;
        if (chunked_len == 0) {
            break;
        }

        // NOTE: parse chunked data, not support for now
        char *chunked_data;
        if (strlen(data) < chunked_len + delimiter_len) {
            return STATE_NEEDS_MORE_DATA;
        }
        chunked_data = substr(data, 0, chunked_len);
        data += chunked_len;
        if (data[0] != '\r' || data[1] != '\n') {
            return STATE_INVALID;
        }
        data += delimiter_len;

        // 仅偏移chunk_data长度的指针
        data += chunked_len + delimiter_len;

        // 计算总长度
        total_size += strlen(chunked_data);
    }

    raw_data->current_pos += data + raw_data->current_pos - raw_data->data;

    // Note: 暂不计算body
//    *body = data;

    *offset = total_size;
    return STATE_SUCCESS;
}

/**
 * parse request body
 * 请求体分三种情况：
 * 1）请求头中有Content-Length字段时，该字段的值即是请求体body的长度。如果非Transfer-Encoding的请求体，客户端必须加上Content-Length字段
 * 2）请求头中有Transfer-Encoding字段时，不再有Content-Length字段，需要对Transfer-Encoding=Chunked的请求体进行解析
 * 3）请求头中既没有Content-Length也没有Transfer-Encoding字段时，即该请求没有body
 *
 * @param raw_data
 * @param frame_data
 * @return
 */
static parse_state_t parse_request_body(struct raw_data_s *raw_data, struct http_message *frame_data)
{
    size_t offset = 0;

    // 1. Content-Length
    char *content_len_str = get_1st_value_by_key(frame_data->headers, KEY_CONTENT_LENGTH);
    if (content_len_str != NULL) {
        size_t content_len = atoi(content_len_str);
        if (strcmp(content_len_str, "0") != 1 && content_len == 0) {
            WARN("[HTTP1.x PARSER] Failed to parse content-Length.\n");
            return STATE_INVALID;
        }
        if (content_len > raw_data->data_len - raw_data->current_pos) {
            WARN("[HTTP1.x PARSER] Parsing request body needs more data.\n");
            return STATE_NEEDS_MORE_DATA;
        }
//        frame_data->body = substr(raw_data->data, raw_data->current_pos, raw_data->current_pos + content_len);
        frame_data->body_size = content_len;
        raw_data->current_pos += content_len;
        return STATE_SUCCESS;
    }

    // 2. Transfer-Encoding: Chunked
    char *transfer_encoding = get_1st_value_by_key(frame_data->headers, KEY_TRANSFER_ENCODING);
    if (transfer_encoding != NULL && strcmp(transfer_encoding, "chunked")) {
        parse_state_t state = parse_chunked(raw_data, &offset, &(frame_data->body));
        frame_data->body_size = offset;
        return state;
    }

    // 3. 无Content-Length和Transfer-Encoding，即无请求body，直接返回successful即可
//    frame_data->body = "";
    frame_data->body_size = 0;
    raw_data->current_pos += offset;
    return STATE_SUCCESS;
}

/**
 * parse response body
 * 响应体分四种情况：
 * 1）如果时HEAD请求的响应，本身没有响应体。解析完响应头之后就直接是下一个响应了，此时指针起始点以HTTP1.x协议号开头；
 * 2）响应头中有Content-Length字段，此时直接取该length作为body长度，偏移指针即可；
 * 3）再是没有Content-Length，但是有Transfer-Encoding字段的情况，同request的处理；
 * 4）已知的没有body体的情况，状态码在 [100, 199], {204, 304} 范围内的。其中101较为特殊，是Upgrade消息，暂不支持；
 * 5）无法预知是否有body的，响应头中既没有Content-Length也没有Transfer-Encoding，这种情况应该等待连接断开
 * 注：在解析body之前，解析完header之后raw_data.current_pos指针已发生偏移。若解析body返回非SUCCESS，上层应回退指针；返回SUCCESS时，此处偏移指针。
 *
 * @param raw_data
 * @param frame_data
 * @return
 */
static parse_state_t parse_response_body(struct raw_data_s *raw_data, struct http_message *frame_data)
{
    size_t offset = 0;
    char *buf = raw_data->data + raw_data->current_pos;

    // 1. HEAD请求的响应，前面已经解析完响应头，此处是新的响应的开始，以协议号开头。此处预解析新的响应，不发生指针偏移
    if (frame_data->type == MESSAGE_RESPONSE && starts_with(buf, "HTTP") == 1) {
        http_response resp = {0};
        size_t next_resp_header_offset = http_parse_response_headers(raw_data, &resp);
        if (next_resp_header_offset > 0) {
//            frame_data->body = "";
            frame_data->body_size = 0;
            return STATE_SUCCESS;
        }
    }

    // 2. 有Content-Length
    char *content_len_str = get_1st_value_by_key(frame_data->headers, KEY_CONTENT_LENGTH);
    if (content_len_str != NULL) {
        size_t content_len = atoi(content_len_str);
        if (strcmp(content_len_str, "0") != 1 && content_len == 0) {
            WARN("[HTTP1.x PARSER] Failed to parse content-Length.\n");
            return STATE_INVALID;
        }
        if (content_len > raw_data->data_len - raw_data->current_pos) {
            WARN("[HTTP1.x PARSE] Parsing response body needs more data.\n");
            return STATE_NEEDS_MORE_DATA;
        }
//        frame_data->body = substr(raw_data->data, raw_data->current_pos, raw_data->current_pos + content_len);
        frame_data->body_size = content_len;
        raw_data->current_pos += content_len;
        return STATE_SUCCESS;
    }

    // 3. 有Transfer-Encoding
    char *transfer_encoding = get_1st_value_by_key(frame_data->headers, KEY_TRANSFER_ENCODING);
    if (transfer_encoding != NULL && strcmp(transfer_encoding, "chunked")) {
        parse_state_t state = parse_chunked(raw_data, &offset, &(frame_data->body));

        // note: 暂不需要解析body内容，仅拿到body长度即可
//        frame_data->body = *body;
        frame_data->body_size = offset;
        return state;
    }

    // 4. 已知的无body情况，状态码在[100, 199], {204, 304} 范围内的。其中101较为特殊，是Upgrade消息，暂不支持；
    if ((frame_data->resp_status >= 100 && frame_data->resp_status < 200) || frame_data->resp_status == 204 ||
        frame_data->resp_status == 304) {
//        frame_data->body = "";
        frame_data->body_size = 0;

        if (frame_data->resp_status == 101) {
            char *upgrade_str = get_1st_value_by_key(frame_data->headers, KEY_UPGRADE);
            if (upgrade_str == NULL) {
                WARN("[HTTP1.x PARSER] Expected an Upgrade header with http status code 101.\n");
            }
            WARN("[HTTP1.x PARSER] Http Upgrades are not supported yet.\n");
            return STATE_EOS;
        }
        return STATE_SUCCESS;
    }

    // note: 暂不考虑该情况，直接跳过，解析下一帧
    // 5. 无法预知是否有body的，响应头中既没有Content-Length也没有Transfer-Encoding，这种情况应该等待连接断开
    frame_data->body_size = 0;
//    frame_data->body = "";

    raw_data->current_pos += offset;
    return STATE_SUCCESS;
}

/**
 * parse request
 *
 * @param buf
 * @param result
 * @return
 */
static parse_state_t parse_request_frame(struct raw_data_s *raw_data, http_message *frame_data) {
    http_request req = {0};

    // 解析 request headers
    size_t offset = http_parse_request_headers(raw_data, &req);

    // 返回的retval若为-2，则表示部分解析成功，但需要更多数据来完成解析，指针不偏移
    if (offset == -2) {
        WARN("[HTTP1.x PARSER] Parser needs more data.\n");
        return STATE_NEEDS_MORE_DATA;
    }

    // -1时为解析失败
    if (offset == -1) {
        WARN("[HTTP1.x PARSER] Failed to parse raw_data into request.\n");
        return STATE_INVALID;
    }

    // 组装frame
    frame_data->type = MESSAGE_REQUEST;
    frame_data->timestamp_ns = raw_data->timestamp_ns;
    frame_data->minor_version = req.minor_version;
    frame_data->headers = get_http_headers_map(req.headers, req.num_headers);
    frame_data->req_method = strndup(req.method, req.method_len);
    frame_data->req_path = strndup(req.path, req.path_len);
    frame_data->headers_byte_size = offset;

    // raw_data指针偏移offset长度
    raw_data->current_pos += offset;
    DEBUG("[HTTP1.x PARSER] Parsing req, offset: %d, raw_data.current_pos: %d.\n", offset, raw_data->current_pos);

    // 解析request body
    parse_state_t state = parse_request_body(raw_data, frame_data);
    if (state != STATE_SUCCESS) {
        raw_data->current_pos -= offset;
    }
    DEBUG("[HTTP1.x PARSER] Finished Parsing req, state: %d, current_pos: %d. \n", state, raw_data->current_pos);
    return state;
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
    http_response resp = {0};

    // 解析 response header
    size_t offset = http_parse_response_headers(raw_data, &resp);

    // 返回的offset若为-2，则表示部分解析成功，但需要更多数据来完成解析，指针不偏移
    if (offset == -2) {
        WARN("[HTTP1.x PARSER] Parser needs more data.\n");
        return STATE_NEEDS_MORE_DATA;
    }

    // -1时为解析失败
    if (offset == -1) {
        WARN("[HTTP1.x PARSER] Failed to parse raw_data into response, offset code: %d\n", offset);
        return STATE_INVALID;
    }

    // 组装frame
    frame_data->type = MESSAGE_RESPONSE;
    frame_data->timestamp_ns = raw_data->timestamp_ns;
    frame_data->minor_version = resp.minor_version;
    frame_data->headers = get_http_headers_map(resp.headers, resp.num_headers);
    frame_data->resp_status = resp.status;
    frame_data->resp_message = strndup(resp.msg, resp.msg_len);
    frame_data->headers_byte_size = offset;

    // raw_data指针偏移offset长度
    raw_data->current_pos += offset;

    // 解析response body
    parse_state_t state = parse_response_body(raw_data, frame_data);
    if (state != STATE_SUCCESS) {
        raw_data->current_pos -= offset;
    }

    DEBUG("[HTTP1.x PARSER] Finished Parsing resp, state: %d, current_pos: %d. \n", state, raw_data->current_pos);
    return state;
}

/**
 * Parses a raw input buffer for HTTP messages.
 *
 * @param msg_type request or response
 * @param raw_data The source buffer to parse. The prefix of this buffer will be consumed to indicate
 * the point until which the parse has progressed.
 * @param frame_data A parsed HTTP message, if parse was successful (must consider return value).
 * @return parse_state
 */
parse_state_t http_parse_frame(enum message_type_t msg_type, struct raw_data_s *raw_data, struct frame_data_s **frame_data) {
    http_message *http_msg = init_http_msg();
    parse_state_t state = STATE_INVALID;
    switch (msg_type) {
        case MESSAGE_REQUEST:
            DEBUG("[HTTP1.x PARSER] parse http request frame.\n");
            state = parse_request_frame(raw_data, http_msg);
            break;
        case MESSAGE_RESPONSE:
            DEBUG("[HTTP1.x PARSER] parse http response frame.\n");
            state = parse_response_frame(raw_data, http_msg);
            break;
        default:
            WARN("[HTTP1.x PARSER] Message type invalid.\n");
            break;
    }
    if (state != STATE_SUCCESS) {
        WARN("[HTTP1.x PARSER] Parsing Failed.\n");
        free_http_msg(http_msg);
        return state;
    }

    *frame_data = (struct frame_data_s *) malloc(sizeof(struct frame_data_s));
    if ((*frame_data) == NULL) {
        WARN("[HTTP1.x PARSER] Failed to malloc frame_data.\n");
        free_http_msg(http_msg);
        return STATE_INVALID;
    }
    (*frame_data)->frame = http_msg;
    (*frame_data)->msg_type = msg_type;
    (*frame_data)->timestamp_ns = http_msg->timestamp_ns;
    DEBUG("[HTTP1.x PARSER] Parse frame finished, msg_type: %s, ts: %d\n", msg_type, http_msg->timestamp_ns);
    return state;
}

size_t http_find_frame_boundary(enum message_type_t msg_type, struct raw_data_s *raw_data) {
    DEBUG("[HTTP1.x PARSER] Start finding frame boundary, current_pos: %d\n", raw_data->current_pos);
    size_t start_pos = raw_data->current_pos;

    // 所有的HTTP Method列表，HTTP请求都以method起始，参考：
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
    static const char *HTTP_REQUEST_START_PATTERN_ARRAY[] = {
        "GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "CONNECT ", "OPTIONS ", "TRACE ", "PATCH "
    };

    // HTTP1.x版本号，HTTP响应都以版本号其实，参考：
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages
    static const char *HTTP_RESPONSE_START_PATTERN_ARRAY[] = {"HTTP/1.1 ", "HTTP/1.0 "};

    static const char *kBoundaryMarker = "\r\n\r\n";

    // 根据req或resp使用不同的起始规则
    const char **start_patterns = {0};
    size_t patterns_len = 0;
    switch (msg_type) {
        case MESSAGE_REQUEST:
            start_patterns = HTTP_REQUEST_START_PATTERN_ARRAY;
            patterns_len = 9;
            DEBUG("[HTTP1.x PARSER][Find Frame Boundary] Finding request boundary.\n");
            break;
        case MESSAGE_RESPONSE:
            start_patterns = HTTP_RESPONSE_START_PATTERN_ARRAY;
            patterns_len = 2;
            DEBUG("[HTTP1.x PARSER][Find Frame Boundary] Finding response boundary.\n");
            break;
        case MESSAGE_UNKNOW:
            WARN("[HTTP1.x PARSER][Find Frame Boundary] Message type unknown, ignore it.\n");
            return PARSER_INVALID_BOUNDARY_INDEX;
    }

    // 查找帧边界标识，如-HTTP Response:
    //   leftover body (from previous message)
    //   状态行：   HTTP/1.1 ...
    //   响应头：   headers
    //   空行标识： \r\n\r\n
    //   响应体：   body
    // 首先查找\r\n\r\n的标记，然后再反过来查找状态行首的协议版本号
    // 不直接查找协议版本号作为帧边界，是因为可能会在req/resp中找到，导致分帧错误
    // 因此先找\r\n\r\n，再回头找最接近\r\n\r\n的协议号，这样比较准确
    while (true) {
        // 1.find the first "\r\n\r\n" sub-string in the raw_data.data
        size_t marker_pos = find_str(raw_data->data, kBoundaryMarker, raw_data->current_pos);

        // 如果pos数值不正确，返回-1
        if (marker_pos == -1) {
            WARN("[HTTP1.x PARSER][Find Frame Boundary] Message marker CRLF not found , return INVALID state.\n");
            return PARSER_INVALID_BOUNDARY_INDEX;
        }

        // 2.寻找子字符串: start_pos ~ marker_pos
        char *buf_substr = substr(raw_data->data + raw_data->current_pos, start_pos, marker_pos - start_pos);
        DEBUG("[HTTP1.x PARSER][Find Frame Boundary] Substr from start_pos[%d]~marker_pos[]%d is: %s\n", start_pos, marker_pos, buf_substr);

        // 3.匹配start_pos ~ marker_pos之间子串中的start_pattern，取最后一个（最靠近 "\r\n\r\n" 标志的帧边界）
        size_t substr_pos = -1;
        for (int i = 0; i < patterns_len; i++) {
            const char *start_pattern = start_patterns[i];
            size_t current_substr_pos = rfind_str(buf_substr, start_pattern);
            DEBUG("[HTTP1.x PARSER][Find Frame Boundary] Find frame start boundary, pos: %d\n", current_substr_pos);
            if (current_substr_pos != -1) {
                // 寻找一个最接近\r\n标志位置的起始位置，这个起始位置才是最可靠的帧边界，因此每个start_pattern都要找一遍
                size_t max_pos = substr_pos;
                if (max_pos < current_substr_pos) {
                    marker_pos = current_substr_pos;
                }
                substr_pos = (substr_pos == -1) ? current_substr_pos : max_pos;
            }
        }

        // 4.返回帧边界标志匹配到的位置
        if (substr_pos != -1) {
            DEBUG("[HTTP1.x PARSER][Find Frame Boundary] Frame boundary found, pos: %d\n", start_pos + substr_pos);
            return start_pos + substr_pos;
        }

        // 5.找不到帧边界时，将指针移至 "\r\n\r\n" 标志的末尾，进行下一个帧边界的寻找
        // Couldn't find a start position. Move to the marker, and search for another marker.
        raw_data->current_pos = marker_pos + strlen(kBoundaryMarker);
        WARN("[HTTP1.x PARSER][Find Frame Boundary] Frame boundary not found, move current_pos to the end of current marker, then find the next boundary.\n");
    }
}
