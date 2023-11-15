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
    if (raw_data->current_pos == raw_data->data_len) {
        return STATE_NEEDS_MORE_DATA;
    }
#define CHUNKED_SEARCH_WINDOW  2048
#define CHUNKED_DELIMITER      "\r\n"
    const size_t delimiter_len = strlen(CHUNKED_DELIMITER);
    char data_search[CHUNKED_SEARCH_WINDOW + 1];
    char *data = raw_data->data + raw_data->current_pos;
    size_t data_len = raw_data->data_len - raw_data->current_pos;
    size_t total_size = 0;
    while (true) {
        size_t chunked_len = 0;
        (void)strncpy(data_search, data, CHUNKED_SEARCH_WINDOW);
        data_search[CHUNKED_SEARCH_WINDOW] = 0;
        size_t deli_pos = find_str(data_search, CHUNKED_DELIMITER, 0);
        if (deli_pos == -1 || deli_pos == data_len) {
            return data_len > CHUNKED_SEARCH_WINDOW ? STATE_INVALID : STATE_NEEDS_MORE_DATA;
        }

        // There is data length in the beginning of every chunked data, separated by ';' with extension(not necessarily present),
        // and if it is present, then we refresh the value of 'len'
        // Format: chunked_data_len ; extension | \r\n | data
        // Sample:
        // 5
        // hello
        // 0
        char *chunked_len_str = substr(data, 0, deli_pos);
        if (chunked_len_str == NULL) {
            ERROR("[HTTP1.x PARSER] Failed to alloc chunked len buf\n");
            return STATE_INVALID;
        }

        char *ext = strchr(chunked_len_str, ';');
        if (ext != NULL) {
            *ext = 0;
        }

        chunked_len = atoi(chunked_len_str);
        free(chunked_len_str);
        if (data - raw_data->data == raw_data->data_len) {
            return STATE_NEEDS_MORE_DATA;
        }

        // pointer offset for the length of 'deli_pod + delimiter_len'
        data += deli_pos + delimiter_len;

        // the chunked data ends with a character '0', exit the cycle if meets a '0', and refresh the pointer
        if (chunked_len == 0) {
            raw_data->current_pos = data - raw_data->data;
            break;
        }

        // NOTE: Not support for parsing chunked data now
        if (strlen(data) < chunked_len + delimiter_len) {
            return STATE_NEEDS_MORE_DATA;
        }

        // pointer offset for chunked_len, skip the content ended up with '\r\n'
        data += chunked_len;

        // the pointer is at the end of the data without a '0', we need more data to continue parsing
        if (data - raw_data->data == raw_data->data_len) {
            return STATE_NEEDS_MORE_DATA;
        }

        // there is '\r\n' at the end of the data line. If not, it means an ERROR of data
        if (data[0] != '\r' || data[1] != '\n') {
            return STATE_INVALID;
        }
        data += delimiter_len;

        // accumulate the total_size of the chunked data
        total_size += chunked_len;
    }

    raw_data->current_pos = data - raw_data->data;

    // Note: we do not need body currently
    *offset = total_size;
    return STATE_SUCCESS;
}

/**
 * Parse request body
 * There are 3 cases for request body:
 * 1) When there is Content-Length in headers, the field means the length of the request body.
 * If there is no Transfer-Encoding in headers, the HTTP Client must have the field of Content-Length.
 * 2) When there is Transfer-Encoding, and no Content-Length in headers, we need to process the scenario of Transfer-Encoding=Chunked
 * 3) When there is no Content-Length or Transfer-Encoding, it means the packet has no body.
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
        // Content-Length is not 0, then return STATE_INVALID to tell failed
        if (strcmp(content_len_str, "0") != 0 && content_len == 0) {
            WARN("[HTTP1.x PARSER] Failed to parse content-Length.\n");
            return STATE_INVALID;
        }
        if (content_len > raw_data->data_len - raw_data->current_pos) {
            DEBUG("[HTTP1.x PARSER] Parsing request body needs more data.\n");
            return STATE_NEEDS_MORE_DATA;
        }
        frame_data->body_size = content_len;
        raw_data->current_pos += content_len;
        return STATE_SUCCESS;
    }

    // 2. Transfer-Encoding: Chunked
    char *transfer_encoding = get_1st_value_by_key(frame_data->headers, KEY_TRANSFER_ENCODING);
    if (transfer_encoding != NULL && strcmp(transfer_encoding, "chunked") == 0) {
        parse_state_t state = parse_chunked(raw_data, &offset, &(frame_data->body));
        frame_data->body_size = offset;
        return state;
    }

    // 3. No Content-Length or Transfer-Encoding, it means no packet body to parse, then return STATE_SUCCESS
    frame_data->body_size = 0;
    return STATE_SUCCESS;
}

/**
 * Parse response body
 * There are 5 cases for response body:
 * 1) If the response is for HEAD request, the response packet has no body. We judge if the follow content is start with HTTP Version such as 'HTTP'.
 * 2) When there is Content-Length in response headers, We take it as the length of response body, just make the pointer offset.
 * 3) When there is no Content-Length but Transfer-Encoding=chunked, We process it the same as request.
 * 4) We have knowledge of some scenarios of no body according to the status code of response, such as [100,199], {204, 304]. And 101 UPGRADE is special, we have not support it yet.
 * 5) When there is no Content-Length or Transfer-Encoding, we don not know if the packet has body, we skip it with no processing currently.
 * NOTE: The pointer of raw_data.current_pos has offset after parsing headers before Parsing body. If the Parser returns non-success state, the caller should fallback the pointer, if success then offset.
 *
 * @param raw_data
 * @param frame_data
 * @return
 */
static parse_state_t parse_response_body(struct raw_data_s *raw_data, struct http_message *frame_data)
{
    size_t offset = 0;
    char *buf = raw_data->data + raw_data->current_pos;

    // 1. When the response is of HEAD request, we have parsed the response headers, the pointer is at the start of next frame started with HTTP Version such as HTTP.
    if (frame_data->type == MESSAGE_RESPONSE && starts_with(buf, "HTTP") == 1) {
        http_response resp = {0};
        size_t next_resp_header_offset = http_parse_response_headers(raw_data, &resp);
        if (next_resp_header_offset > 0) {
            frame_data->body_size = 0;
            return STATE_SUCCESS;
        }
    }

    // 2. Content-Length
    char *content_len_str = get_1st_value_by_key(frame_data->headers, KEY_CONTENT_LENGTH);
    if (content_len_str != NULL) {
        size_t content_len = atoi(content_len_str);
        // If Content-Length is not 0, it returns invalid while parsing failed.
        if (strcmp(content_len_str, "0") != 0 && content_len == 0) {
            WARN("[HTTP1.x PARSER] Failed to parse content-Length.\n");
            return STATE_INVALID;
        }
        if (content_len > raw_data->data_len - raw_data->current_pos) {
            DEBUG("[HTTP1.x PARSE] Parsing response body needs more data.\n");
            return STATE_NEEDS_MORE_DATA;
        }
        frame_data->body_size = content_len;
        raw_data->current_pos += content_len;
        return STATE_SUCCESS;
    }

    // 3. When Transfer-Encoding = chunked
    char *transfer_encoding = get_1st_value_by_key(frame_data->headers, KEY_TRANSFER_ENCODING);
    if (transfer_encoding != NULL && strcmp(transfer_encoding, "chunked") == 0) {
        parse_state_t state = parse_chunked(raw_data, &offset, &(frame_data->body));

        // note: we do not need body currently, just take the length of body.
        frame_data->body_size = offset;
        return state;
    }

    // 4. When there is no body as we know according to the status code of [100, 199], {204, 304}. 101 UPGRADE is special, we do not support it yet.
    if ((frame_data->resp_status >= 100 && frame_data->resp_status < 200) || frame_data->resp_status == 204 ||
        frame_data->resp_status == 304) {
        frame_data->body_size = 0;

        if (frame_data->resp_status == 101) {
            char *upgrade_str = get_1st_value_by_key(frame_data->headers, KEY_UPGRADE);
            if (upgrade_str == NULL) {
                DEBUG("[HTTP1.x PARSER] Expected an Upgrade header with http status code 101.\n");
            }
            DEBUG("[HTTP1.x PARSER] Http Upgrades are not supported yet.\n");
            return STATE_EOS;
        }
        return STATE_SUCCESS;
    }

    // 5. We do not know if the frame has body, while it has neither Content-Length nor Transfer-Encoding. We skip it currently.
    frame_data->body_size = 0;

    raw_data->current_pos += offset;
    return STATE_SUCCESS;
}

/**
 * Parse request
 *
 * @param buf
 * @param result
 * @return
 */
static parse_state_t parse_request_frame(struct raw_data_s *raw_data, http_message *frame_data) {
    http_request req = {0};

    // Parse request headers
    size_t offset = http_parse_request_headers(raw_data, &req);

    // If retval is -2, it means parsing successfully partially, but need more data to continue parsing.
    if (offset == -2) {
        DEBUG("[HTTP1.x PARSER] Parser needs more data.\n");
        return STATE_NEEDS_MORE_DATA;
    }

    // If retval is -1, it means parsing failed.
    if (offset == -1) {
        WARN("[HTTP1.x PARSER] Failed to parse raw_data into request.\n");
        return STATE_INVALID;
    }

    // Generate frame
    frame_data->type = MESSAGE_REQUEST;
    frame_data->timestamp_ns = raw_data->timestamp_ns;
    frame_data->minor_version = req.minor_version;
    frame_data->headers = get_http_headers_map(req.headers, req.num_headers);
    frame_data->req_method = strndup(req.method, req.method_len);
    frame_data->req_path = strndup(req.path, req.path_len);

    frame_data->headers_byte_size = offset;

    // raw_data offset
    raw_data->current_pos += offset;
    DEBUG("[HTTP1.x PARSER] Parsing req, offset: %d, raw_data.current_pos: %d.\n", offset, raw_data->current_pos);

    // Parse request body
    parse_state_t state = parse_request_body(raw_data, frame_data);
    if (state != STATE_SUCCESS) {
        raw_data->current_pos -= offset;
    }
    DEBUG("[HTTP1.x PARSER] Finished Parsing req, state: %d, current_pos: %d.\n", state, raw_data->current_pos);
    return state;
}

/**
 * Parse response
 *
 * @param buf
 * @param result
 * @param state
 * @return
 */
static parse_state_t parse_response_frame(struct raw_data_s *raw_data, struct http_message *frame_data) {
    http_response resp = {0};

    // Parse response header
    size_t offset = http_parse_response_headers(raw_data, &resp);

    // If retval is -2, it means parsing successfully partially, but need more data to continue parsing.
    if (offset == -2) {
        DEBUG("[HTTP1.x PARSER] Parser needs more data.\n");
        return STATE_NEEDS_MORE_DATA;
    }

    // If retval is -1, it means parsing failed.
    if (offset == -1) {
        WARN("[HTTP1.x PARSER] Failed to parse raw_data into response, offset code: %d\n", offset);
        return STATE_INVALID;
    }

    // Generate frame
    frame_data->type = MESSAGE_RESPONSE;
    frame_data->timestamp_ns = raw_data->timestamp_ns;
    frame_data->minor_version = resp.minor_version;
    frame_data->headers = get_http_headers_map(resp.headers, resp.num_headers);
    frame_data->resp_status = resp.status;
    frame_data->resp_message = strndup(resp.msg, resp.msg_len);
    frame_data->headers_byte_size = offset;

    // raw_data pointer offset
    raw_data->current_pos += offset;

    // Parse response body
    parse_state_t state = parse_response_body(raw_data, frame_data);
    if (state != STATE_SUCCESS) {
        raw_data->current_pos -= offset;
    }

    DEBUG("[HTTP1.x PARSER] Finished Parsing resp, state: %d, current_pos: %d.\n", state, raw_data->current_pos);
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
            DEBUG("[HTTP1.x PARSER] Message type invalid.\n");
            break;
    }
    if (state != STATE_SUCCESS) {
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
    DEBUG("[HTTP1.x PARSER] Parse frame finished, msg_type: %d, ts: %lu\n", msg_type, http_msg->timestamp_ns);
    return state;
}

size_t http_find_frame_boundary(enum message_type_t msg_type, struct raw_data_s *raw_data) {
    DEBUG("[HTTP1.x PARSER] Start finding frame boundary, current_pos: %d\n", raw_data->current_pos);
    size_t start_pos = raw_data->current_pos;

    // All HTTP Request Method, HTTP Request packet starts with Method. Methods Reference:
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
    static const char *HTTP_REQUEST_START_PATTERN_ARRAY[] = {
        "GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "CONNECT ", "OPTIONS ", "TRACE ", "PATCH "
    };

    // HTTP 1.x versions, HTTP response packet starts with Version. HTTP Version Reference:
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages
    static const char *HTTP_RESPONSE_START_PATTERN_ARRAY[] = {"HTTP/1.1 ", "HTTP/1.0 "};

    static const char* BOUNDARY_MARKER = "\r\n\r\n";

    // Select packet start pattern according to req/resp
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
            DEBUG("[HTTP1.x PARSER][Find Frame Boundary] Message type unknown, ignore it.\n");
            return PARSER_INVALID_BOUNDARY_INDEX;
    }

    // Find Frame Boundary Marker, take resp as sample:
    //   leftover body (from previous message)
    //   Status Line：           HTTP/1.1 ...
    //   Response Headers：      headers
    //   Blank Line Marker：     \r\n\r\n
    //   Response Body：         body
    // Find marker '\r\n\r\n' firstly, then reversely find the beginning of packet, HTTP Version for response.
    // NOTE: We do not take HTTP Version as frame boundary directly, because it may be found in req/resp body, then cause error for separating frames.
    while (true) {
        // 1. Find the first "\r\n\r\n" sub-string position in the raw_data.data
        size_t marker_pos = find_str(raw_data->data, BOUNDARY_MARKER, raw_data->current_pos);

        // 如果pos数值不正确，返回-1
        if (marker_pos == -1) {
            DEBUG("[HTTP1.x PARSER][Find Frame Boundary] Message marker CRLF not found , return INVALID state.\n");
            return PARSER_INVALID_BOUNDARY_INDEX;
        }

        // 2. Find sub-string: raw_data.data[start_pos, marker_pos]
        char *buf_substr = substr(raw_data->data + raw_data->current_pos, start_pos, marker_pos - start_pos);
        if (buf_substr == NULL) {
            ERROR("[HTTP1.x PARSER][Find Frame Boundary] Failed to alloc substr buf\n");
            return PARSER_INVALID_BOUNDARY_INDEX;
        }

        DEBUG("[HTTP1.x PARSER][Find Frame Boundary] Substr from start_pos[%d]~marker_pos[%d] is: \n%s\n", start_pos, marker_pos, buf_substr);

        // 3. Match start_pattern in raw_data.data[start_pos, marker_pos], take the last one as frame boundary
        size_t substr_pos = -1;
        for (int i = 0; i < patterns_len; i++) {
            const char *start_pattern = start_patterns[i];
            size_t current_substr_pos = rfind_str(buf_substr, start_pattern);
            DEBUG("[HTTP1.x PARSER][Find Frame Boundary] Find frame start boundary, pos: %d\n", current_substr_pos);
            if (current_substr_pos != -1) {
                // Find the position most next to '\r\n\r\n' as start position, this one is the most reliable. So we find for every start_pattern.
                size_t max_pos = substr_pos;
                if (max_pos < current_substr_pos) {
                    marker_pos = current_substr_pos;
                }
                substr_pos = (substr_pos == -1) ? current_substr_pos : max_pos;
            }
        }
        free(buf_substr);

        // 4. Return the position of frame boundary.
        if (substr_pos != -1) {
            DEBUG("[HTTP1.x PARSER][Find Frame Boundary] Frame boundary found, pos: %d\n", start_pos + substr_pos);
            return start_pos + substr_pos;
        }

        // 5. When we have not found frame boundary, we move the data pointer to the end of '\r\n\r\n', then start next finding.
        raw_data->current_pos = marker_pos + strlen(BOUNDARY_MARKER);
        DEBUG("[HTTP1.x PARSER][Find Frame Boundary] Frame boundary not found, move current_pos to the end of current marker, then find the next boundary.\n");
    }
}
