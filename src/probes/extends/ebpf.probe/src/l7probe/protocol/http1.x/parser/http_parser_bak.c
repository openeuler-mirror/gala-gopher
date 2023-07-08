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

/**
 * parse request body
 *
 * @param buf
 * @param result
 * @return
 */
parse_state_t parse_request_body(struct raw_data_s *raw_data, struct http_message *result) {
    // From https://tools.ietf.org/html/rfc7230:
    //  A sender MUST NOT send a Content-Length header field in any message
    //  that contains a Transfer-Encoding header field.
    //
    //  A user agent SHOULD send a Content-Length in a request message when
    //  no Transfer-Encoding is sent and the request method defines a meaning
    //  for an enclosed payload body.  For example, a Content-Length header
    //  field is normally sent in a POST request even when the value is 0
    //  (indicating an empty payload body).  A user agent SHOULD NOT send a
    //  Content-Length header field when the request message does not contain
    //  a payload body and the method semantics do not anticipate such a
    //  body.

    // Case 1: Content-Length
//    const auto content_length_iter = result->headers.find(kContentLength);
    http_headers_map *content_length_values = get_values_by_key(result->headers, kContentLength);
    if (content_length_values != NULL) {
//        char* content_len_str = content_length_values[0];
        parse_state_t state = parse_content(content_length_values[0], raw_data->data, FLAGS_http_body_limit_bytes, result->body, result->body_size);
        DCHECK_LE(result->body_size, FLAGS_http_body_limit_bytes);
        return state;
    }

//    char *content_length_iter = find_first_value(result->headers, kContentLength);
//    if (content_length_iter != result->headers.end()) {
//        std::string_view content_len_str = content_length_iter->second;
//        parse_state_t r = ParseContent(content_len_str, raw_data_s, FLAGS_http_body_limit_bytes, &result->body,
//                              &result->body_size);
//        DCHECK_LE(result->body.size(), FLAGS_http_body_limit_bytes);
//        return r;
//    }

    // Case 2: Chunked transfer.
    char *transfer_encoding_value = get_1st_value_by_key(result->headers, kTransferEncoding);
//    http_headers_map *transfer_encoding_values = get_values_by_key(result->headers, kTransferEncoding);
//    if (transfer_encoding_values != NULL && strcmp(transfer_encoding_values->values[0].value, "chunked") == 0) {
    if (transfer_encoding_value != NULL && strcmp(transfer_encoding_value, "chunked") == 0) {
        parse_state_t state = parse_chunked(raw_data->data, FLAGS_http_body_limit_bytes, &result->body, &result->body_size);
        DCHECK_LE(strlen(result->body), FLAGS_http_body_limit_bytes);
        return state;
    }

//
//
//    const auto transfer_encoding_iter = result->headers.find(kTransferEncoding);
//    if (transfer_encoding_iter != result->headers.end() &&
//        transfer_encoding_iter->second == "chunked") {
//        parse_state_t s = ParseChunked(raw_data_s, FLAGS_http_body_limit_bytes, &result->body, &result->body_size);
//        DCHECK_LE(result->body.size(), FLAGS_http_body_limit_bytes);
//        return s;
//    }

    // Case 3: Message has no Content-Length or Transfer-Encoding.
    // An HTTP request with no Content-Length and no Transfer-Encoding should not have a body when
    // no Content-Length or Transfer-Encoding is set:
    // "A user agent SHOULD NOT send a Content-Length header field when the request message does
    // not contain a payload body and the method semantics do not anticipate such a body."
    //
    // We apply this to all methods, since we have no better strategy in other cases.
    result->body = "";
    return STATE_SUCCESS;
}

parse_state_t parse_response_body(struct raw_data_s *raw_data, struct http_message *result) {
    // Case 0: Check for a HEAD response with no body.
    // Responses to HEAD requests are special, because they may include Content-Length
    // or Transfer-Encoding, but the body will still be empty.
    // Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/HEAD
    // TODO(rcheng): Pass in state to the parser so we know when to expect HEAD responses.
    if (result->type == MESSAGE_RESPONSE) {
        // We typically expect a body at this point, but for responses to HEAD requests,
        // there won't be a body. To detect such HEAD responses, we check to see if the next bytes
        // are actually the beginning of the next response by attempting to parse it.
        http_response *resp;

        int adjacent_resp = starts_with(raw_data->data, "HTTP") == 1 && http_parse_response_headers(raw_data, resp) > 0;
//                absl::StartsWith(*buf, "HTTP") && (pico_wrapper::parse_response(*buf, &r) > 0);

        if (adjacent_resp || (raw_data->data_len == 0)) {
            result->body = "";
            return STATE_SUCCESS;
        }
    }

    // Case 1: Content-Length
    http_headers_map *content_length_values = get_values_by_key(result->headers, kContentLength);
    if (content_length_values != NULL) {
//        char* content_len_str = content_length_values[0];
        parse_state_t state = parse_content(content_length_values[0], raw_data->data, FLAGS_http_body_limit_bytes, result->body, result->body_size);
        DCHECK_LE(result->body_size, FLAGS_http_body_limit_bytes);
        return state;
    }


//    const auto content_length_iter = result->headers.find(kContentLength);
//    if (content_length_iter != result->headers.end()) {
//        std::string_view content_len_str = content_length_iter->second;
//        auto s = ParseContent(content_len_str, buf, FLAGS_http_body_limit_bytes, &result->body,
//                              &result->body_size);
//        DCHECK_LE(result->body.size(), FLAGS_http_body_limit_bytes);
//        return s;
//    }

    // Case 2: Chunked transfer.
    char *transfer_encoding_value = get_1st_value_by_key(result->headers, kTransferEncoding);
//    http_headers_map *transfer_encoding_values = get_values_by_key(result->headers, kTransferEncoding);
//    if (transfer_encoding_values != NULL && strcmp(transfer_encoding_values->values[0].value, "chunked") == 0) {
    if (transfer_encoding_value != NULL && strcmp(transfer_encoding_value, "chunked") == 0) {
        parse_state_t state = parse_chunked(raw_data->data, FLAGS_http_body_limit_bytes, &result->body, &result->body_size);
        DCHECK_LE(strlen(result->body), FLAGS_http_body_limit_bytes);
        return state;
    }

//    const auto transfer_encoding_iter = result->headers.find(kTransferEncoding);
//    if (transfer_encoding_iter != result->headers.end() &&
//        transfer_encoding_iter->second == "chunked") {
//        auto s = ParseChunked(buf, FLAGS_http_body_limit_bytes, &result->body, &result->body_size);
//        DCHECK_LE(result->body.size(), FLAGS_http_body_limit_bytes);
//        return s;
//    }

    // Case 3: Responses where we can assume no body.
    // The status codes below MUST not have a body, according to the spec.
    // See: https://tools.ietf.org/html/rfc2616#section-4.4
    if ((result->resp_status >= 100 && result->resp_status < 200) || result->resp_status == 204 ||
        result->resp_status == 304) {
        result->body = "";

        // Status 101 is an even more special case.
        if (result->resp_status == 101) {
            http_headers_map *upgrade_values = get_values_by_key(result->headers, kUpgrade);

            if (upgrade_values == NULL) {
                WARN("Expected an Upgrade header with HTTP status 101");
            }

            WARN("HTTP upgrades are not yet supported");
            return STATE_EOS;
        }

        return STATE_SUCCESS;
    }

//    // Case 4: Response where we can't assume no body, but where no Content-Length or
//    // Transfer-Encoding is provided. In these cases we should wait for close().
//    // According to HTTP/1.1 standard:
//    // https://www.w3.org/Protocols/HTTP/1.0/draft-ietf-http-spec.html#BodyLength
//    // such messages are terminated by the close of the connection.
//    // TODO(yzhao): For now we just accumulate messages, let probe_close() submit a message to
//    // perf buffer, so that we can terminate such messages.
//    if (state->conn_closed) {
//        result->body = *raw_data->data;
//
////        buf->remove_prefix(buf->size());
//        raw_data->current_pos = strlen(raw_data->data);
//
//        WARN("HTTP message with no Content-Length or Transfer-Encoding may produce "
//                "incomplete message bodies.");
//        return STATE_SUCCESS;
//    }
    return STATE_NEEDS_MORE_DATA;
}
