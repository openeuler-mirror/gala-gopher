///******************************************************************************
// * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
// * gala-gopher licensed under the Mulan PSL v2.
// * You can use this software according to the terms and conditions of the Mulan PSL v2.
// * You may obtain a copy of Mulan PSL v2 at:
// *     http://license.coscl.org.cn/MulanPSL2
// * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
// * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
// * PURPOSE.
// * See the Mulan PSL v2 for more details.
// * Author: eank
// * Create: 2023-04-20
// * Description:
// ******************************************************************************/
//
//#include "http_body_decoder.h"
//#include "../util/string_utils.h"
//#include "../util/decimal_utils.h"
//
//// Length of the CRLF delimiter in HTTP.
//const int kDelimiterLen = 2;
//
///**
// * Extracts the HTTP chunk header, which encodes the chunk length and an optional chunk extension.
// *
// * Examples:
// *    9\r\n             <--- Returns 9
// *    1F\r\n            <--- Returns 31
// *    9;key=value\r\n   <--- Returns 9; This example shows the concept called chunk extensions.
// *
// * @param data Data buffer of the HTTP chunked-encoding message body. The byte of this string_view
// *             are consumed as they are processed
// * @param out A pointer to a variable where the parsed length will be written.
// * @return ParseState::kInvalid if message is malformed.
// *         ParseState::kNeedsMoreData if the message is incomplete.
// *         ParseState::kSuccess if the chunk length was extracted and chunk header is well-formed.
// */
//enum parse_state_t ExtractChunkLength(std::string_view* data, size_t* out) {
//    size_t chunk_len = 0;
//
//    // Maximum number of hex characters we allow in a chunked length encoding.
//    // Choosing a large number to account for chunk extensions.
//    // HTTP protocol does not specify a size limit for these, but we set a practical limit.
//    // Note that HTTP servers do similar things for HTTP headers
//    // (e.g. Apache sets an 8K limit for headers).
//    constexpr int kSearchWindow = 2048;
//
//    size_t delimiter_pos = data->substr(0, kSearchWindow).find("\r\n");
//    if (delimiter_pos == data->npos) {
//        return data->length() > kSearchWindow ? ParseState::kInvalid : ParseState::kNeedsMoreData;
//    }
//
//    std::string_view chunk_len_str = data->substr(0, delimiter_pos);
//
//    // Remove chunk extensions if present.
//    size_t chunk_ext_pos = chunk_len_str.find(";");
//    if (chunk_ext_pos != chunk_len_str.npos) {
//        chunk_len_str = chunk_len_str.substr(0, chunk_ext_pos);
//    }
//
//    bool success = absl::SimpleHexAtoi(chunk_len_str, &chunk_len);
//    if (!success) {
//        return STATE_INVALID;
//    }
//
//    data->remove_prefix(delimiter_pos + kDelimiterLen);
//
//    *out = chunk_len;
//    return STATE_SUCCESS;
//}
//
///**
// * Extracts the HTTP chunk data, given the chunk length.
// *
// * @param data Data buffer of the HTTP chunked-encoding message body starting at the chunk data
// *             (chunk length should have already been removed).
// *             The byte of this string_view are consumed as they are processed
// * @param out A string_view to the chunk contents that will be set upon success.
// * @return ParseState::kInvalid if message is malformed.
// *         ParseState::kNeedsMoreData if the message is incomplete.
// *         ParseState::kSuccess if the chunk data was extracted and chunk data was well-formed.
// */
//enum parse_state_t ExtractChunkData(std::string_view* data, size_t chunk_len, std::string_view* out) {
//    std::string_view chunk_data;
//
//    if (data->length() < chunk_len + kDelimiterLen) {
//        return STATE_NEEDS_MORE_DATA;
//    }
//
//    chunk_data = data->substr(0, chunk_len);
//
//    data->remove_prefix(chunk_len);
//
//    // Expect a \r\n to terminate the data chunk.
//    if ((*data)[0] != '\r' || (*data)[1] != '\n') {
//        return STATE_INVALID;
//    }
//
//    data->remove_prefix(kDelimiterLen);
//
//    *out = chunk_data;
//    return STATE_SUCCESS;
//}
//
//
//// This is an alternative to the picohttpparser implementation,
//// because that one is destructive on incomplete data.
//// We may attempt parsing in the middle of a stream and cannot
//// have both the result fail and the input buffer be modified.
//// Reference: https://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.6.1
//enum parse_state_t CustomParseChunked(std::string_view* buf, size_t body_size_limit_bytes,
//                              std::string* result, size_t* body_size) {
//    std::vector<std::string_view> chunks;
//    size_t total_bytes = 0;
//
//    std::string_view data = *buf;
//
//    parse_state_t s;
//
//    while (true) {
//        // Extract the chunk length.
//        size_t chunk_len = 0;
//        s = ExtractChunkLength(&data, &chunk_len);
//        if (s != STATE_SUCCESS) {
//            return s;
//        }
//
//        // A length of zero marks the end of data.
//        if (chunk_len == 0) {
//            break;
//        }
//
//        // Extract the chunk data.
//        std::string_view chunk_data;
//        s = ExtractChunkData(&data, chunk_len, &chunk_data);
//        if (s != STATE_SUCCESS) {
//            return s;
//        }
//
//        // Only bother collecting chunks up to a certain size, since we will truncate anyways.
//        // Don't break out of the parsing though, since we need to know where the body ends.
//        if (total_bytes + chunk_data.size() < body_size_limit_bytes) {
//            chunks.push_back(chunk_data);
//        } else if (total_bytes < body_size_limit_bytes) {
//            size_t bytes_available = body_size_limit_bytes - total_bytes;
//            chunks.push_back(chunk_data.substr(0, bytes_available));
//        }
//
//        total_bytes += chunk_data.size();
//    }
//
//    // Two scenarios to wrap up:
//    //   No trailers (common case): Immediately expect one more \r\n
//    //   Trailers: End on next \r\n\r\n.
//    if (data.length() >= kDelimiterLen && data[0] == '\r' && data[1] == '\n') {
//        data.remove_prefix(kDelimiterLen);
//    } else {
//        // HTTP doesn't specify a limit on how big headers and trailers can be.
//        // 8K is the maximum headers size in many popular HTTP servers (like Apache),
//        // so use that as a proxy of the maximum trailer size we can expect.
//        constexpr int kSearchWindow = 8192;
//
//        size_t pos = data.substr(0, kSearchWindow).find("\r\n\r\n");
//        if (pos == data.npos) {
//            return data.length() > kSearchWindow ? ParseState::kInvalid : ParseState::kNeedsMoreData;
//        }
//
//        data.remove_prefix(pos + 4);
//    }
//
//    *result = absl::StrJoin(chunks, "");
//    *body_size = total_bytes;
//
//    // Update the input buffer only if the data was parsed properly, because
//    // we don't want to be destructive on failure.
//    *buf = data;
//    return STATE_SUCCESS;
//}
//
//// Parse an HTTP chunked body using pico's parser. This implementation
//// has the disadvantage that it incurs a potentially expensive copy even when
//// the final result is kNeedsMoreData.
//// See our Custom implementation for an alternative that doesn't have that cost.
//enum parse_state_t PicoParseChunked(std::string_view* data, size_t body_size_limit_bytes,
//                            std::string* result, size_t* body_size) {
//    // Make a copy of the data because phr_decode_chunked mutates the input,
//    // and if the original parse fails due to a lack of data, we need the original
//    // state to be preserved.
//    std::string data_copy(*data);
//
//    phr_chunked_decoder chunk_decoder = {};
//    chunk_decoder.consume_trailer = 1;
//    char* buf = data_copy.data();
//    size_t buf_size = data_copy.size();
//    ssize_t retval = phr_decode_chunked(&chunk_decoder, buf, &buf_size);
//
//    if (retval == -1) {
//        // Parse failed.
//        return STATE_INVALID;
//    } else if (retval == -2) {
//        // Incomplete message.
//        return STATE_NEEDS_MORE_DATA;
//    } else if (retval >= 0) {
//        // Found a complete message.
//        data_copy.resize(std::min(buf_size, body_size_limit_bytes));
//        data_copy.shrink_to_fit();
//        *result = std::move(data_copy);
//        *body_size = buf_size;
//
//        // phr_decode_chunked rewrites the buffer in place, removing chunked-encoding headers.
//        // So we cannot simply remove the prefix, but rather have to shorten the buffer too.
//        // This is done via retval, which specifies how many unprocessed bytes are left.
//        data->remove_prefix(data->size() - retval);
//
//        return STATE_SUCCESS;
//    }
//
//    LOG(DFATAL) << "Unexpected retval from phr_decode_chunked()";
//    return STATE_UNKNOWN;
//}
//
//// Parse an HTTP message body in the chunked transfer-encoding.
//// Reference: https://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.6.1
//parse_state_t parse_chunked(char** buf, size_t body_size_limit_bytes, char** result, size_t* body_size) {
//    return CustomParseChunked(data, body_size_limit_bytes, result, body_size);
//}
//
//parse_state_t parse_content(char* content_len_str, char** data,
//                            size_t body_size_limit_bytes, char** result, size_t* body_size) {
//    size_t len;
//    if (!simple_atoi(content_len_str, &len)) {
//        ERROR("Unable to parse Content-Length: %s", content_len_str);
//        return STATE_INVALID;
//    }
//
//    if (strlen(data)< len) {
//        return STATE_NEEDS_MORE_DATA;
//    }
//
////    *result = data->substr(0, std::min(len, body_size_limit_bytes));
//    *result = substr(data, 0, min(len, body_size_limit_bytes));
//    *body_size = len;
//    remove_prefix(data, min(len, strlen(data)));
//    return STATE_SUCCESS;
//}
