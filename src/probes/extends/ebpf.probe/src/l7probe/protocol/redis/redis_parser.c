/*******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: niebin
 * Create: 2023-04-12
 * Description:
 ******************************************************************************/
#include <string.h>
#include <stdint.h>
#include <utarray.h>
#include "utils/binary_decoder.h"
#include "utils/string_utils.h"
#include "common/protocol_common.h"
#include "l7.h"
#include "redis_msg_format.h"
#include "format.h"
#include "redis_parser.h"

const char SIMPLE_STRING_MARKER = '+';
const char ERROR_MARKER = '-';
const char INTEGER_MARKER = ':';
const char BULK_STRINGS_MARKER = '$';
const char ARRAY_MARKER = '*';
// Redis' terminating sequence
const char *TERMINAL_SEQUENCE = "\r\n";
const int NULL_SIZE = -1;

// Parse the size of bulk strings or array.
static parse_state_t parse_size(struct raw_data_s *raw_data_buf, int *size)
{
    char *size_str = NULL;
    char *endptr;
    const int decimal_base = 10;
    const size_t SIZE_STR_MAX_LEN = 16;

    parse_state_t state = decoder_extract_str_until_str(raw_data_buf, &size_str, TERMINAL_SEQUENCE);
    if (state != STATE_SUCCESS) {
        return state;
    }

    if (strlen(size_str) > SIZE_STR_MAX_LEN) {
        ERROR("[Redis Parse] The size of the string in Redis is exceeding %d, implying that the traffic might have been"
              "incorrectly categorized as Redis.\n", SIZE_STR_MAX_LEN);
        free(size_str);
        return STATE_INVALID;
    }

    // Length could be -1, which stands for NULL, so initiate value is -2.
    *size = -2;

    *size = strtol(size_str, &endptr, decimal_base);
    if (*endptr != '\0') {
        ERROR("[Redis Parse] String %s cannot be parsed as integer.\n", size_str);
        free(size_str);
        return STATE_INVALID;
    }

    if (*size < NULL_SIZE) {
        ERROR("[Redis Parse] Size cannot be less than %d, got %s.\n", NULL_SIZE, size_str);
        free(size_str);
        return STATE_INVALID;
    }

    free(size_str);
    return STATE_SUCCESS;
}

static bool is_pub_msg(const UT_array *payloads)
{
    // Published message format is at https://redis.io/topics/pubsub#format-of-pushed-messages
    const size_t ARRAY_PAYLOAD_SIZE = 3;
    const char *MESSAGE_STR = "MESSAGE";

    if (payloads == NULL) {
        return false;
    }
    if (utarray_len(payloads) < ARRAY_PAYLOAD_SIZE) {
        return false;
    }
    if (!strcasecmp(*(char **)utarray_front(payloads), MESSAGE_STR)) {
        return false;
    }
    return true;
}

// The format of a Bulk string is as follows: <length>\r\n<actual string, up to 512MB>\r\n
static parse_state_t parse_bulk_string_msg(struct raw_data_s *raw_data_buf, struct redis_msg_s *msg)
{
    int len = -2;
    const int kMaxLen = 512 * 1024 * 1024;
    char *payload = NULL;

    parse_state_t state = parse_size(raw_data_buf, &len);
    if (state != STATE_SUCCESS) {
        return state;
    }

    if (len > kMaxLen) {
        ERROR("[Redis Parse] The size of bulk string cannot be larger than 512MB, got %d.\n", len);
        return STATE_INVALID;
    }

    if (len == NULL_SIZE) {
        char *NULL_BULK_STRING = "<NULL>";
        free(msg->payload);

        msg->payload = strdup(NULL_BULK_STRING);
        return STATE_SUCCESS;
    }

    state = decoder_extract_string(raw_data_buf, &payload, len + strlen(TERMINAL_SEQUENCE));
    if (state != STATE_SUCCESS) {
        return state;
    }

    if (!is_end_with(payload, TERMINAL_SEQUENCE)) {
        ERROR("[Redis Parse] Bulk string should be terminated by \\r\\n.\n");
        free(payload);
        return STATE_INVALID;
    }
    free(msg->payload);

    msg->payload = remove_suffix(payload, strlen(TERMINAL_SEQUENCE));
    return STATE_SUCCESS;
}

static parse_state_t parse_msg_recursive(enum message_type_t msg_type, struct raw_data_s *raw_data,
    struct redis_msg_s *msg);

// The format of Array is as follows: *<size_str>\r\n[one of simple string, error, bulk string, etc.]
static parse_state_t parse_array_msg(enum message_type_t msg_type, struct raw_data_s *raw_data_buf,
    struct redis_msg_s *msg)
{
    int len = -2;
    UT_array *payloads;

    parse_state_t state = parse_size(raw_data_buf, &len);
    if (state != STATE_SUCCESS) {
        return state;
    }

    if (len == NULL_SIZE) {
        char *NULL_ARRAY = "[NULL]";
        msg->payload = strdup(NULL_ARRAY);
        return STATE_SUCCESS;
    }

    utarray_new(payloads, &ut_str_icd);
    for (int i = 0; i < len; ++i) {
        struct redis_msg_s tmp_msg = {0};
        parse_state_t recur_parse_state = parse_msg_recursive(msg_type, raw_data_buf, &tmp_msg);
        if (tmp_msg.payload == NULL) {
            utarray_free(payloads);
            return STATE_INVALID;
        }

        if (recur_parse_state != STATE_SUCCESS) {
            utarray_free(payloads);
            free(tmp_msg.payload);
            return recur_parse_state;
        }

        utarray_push_back(payloads, &tmp_msg.payload);
        free(tmp_msg.payload);
        msg->single_reply_msg_count = tmp_msg.single_reply_msg_count;
        msg->single_reply_error_msg_count = tmp_msg.single_reply_error_msg_count;
    }

    format_array_msg(payloads, msg);

    if (msg_type == MESSAGE_REQUEST && is_pub_msg(payloads)) {
        msg->is_pub_msg = true;
    }
    utarray_free(payloads);

    return STATE_SUCCESS;
}

// Redis parse recursive function
static parse_state_t parse_msg_recursive(enum message_type_t msg_type, struct raw_data_s *raw_data,
    struct redis_msg_s *msg)
{
    char type_marker;
    parse_state_t state = decoder_extract_char(raw_data, &type_marker);
    if (state != STATE_SUCCESS) {
        return state;
    }

    if (type_marker == SIMPLE_STRING_MARKER) {
        if (msg_type == MESSAGE_RESPONSE) {
            ++msg->single_reply_msg_count;
        }
        return decoder_extract_str_until_str(raw_data, &(msg->payload), TERMINAL_SEQUENCE);
    }

    if (type_marker == BULK_STRINGS_MARKER) {
        if (msg_type == MESSAGE_RESPONSE) {
            ++msg->single_reply_msg_count;
        }
        return parse_bulk_string_msg(raw_data, msg);
    }

    if (type_marker == ERROR_MARKER) {
        char *str = NULL;
        parse_state_t extract_str_state = decoder_extract_str_until_str(raw_data, &str, TERMINAL_SEQUENCE);
        if (extract_str_state != STATE_SUCCESS) {
            return extract_str_state;
        }

        // Append ERROR_MARKER
        char *payload = malloc((strlen(str) + 2) * sizeof(char));
        if (payload == NULL) {
            ERROR("[Redis Parse] Malloc payload failed.\n");
            free(str);
            return STATE_INVALID;
        }
        memset(payload, 0, (strlen(str) + 2) * sizeof(char));
        strcpy(payload, "-");
        strcat(payload, str);
        free(msg->payload);

        msg->payload = payload;
        if (msg_type == MESSAGE_RESPONSE) {
            ++msg->single_reply_error_msg_count;
            ++msg->single_reply_msg_count;
        }

        // str 在decoder后指向了动态分配内存, 需要手动释放
        free(str);
        return STATE_SUCCESS;
    }

    if (type_marker == INTEGER_MARKER) {
        if (msg_type == MESSAGE_RESPONSE) {
            ++msg->single_reply_msg_count;
        }
        return decoder_extract_str_until_str(raw_data, &(msg->payload), TERMINAL_SEQUENCE);
    }

    if (type_marker == ARRAY_MARKER) {
        return parse_array_msg(msg_type, raw_data, msg);
    }

    ERROR("[Redis Parse] Invalid redis type marker char: %c.\n", type_marker);
    return STATE_INVALID;
}

size_t redis_find_frame_boundary(struct raw_data_s *raw_data)
{
    for (size_t pos = raw_data->current_pos; pos < raw_data->data_len; ++pos) {
        char type_marker = (raw_data->data)[pos];
        if (type_marker == SIMPLE_STRING_MARKER || type_marker == ERROR_MARKER || type_marker == INTEGER_MARKER ||
            type_marker == BULK_STRINGS_MARKER || type_marker == ARRAY_MARKER) {
            return pos;
        }
    }
    return PARSER_INVALID_BOUNDARY_INDEX;
}

parse_state_t redis_parse_frame(enum message_type_t msg_type, struct raw_data_s *raw_data,
        struct frame_data_s **frame_data)
{
    // 校验raw_data缓存长度是否合法
    if ((raw_data->data_len == 0 || raw_data->current_pos == raw_data->data_len)) {
        ERROR("[Redis Parse] The raw_data length is insufficient.\n");
        return STATE_NEEDS_MORE_DATA;
    }

    struct redis_msg_s *msg = init_redis_msg();
    if (msg == NULL) {
        ERROR("[Redis Parse] Redis msg init failed.\n");
        return STATE_INVALID;
    }

    // 解析redis 消息
    parse_state_t state = parse_msg_recursive(msg_type, raw_data, msg);
    if (state != STATE_SUCCESS) {
        free_redis_msg(msg);
        return state;
    }
    msg->timestamp_ns = raw_data->timestamp_ns;

    *frame_data = (struct frame_data_s *) malloc(sizeof(struct frame_data_s));
    if ((*frame_data) == NULL) {
        free_redis_msg(msg);
        ERROR("[Redis Parse] The frame_data_s malloc failed.\n");
        return STATE_INVALID;
    }
    memset(*frame_data, 0, sizeof(struct frame_data_s));

    // 解析后的msg封装到通用数据结构frame_data中
    (*frame_data)->frame = msg;
    (*frame_data)->msg_type = msg_type;
    (*frame_data)->timestamp_ns = msg->timestamp_ns;

    return state;
}