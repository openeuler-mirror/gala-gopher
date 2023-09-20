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
 * Author: zhaoguolin
 * Create: 2023-04-04
 * Description:
 ******************************************************************************/

#include <string.h>

#include "pgsql_parser.h"
#include "../utils/macros.h"
#include "../utils/binary_decoder.h"
#include "../common/protocol_common.h"

#define CHECK_RAW_DATA_LEN (raw_data->data_len == 0 || raw_data->current_pos == raw_data->data_len)

parse_state_t pgsql_parse_regular_msg(struct raw_data_s *raw_data, struct pgsql_regular_msg_s *msg)
{
    parse_state_t extract_tag_state;
    parse_state_t msg_len_state;
    size_t payload_len;
    parse_state_t extract_payload_state;

    // 校验raw_data缓存长度是否合法
    if (CHECK_RAW_DATA_LEN) {
        DEBUG("[Pgsql parser] The raw_data length is insufficient.\n");
        return STATE_NEEDS_MORE_DATA;
    }

    extract_tag_state = decoder_extract_char(raw_data, &msg->tag);
    if (extract_tag_state != STATE_SUCCESS) {
        return STATE_NEEDS_MORE_DATA;
    }
    msg_len_state = decoder_extract_int32_t(raw_data, &msg->len);
    if (msg_len_state != STATE_SUCCESS) {
        return STATE_NEEDS_MORE_DATA;
    }

    if (msg->len < PGSQL_REGULAR_MSG_MIN_LEN) {
        WARN("[Pgsql parser] Failed to parse regular msg, msg.len is less than 4.\n");
        return STATE_INVALID;
    }

    payload_len = msg->len - PGSQL_REGULAR_MSG_MIN_LEN;
    extract_payload_state = decoder_extract_raw_data_with_len(raw_data, payload_len, &msg->payload_data);
    if (extract_payload_state != STATE_SUCCESS) {
        return STATE_NEEDS_MORE_DATA;
    }
    return STATE_SUCCESS;
}

parse_state_t pgsql_parse_startup_name_value(struct raw_data_s *raw_data_buf)
{
    parse_state_t parse_state;
    char *name = NULL;
    char *value = NULL;
    while (raw_data_buf->current_pos < raw_data_buf->data_len) {
        // 当前对于消息体中的name-value对只作解析，不作保存，可按需扩展
        parse_state = decoder_extract_str_until_char(raw_data_buf, &name, '\0');
        if (parse_state != STATE_SUCCESS) {
            if (name != NULL) {
                free(name);
            }
            return parse_state;
        }
        if (strlen(name) == 0) {
            if (name != NULL) {
                free(name);
                name = NULL;
            }
            break;
        }
        if (name != NULL) {
            free(name);
            name = NULL;
        }

        parse_state = decoder_extract_str_until_char(raw_data_buf, &value, '\0');
        if (parse_state != STATE_SUCCESS) {
            if (value != NULL) {
                free(value);
                value = NULL;
            }
            return parse_state;
        }
        if (strlen(value) == 0) {
            if (value != NULL) {
                free(value);
                value = NULL;
            }
            WARN("[Pgsql parser] Failed to parse startup msg , not enough data to extract payload value.\n");
            return STATE_INVALID;
        }
        if (value != NULL) {
            free(value);
            value = NULL;
        }
    }
    return STATE_SUCCESS;
}

parse_state_t pgsql_parse_startup_msg(struct raw_data_s *raw_data, struct pgsql_startup_msg_s *msg)
{
    parse_state_t parse_state;

    // 校验raw_data缓存长度是否合法
    if (CHECK_RAW_DATA_LEN) {
        DEBUG("[Pgsql parser] The raw_data length is insufficient.\n");
        return STATE_NEEDS_MORE_DATA;
    }

    // 提取消息len
    parse_state = decoder_extract_int32_t(raw_data, &msg->len);
    if (parse_state != STATE_SUCCESS) {
        return parse_state;
    }

    // 提取版本信息
    parse_state = decoder_extract_int16_t(raw_data, &msg->protocol_ver->major_version);
    if (parse_state != STATE_SUCCESS) {
        return parse_state;
    }
    parse_state = decoder_extract_int16_t(raw_data, &msg->protocol_ver->minor_version);
    if (parse_state != STATE_SUCCESS) {
        return parse_state;
    }

    // 校验缓存区剩余容量是否足够获取payload
    if ((raw_data->data_len - raw_data->current_pos) < (msg->len - PGSQL_MSG_HEADER_SIZE)) {
        WARN("[Pgsql parser] Failed to parse startup msg, not enough data.\n");
        return STATE_INVALID;
    }

    parse_state = pgsql_parse_startup_name_value(raw_data);
    if (parse_state != STATE_SUCCESS) {
        return parse_state;
    }

    return STATE_SUCCESS;
}

parse_state_t pgsql_parse_cmd_complete(struct pgsql_regular_msg_s *msg, struct pgsql_cmd_complete_s *cmd_complete)
{
    cmd_complete->timestamp_ns = msg->timestamp_ns;

    // 反向寻找'\0'字符并切割，c字符串以'\0'结束，直接赋值即可
    size_t cmd_tag_len = strlen(msg->payload_data->data);
    cmd_complete->cmd_tag = malloc(cmd_tag_len);
    if (cmd_complete->cmd_tag == NULL) {
        return STATE_INVALID;
    }
    memcpy(cmd_complete->cmd_tag, msg->payload_data->data, cmd_tag_len);
    return STATE_SUCCESS;
}

// 根据row_description字段解析报文
parse_state_t pgsql_extract_row_desc_field(struct raw_data_s *raw_data_buf, struct pgsql_row_desc_field_s *field)
{
    parse_state_t parse_state;
    parse_state = decoder_extract_str_until_char(raw_data_buf, &field->name, '\0');
    if (parse_state != STATE_SUCCESS) {
        return parse_state;
    }
    parse_state = decoder_extract_int32_t(raw_data_buf, &field->table_oid);
    if (parse_state != STATE_SUCCESS) {
        return parse_state;
    }
    parse_state = decoder_extract_int16_t(raw_data_buf, &field->attr_num);
    if (parse_state != STATE_SUCCESS) {
        return parse_state;
    }
    parse_state = decoder_extract_int32_t(raw_data_buf, &field->type_oid);
    if (parse_state != STATE_SUCCESS) {
        return parse_state;
    }
    parse_state = decoder_extract_int16_t(raw_data_buf, &field->type_size);
    if (parse_state != STATE_SUCCESS) {
        return parse_state;
    }
    parse_state = decoder_extract_int32_t(raw_data_buf, &field->type_modifier);
    if (parse_state != STATE_SUCCESS) {
        return parse_state;
    }
    parse_state = decoder_extract_int16_t(raw_data_buf, (int16_t *) &field->fmt_code);
    if (parse_state != STATE_SUCCESS) {
        return parse_state;
    }
    return STATE_SUCCESS;
}

parse_state_t pgsql_parse_row_desc(struct pgsql_regular_msg_s *msg, struct pgsql_row_description_s *row_desc)
{
    int16_t field_count;
    parse_state_t field_count_state;
    row_desc->timestamp_ns = msg->timestamp_ns;

    if (msg->payload_data == NULL || msg->payload_data->data_len == 0) {
        WARN(
            "[Pgsql parser] Failed to get payload_data of msg, msg->payload_data is null or msg->payload_data->data_len is 0.\n");
        return STATE_INVALID;
    }
    msg->payload_data->current_pos = 0;

    field_count_state = decoder_extract_int16_t(msg->payload_data, &field_count);
    if (field_count_state != STATE_SUCCESS) {
        return field_count_state;
    }
    for (int i = 0; i < field_count; ++i) {
        struct pgsql_row_desc_field_s *field;
        parse_state_t parse_state;
        field = init_pgsql_row_desc_field();
        if (field == NULL) {
            WARN("[Pgsql parser] Failed to malloc struct pgsql_row_desc_field_s*.\n");
            return STATE_INVALID;
        }
        parse_state = pgsql_extract_row_desc_field(msg->payload_data, field);
        if (parse_state != STATE_SUCCESS) {
            free_pgsql_row_desc_field(field);
            return parse_state;
        }
        row_desc->row_desc_fields[i] = field;
        row_desc->row_desc_field_size++;
    }
    msg->payload_data->current_pos = 0;

    return STATE_SUCCESS;
}

parse_state_t pgsql_parse_data_row(struct pgsql_regular_msg_s *msg, struct pgsql_data_row_s *data_row)
{
    int16_t field_count = 0;
    parse_state_t field_count_state;
    int32_t value_len = 0;
    parse_state_t value_len_state;
    parse_state_t col_values_state;
    data_row->timestamp_ns = msg->timestamp_ns;
    data_row->colum_values_len = 0;

    if (msg->payload_data == NULL || msg->payload_data->data_len == 0) {
        WARN(
            "[Pgsql parser] Failed to get payload_data of msg, msg->payload_data is null or msg->payload_data->data_len is 0.\n");
        return STATE_INVALID;
    }
    msg->payload_data->current_pos = 0;

    field_count_state = decoder_extract_int16_t(msg->payload_data, &field_count);
    if (field_count_state != STATE_SUCCESS) {
        return field_count_state;
    }
    for (int i = 0; i < field_count; ++i) {
        value_len = 0;
        value_len_state = decoder_extract_int32_t(msg->payload_data, &value_len);
        if (value_len_state != STATE_SUCCESS) {
            return value_len_state;
        }
        if (value_len == -1) {
            data_row->colum_values[i] = NULL;
            data_row->colum_values_len++;
            continue;
        }
        if (value_len == 0) {
            // todo 是否需要修改数据类型
            data_row->colum_values[i] = NULL;
            data_row->colum_values_len++;
            continue;
        }
        col_values_state = decoder_extract_string(msg->payload_data, &data_row->colum_values[i], value_len);
        if (col_values_state != STATE_SUCCESS) {
            return col_values_state;
        }
        data_row->colum_values_len++;
    }
    msg->payload_data->current_pos = 0;

    return STATE_SUCCESS;
}

parse_state_t pgsql_parse_bind_req(struct pgsql_regular_msg_s *msg, struct pgsql_bind_req_s *bind_req)
{
    parse_state_t dest_portal_state;
    parse_state_t stat_name_state;
    int16_t fmt_code_count = 0;
    parse_state_t count_state;
    int16_t fmt_code = 0;
    parse_state_t fmt_code_state;

    bind_req->timestamp_ns = msg->timestamp_ns;

    if (msg->payload_data == NULL || msg->payload_data->data_len == 0) {
        WARN(
            "[Pgsql parser] Failed to get payload_data of msg, msg->payload_data is null or msg->payload_data->data_len is 0.\n");
        return STATE_INVALID;
    }
    msg->payload_data->current_pos = 0;

    dest_portal_state = decoder_extract_str_until_char(msg->payload_data, &bind_req->dest_portal_name, '\0');
    if (dest_portal_state != STATE_SUCCESS) {
        return dest_portal_state;
    }
    stat_name_state = decoder_extract_str_until_char(msg->payload_data, &bind_req->src_prepared_stat_name, '\0');
    if (stat_name_state != STATE_SUCCESS) {
        return stat_name_state;
    }

    count_state = decoder_extract_int16_t(msg->payload_data, &fmt_code_count);
    if (count_state != STATE_SUCCESS) {
        return count_state;
    }
    for (int i = 0; i < fmt_code_count; ++i) {
        // 当前未解析fmt信息
        fmt_code_state = decoder_extract_int16_t(msg->payload_data, &fmt_code);
        if (fmt_code_state != STATE_SUCCESS) {
            return fmt_code_state;
        }
    }
    msg->payload_data->current_pos = 0;

    return STATE_SUCCESS;
}

parse_state_t pgsql_parse_param_desc(struct pgsql_regular_msg_s *msg, struct pgsql_param_description_s *param_desc)
{
    int16_t param_count = 0;
    parse_state_t extract_count_state;
    int32_t type_oid;

    param_desc->timestamp_ns = msg->timestamp_ns;

    if (msg->payload_data == NULL || msg->payload_data->data_len == 0) {
        WARN(
            "[Pgsql parser] Failed to get payload_data of msg, msg->payload_data is null or msg->payload_data->data_len is 0.\n");
        return STATE_INVALID;
    }
    msg->payload_data->current_pos = 0;

    extract_count_state = decoder_extract_int16_t(msg->payload_data, &param_count);
    if (extract_count_state != STATE_SUCCESS) {
        return extract_count_state;
    }
    for (int i = 0; i < param_count; ++i) {
        // type_oid字段尚未使用，仅做解析不保存
        parse_state_t extract_oid_state = decoder_extract_int32_t(msg->payload_data, &type_oid);
        if (extract_oid_state != STATE_SUCCESS) {
            return extract_oid_state;
        }
    }
    msg->payload_data->current_pos = 0;

    return STATE_SUCCESS;
}

parse_state_t pgsql_parse_parse_msg(struct pgsql_regular_msg_s *msg, struct pgsql_parse_req_s *parse_req)
{
    parse_state_t stmt_name_state;
    parse_state_t query_state;
    int16_t param_count_count = 0;
    parse_state_t param_count_state;
    int32_t type_oid = 0;
    parse_req->timestamp_ns = msg->timestamp_ns;

    if (msg->payload_data == NULL || msg->payload_data->data_len == 0) {
        WARN(
            "[Pgsql parser] Failed to get payload_data of msg, msg->payload_data is null or msg->payload_data->data_len is 0.\n");
        return STATE_INVALID;
    }
    msg->payload_data->current_pos = 0;

    stmt_name_state = decoder_extract_str_until_char(msg->payload_data, &parse_req->stmt_name, '\0');
    if (stmt_name_state != STATE_SUCCESS) {
        return stmt_name_state;
    }
    query_state = decoder_extract_str_until_char(msg->payload_data, &parse_req->query, '\0');
    if (query_state != STATE_SUCCESS) {
        return query_state;
    }

    param_count_state = decoder_extract_int16_t(msg->payload_data, &param_count_count);
    if (param_count_state != STATE_SUCCESS) {
        return param_count_state;
    }
    for (int i = 0; i < param_count_count; ++i) {
        // 当前保存消息体，未维护oid列表
        parse_state_t type_oid_state = decoder_extract_int32_t(msg->payload_data, &type_oid);
        if (type_oid_state != STATE_SUCCESS) {
            return type_oid_state;
        }
    }
    msg->payload_data->current_pos = 0;

    return STATE_SUCCESS;
}

parse_state_t pgsql_parse_err_resp(struct pgsql_regular_msg_s *msg, struct pgsql_err_resp_s *err_resp)
{
    char code;
    parse_state_t extract_code_state;
    parse_state_t parse_state;
    char *value = NULL;
    parse_state_t extract_value_state;
    err_resp->timestamp_ns = msg->timestamp_ns;
    if (msg->payload_data == NULL || msg->payload_data->data_len == 0) {
        WARN(
            "[Pgsql parser] Failed to get payload_data of msg, msg->payload_data is null or msg->payload_data->data_len is 0.\n");
        return STATE_INVALID;
    }
    msg->payload_data->current_pos = 0;

    // 解析payload所有字节
    while (msg->payload_data->current_pos < msg->payload_data->data_len) {
        value = NULL;
        extract_code_state = decoder_extract_char(msg->payload_data, &code);
        if (extract_code_state != STATE_SUCCESS) {
            return extract_code_state;
        }
        if (code == '\0') {
            // 到达payload末端
            parse_state = (msg->payload_data->current_pos == msg->payload_data->data_len) ? STATE_SUCCESS
                                                                                          : STATE_INVALID;
            msg->payload_data->current_pos = 0;
            return parse_state;
        }

        extract_value_state = decoder_extract_str_until_char(msg->payload_data, &value, '\0');
        if (extract_value_state != STATE_SUCCESS) {
            if (value != NULL) {
                free(value);
            }
            return extract_value_state;
        }

        // 当前只解析错误码，错误信息、错误代码位置未来可按需扩展
        if (code == PGSQL_CODE) {
            err_resp->pgsql_err_code = value;
            continue;
        }
        if (value != NULL) {
            free(value);
            value = NULL;
        }
    }
    msg->payload_data->current_pos = 0;

    return STATE_SUCCESS;
}

parse_state_t pgsql_parse_describe(struct pgsql_regular_msg_s *msg, struct pgsql_describe_req_s *desc_req)
{
    parse_state_t extract_type_state;
    parse_state_t extract_name_state;
    desc_req->timestamp_ns = msg->timestamp_ns;
    if (msg->payload_data == NULL || msg->payload_data->data_len == 0) {
        WARN(
            "[Pgsql parser] Failed to get payload_data of msg, msg->payload_data is null or msg->payload_data->data_len is 0.\n");
        return STATE_INVALID;
    }
    msg->payload_data->current_pos = 0;

    extract_type_state = decoder_extract_char(msg->payload_data, &desc_req->desc_type);
    if (extract_type_state != STATE_SUCCESS) {
        return extract_type_state;
    }
    extract_name_state = decoder_extract_str_until_char(msg->payload_data, &desc_req->name, '\0');
    if (extract_name_state != STATE_SUCCESS) {
        return extract_name_state;
    }
    msg->payload_data->current_pos = 0;

    return STATE_SUCCESS;
}

size_t pgsql_find_frame_boundary(struct raw_data_s *raw_data)
{
    for (size_t i = raw_data->current_pos; i < raw_data->data_len; ++i) {
        if (contains_pgsql_tag(raw_data->data[i]) &&
        ((i == 0 && raw_data->data[i + 1] == '\0') ||
        (i != 0 && raw_data->data[i - 1] == '\0' && raw_data->data[i + 1] == '\0'))) {
            return i;
        }
    }
    return PARSER_INVALID_BOUNDARY_INDEX;
}

parse_state_t pgsql_parse_frame(struct raw_data_s *raw_data, struct frame_data_s **frame_data)
{
    struct pgsql_regular_msg_s *regular_msg;
    parse_state_t parse_msg_state;

    // 校验raw_data缓存长度是否合法
    if (CHECK_RAW_DATA_LEN) {
        DEBUG("[Pgsql parser] The raw_data length is insufficient.\n");
        return STATE_NEEDS_MORE_DATA;
    }

    *frame_data = (struct frame_data_s *) malloc(sizeof(struct frame_data_s));
    if ((*frame_data) == NULL) {
        return STATE_INVALID;
    }
    memset(*frame_data, 0, sizeof(struct frame_data_s));

    regular_msg = init_pgsql_regular_msg();
    if (regular_msg == NULL) {
        return STATE_INVALID;
    }
    regular_msg->timestamp_ns = raw_data->timestamp_ns;
    (*frame_data)->frame = regular_msg;
    parse_msg_state = pgsql_parse_regular_msg(raw_data, regular_msg);
    if (parse_msg_state != STATE_SUCCESS) {
        free_pgsql_regular_msg(regular_msg);
        free(*frame_data);
        return parse_msg_state;
    }
    return STATE_SUCCESS;
}
