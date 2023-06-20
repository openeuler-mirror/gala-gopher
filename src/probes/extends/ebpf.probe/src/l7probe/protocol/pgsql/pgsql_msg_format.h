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

#ifndef __PGSQL_MSG_FORMAT_H__
#define __PGSQL_MSG_FORMAT_H__

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <utlist.h>

#include "hash.h"

#define PGSQL_MSG_HEADER_SIZE (2 * sizeof(int32_t))

// regular msg最小长度
#define REGULAR_MSG_MIN_LEN 4

// Tag: The first field of the regular message.
// References pgsql spec:
// https://www.postgresql.org/docs/15/protocol-message-formats.html
enum pgsql_tag_t {
    PGSQL_COPY_DATA = 'd',
    PGSQL_COPY_DONE = 'c',

    // client
    PGSQL_PASSWD = 'p',
    PGSQL_SIMPLE_QUERY = 'Q',
    PGSQL_EXTENDED_QUERY_PARSE = 'P',
    PGSQL_EXTENDED_QUERY_BIND = 'B',
    PGSQL_EXTENDED_QUERY_EXECUTE = 'E',
    PGSQL_FASTCALL_FUNCTION_CALL = 'F',
    PGSQL_CLOSE = 'C',
    PGSQL_EXTENDED_QUERY_DESCRIBE = 'D',
    PGSQL_FLUSH = 'H',
    PGSQL_SYNC = 'S',
    PGSQL_TERMINATE = 'X',
    PGSQL_COPY_FAIL = 'f',

    // server
    PGSQL_CMD_COMPLETE = 'C',
    PGSQL_ERR_RETURN = 'E',
    PGSQL_READY_FOR_QUERY = 'Z',
    PGSQL_EMPTY_QUERY_RESP = 'I',
    PGSQL_PARSE_COMPLETE = '1',
    PGSQL_BIND_COMPLETE = '2',
    PGSQL_CLOSE_COMPLETE = '3',
    PGSQL_PARAMETER_STATUS = 'S',
    PGSQL_SECRET_KEY = 'K',
    PGSQL_ROW_DESCRIPTION = 'T',
    PGSQL_NO_DATA = 'n',
    PGSQL_PARAMETER_DESCRIPTION = 't',
    PGSQL_DATA_ROW = 'D',
    PGSQL_START_COPY_IN = 'G',
    PGSQL_START_COPY_OUT = 'H',
    PGSQL_START_COPY_BOTH = 'W',
    PGSQL_AUTH = 'R',

    PGSQL_UNKNOWN_TAG = '\0'
};

struct pgsql_tag_enum_value_s {
    bool isClient;
    char value;
};

#define PGSQL_TAG_ENUM_VALUE(x, y) {x, y}

struct pgsql_tag_enum_value_s pgsql_tag_enum_values[];

const int pgsql_tag_enum_values_count;

bool contains_pgsql_tag(char tag);

// https://www.postgresql.org/docs/15/protocol-error-fields.html
enum pgsql_err_field_code_t {
    PGSQL_SEVERITY = 'S',
    PGSQL_INTERNAL_SEVERITY = 'V',
    PGSQL_CODE = 'C',
    PGSQL_MESSAGE = 'M',
    PGSQL_DETAIL = 'D',
    PGSQL_HINT = 'H',
    PGSQL_POSITION = 'P',
    PGSQL_INTERNAL_POSITION = 'p',
    PGSQL_INTERNAL_QUERY = 'q',
    PGSQL_WHERE = 'W',
    PGSQL_SCHEMA_NAME = 's',
    PGSQL_TABLE_NAME = 't',
    PGSQL_COLUMN_NAME = 'c',
    PGSQL_DATA_TYPE_NAME = 'd',
    PGSQL_CONSTRAINT_NAME = 'n',
    PGSQL_FILE = 'F',
    PGSQL_LINE = 'L',
    PGSQL_ROUTINE = 'R',
    PGSQL_UNKNOWN_ERR_CODE = '\0'
};

/**
 * The protocol version number.
 * The most significant 16 bits are the major version number.
 * The least significant 16 bits are the minor version number.
 */
struct pgsql_protocol_version_s {
    int16_t major_version;
    int16_t minor_version;
};

/**
 * Connection information in the form of key-value pairs.
 */
struct pgsql_name_value_pair_s {
    char *name;
    char *value;
};

/**
 * Startup packet's format:
 * ----------------------------------------------------------------------------------------------------
 * | int32 len (including this field) | int32 protocol version | str name | \0 | str value | ... | \0 |
 * ----------------------------------------------------------------------------------------------------
 *
 * NOTE: The first message sent by the client during connection creation.
 * There is no tag field, starting with the message length, followed by the protocol version number.
 * Payload contains connection information in the form of key-value pairs.
 */
#define __NAME_VALUE_PAIR_BUF_SIZE (50)
#define PGSQL_STARTUP_MSG_MIN_LEN (sizeof(int32_t) + sizeof(int32_t))
struct pgsql_startup_msg_s {
    int32_t len;
    struct pgsql_protocol_version_s *protocol_ver;
    struct pgsql_name_value_pair_s *name_value_pairs[__NAME_VALUE_PAIR_BUF_SIZE];
    size_t name_value_pair_len;
};

/**
 * Cancel request's format:
 * -----------------------------------------------------------------------------------
 * | int32 len (including this field) | int32 cancel code | int32 pid | int32 secret |
 * -----------------------------------------------------------------------------------
 */
struct cancel_request_msg_s {
    uint64_t timestamp_ns;
    int32_t len;
    int32_t cancel_code;
    int32_t pid;
    int32_t secret;
};

/**
 * Regular packet's format:
 * ---------------------------------------------------------
 * | char tag | int32 len (including this field) | payload |
 * ---------------------------------------------------------
 *
 * NOTE: The first byte identifies the message type.
 */
struct pgsql_regular_msg_s {
    uint64_t timestamp_ns;

    // default: '\0'
    char tag;
    int32_t len;
    char *payload;
    bool consumed;
};

struct pgsql_regular_msg_s *init_pgsql_regular_msg();

void free_pgsql_regular_msg(struct pgsql_regular_msg_s *msg);


/**
 * The parameter format codes. Each must presently be zero (text) or one (binary).
 * https://www.postgresql.org/docs/15/protocol-message-formats.html
 */
enum format_code_s {
    TEXT = 0,
    BINARY = 1;
};

struct pgsql_row_desc_field_s {
    // The field name.
    char *name;

    // If the field can be identified as a column of a specific table, the object ID of the table; otherwise zero.
    int32_t table_oid;

    // If the field can be identified as a column of a specific table,
    // the attribute number of the column; otherwise zero.
    int16_t attr_num;

    // The object ID of the field's data type
    int32_t type_oid;

    // Note that negative values denote variable-width types.
    int16_t type_size;

    // The type modifier (see pg_attribute.atttypmod). The meaning of the modifier is type-specific
    int32_t type_modifier;
    enum format_code_s fmt_code;
};

/**
 * Malloc初始化struct pgsql_row_desc_field_s*
 *
 * @return struct pgsql_row_desc_field_s*
 */
struct pgsql_row_desc_field_s *init_pgsql_row_desc_field(void);

/**
 * 释放struct pgsql_row_desc_field_s*
 *
 * @param msg struct pgsql_row_desc_field_s指针
 */
void free_pgsql_row_desc_field(struct pgsql_row_desc_field_s *field);

#define __PGSQL_ROW_DESC_SIZE (1024)
struct pgsql_row_description_s {
    uint64_t timestamp_ns;
    struct pgsql_row_desc_field_s *row_desc_fields[__PGSQL_ROW_DESC_SIZE];
    size_t row_desc_field_size;
};

/**
 * DataRow.
 */
#define __PGSQL_DATA_ROW_SIZE (1024)
struct pgsql_data_row_s {
    uint64_t timestamp_ns;
    char *colum_values[__PGSQL_DATA_ROW_SIZE];
    size_t colum_values_len;
};

/**
 * Indicates that the current command execution is complete.
 */
struct pgsql_cmd_complete_s {
    uint64_t timestamp_ns;

    // This is usually a single word that identifies which SQL command was completed.
    char *cmd_tag;
};

/**
 * ErrorResponse.
 */
struct pgsql_err_resp_s {
    uint64_t timestamp_ns;

    // default: '\0'
    char failed_code;
    char *field_value;
};

/**
 * Simple query request.
 * --------------------------------------------------
 * | 'Q' | int32 len (including this field) | query |
 * --------------------------------------------------
 */
struct pgsql_query_req_s {
    uint64_t timestamp_ns;
    char *query;
};

/**
 * Simple query response.
 */
#define __PGSQL_ROW_DATA_SIZE (1024)
struct pgsql_query_resp_s {
    uint64_t timestamp_ns;
    struct pgsql_row_description_s *row_desc;
    struct pgsql_data_row_s *data_rows[__PGSQL_ROW_DATA_SIZE];
    size_t data_row_len;
    struct pgsql_cmd_complete_s *cmd_cmpl;
    bool is_err_resp = false;
    struct pgsql_err_resp_s *err_resp;
};

/**
 * Simple query request and response struct.
 */
struct pgsql_query_req_resp_s {
    struct pgsql_query_req_s *req;
    struct pgsql_query_resp_s *resp;
};

/**
 * Extended query parse request.
 * ----------------------------------------------------------------------------------------------------------
 * | 'P' | int32 len (including this field) | str stmt | str query | int16 numparams | int32 paramoid | ... |
 * ----------------------------------------------------------------------------------------------------------
 */
#define __PARAM_TYPE_OID_SIZE (1024)
struct pgsql_parse_req_s {
    uint64_t timestamp_ns;
    char *stmt_name;
    char *query;
    int32_t *param_type_oid[__PARAM_TYPE_OID_SIZE];
    size_t param_type_oid_len;
};

enum pgsql_combo_msg_type_t {
    CMD_CMPL_MSG,
    ERR_RESP_MSG
};

struct pgsql_combo_resp_s {
    uint64_t timestamp_ns;
    enum pgsql_combo_msg_type_t msg_type;
    union {
        struct pgsql_cmd_complete_s *cmd_cmpl_msg;
        struct pgsql_err_resp_s *err_resp_msg;
    };
};

/**
 * Parse request and response struct.
 */
struct pgsql_parse_req_resp_s {
    struct pgsql_parse_req_s *req;
    struct pgsql_combo_resp_s *resp;
};

struct pgsql_param_s {
    enum format_code_s format_code;
    char *value;
};

/**
 * Extended query bind request.
 */
#define __PGSQL_BIND_PARAM_SIZE (1024)
struct pgsql_bind_req_s {
    uint64_t timestamp_ns;
    char *dest_portal_name;
    char *src_prepared_stat_name;
    struct pgsql_param_s *params[__PGSQL_BIND_PARAM_SIZE];
    size_t params_len;
    int *res_col_fmt_codes[__PGSQL_BIND_PARAM_SIZE];
    size_t col_fmt_codes_len;
};

/**
 * Bind request and response struct.
 */
struct pgsql_bind_req_resp_s {
    struct pgsql_bind_req_s *req;
    struct pgsql_combo_resp_s *resp;
};

/**
 * Extended query describe request.
 */
#define PGSQL_DESCRIBE_TYPE_STATEMENT 'S'
#define PGSQL_DESCRIBE_TYPE_PORTAL 'P'
struct pgsql_describe_req_s {
    uint64_t timestamp_ns;

    // PGSQL_DESCRIBE_TYPE_STATEMENT or PGSQL_DESCRIBE_TYPE_PORTAL
    char desc_type;
    char *name;
};

struct pgsql_param_description_s {
    uint64_t timestamp_ns;
    int32_t type_oids[0];
};

/**
 * Extended query describe response.
 */
struct pgsql_describe_resp_s {
    uint64_t timestamp_ns;
    bool is_no_data;

    // This field is unset if Desc asks for the description of a "portal".
    struct pgsql_param_description_s *param_desc;
    struct pgsql_row_description_s *row_desc;

    // This field is set if is_err_resp is true.
    struct pgsql_err_resp_s *err_resp;
    bool is_err_resp;
};

/**
 * Describe request and response struct.
 */
struct pgsql_describe_req_resp_s {
    struct pgsql_describe_req_s *req;
    struct pgsql_describe_resp_s *resp;
};

/**
 * Extended query execute response.
 */
struct pgsql_execute_req_s {
    uint64_t timestamp_ns;
    char *query;
    struct pgsql_param_s *params[0];
};

/**
 * Execute request and response struct.
 */
struct pgsql_execute_req_resp_s {
    struct pgsql_execute_req_s *req;
    struct pgsql_query_resp_s *resp;
};

struct pgsql_state_s {
    // todo convert prepared_statements to hashmap: map<string, string> key name, value statement
    char *prepared_statements;
    char *unnamed_statement;
    char *bound_statement;
    struct pgsql_param_s *params[0];
};

struct pgsql_state_wrapper_s {
    struct pgsql_state_s global;
    void *send;
    void *recv;
};

struct pgsql_protocol_traits_s {
    struct pgsql_regular_msg_s *frame;
    struct pgsql_record_s *record;
    struct pgsql_state_wrapper_s *state;
};

struct pgsql_record_s {
    pgsql_regular_msg_s *req_msg;
    pgsql_regular_msg_s *resp_msg;
};

#endif
