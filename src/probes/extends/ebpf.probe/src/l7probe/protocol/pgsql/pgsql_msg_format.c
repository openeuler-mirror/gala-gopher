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
 * Create: 2023-04-27
 * Description:
 ******************************************************************************/

#include <stdlib.h>
#include "pgsql_msg_format.h"

struct pgsql_tag_enum_value_s pgsql_tag_enum_values[] = {
        PGSQL_TAG_ENUM_VALUE(true, PGSQL_COPY_DATA),
        PGSQL_TAG_ENUM_VALUE(true, PGSQL_COPY_DONE),
        PGSQL_TAG_ENUM_VALUE(true, PGSQL_SIMPLE_QUERY),
        PGSQL_TAG_ENUM_VALUE(true, PGSQL_EXTENDED_QUERY_PARSE),
        PGSQL_TAG_ENUM_VALUE(true, PGSQL_EXTENDED_QUERY_BIND),
        PGSQL_TAG_ENUM_VALUE(true, PGSQL_EXTENDED_QUERY_EXECUTE),
        PGSQL_TAG_ENUM_VALUE(true, PGSQL_FASTCALL_FUNCTION_CALL),
        PGSQL_TAG_ENUM_VALUE(true, PGSQL_CLOSE),
        PGSQL_TAG_ENUM_VALUE(true, PGSQL_EXTENDED_QUERY_DESCRIBE),
        PGSQL_TAG_ENUM_VALUE(true, PGSQL_SYNC),
        PGSQL_TAG_ENUM_VALUE(true, PGSQL_FLUSH),
        PGSQL_TAG_ENUM_VALUE(true, PGSQL_TERMINATE),
        PGSQL_TAG_ENUM_VALUE(true, PGSQL_COPY_FAIL),
        PGSQL_TAG_ENUM_VALUE(false, PGSQL_COPY_DATA),
        PGSQL_TAG_ENUM_VALUE(false, PGSQL_COPY_DONE),
        PGSQL_TAG_ENUM_VALUE(false, PGSQL_CMD_COMPLETE),
        PGSQL_TAG_ENUM_VALUE(false, PGSQL_ERR_RETURN),
        PGSQL_TAG_ENUM_VALUE(false, PGSQL_READY_FOR_QUERY),
        PGSQL_TAG_ENUM_VALUE(false, PGSQL_EMPTY_QUERY_RESP),
        PGSQL_TAG_ENUM_VALUE(false, PGSQL_PARSE_COMPLETE),
        PGSQL_TAG_ENUM_VALUE(false, PGSQL_BIND_COMPLETE),
        PGSQL_TAG_ENUM_VALUE(false, PGSQL_CLOSE_COMPLETE),
        PGSQL_TAG_ENUM_VALUE(false, PGSQL_PARAMETER_STATUS),
        PGSQL_TAG_ENUM_VALUE(false, PGSQL_SECRET_KEY),
        PGSQL_TAG_ENUM_VALUE(false, PGSQL_ROW_DESCRIPTION),
        PGSQL_TAG_ENUM_VALUE(false, PGSQL_NO_DATA),
        PGSQL_TAG_ENUM_VALUE(false, PGSQL_PARAMETER_DESCRIPTION),
        PGSQL_TAG_ENUM_VALUE(false, PGSQL_DATA_ROW),
        PGSQL_TAG_ENUM_VALUE(false, PGSQL_START_COPY_IN),
        PGSQL_TAG_ENUM_VALUE(false, PGSQL_START_COPY_OUT),
        PGSQL_TAG_ENUM_VALUE(false, PGSQL_START_COPY_BOTH),
        PGSQL_TAG_ENUM_VALUE(false, PGSQL_AUTH)
};

const int pgsql_tag_enum_values_count = sizeof(pgsql_tag_enum_values) / sizeof(struct pgsql_tag_enum_value_s);

bool contains_pgsql_tag(char tag)
{
    for (int i = 0; i < pgsql_tag_enum_values_count; ++i) {
        if (pgsql_tag_enum_values[i].value == tag) {
            return true;
        }
    }
    return false;
}

struct pgsql_regular_msg_s *init_pgsql_regular_msg()
{
    struct pgsql_regular_msg_s *msg = (struct pgsql_regular_msg_s *) malloc(sizeof(struct pgsql_regular_msg_s));
    if (msg == NULL) {
        return NULL;
    }
    return msg;
}

void free_pgsql_regular_msg(struct pgsql_regular_msg_s *msg)
{
    if (msg == NULL) {
        return;
    }
    if (msg->payload != NULL) {
        free(msg->payload);
    }
    free(msg);
}


struct pgsql_row_desc_field_s *init_pgsql_row_desc_field(void)
{
    struct pgsql_row_desc_field_s *field = (struct pgsql_row_desc_field_s *) malloc(
        sizeof(struct pgsql_row_desc_field_s));
    if (field == NULL) {
        return NULL;
    }
    field->name = NULL;
    return field;
}

void free_pgsql_row_desc_field(struct pgsql_row_desc_field_s *field)
{
    if (field == NULL) {
        return;
    }
    if (field->name != NULL) {
        free(field->name);
    }
    free(field);
}
