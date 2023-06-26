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
 * Create: 2023-05-31
 * Description:
 ******************************************************************************/

#include "include/data_stream.h"

struct raw_data_s *parser_copy_raw_data(struct raw_data_s *raw_data)
{
    struct raw_data_s *copied_raw_data = (struct raw_data_s *) malloc(
        sizeof(struct raw_data_s) + raw_data->data_len + 1);
    if (copied_raw_data == NULL) {
        return NULL;
    }
    copied_raw_data->timestamp_ns = raw_data->timestamp_ns;
    copied_raw_data->current_pos = raw_data->current_pos;

    size_t raw_data_len = raw_data->data_len;
    copied_raw_data->data_len = raw_data_len;
    memcpy(copied_raw_data->data, raw_data->data, raw_data_len);
    return copied_raw_data;
}

struct raw_data_s *init_raw_data_with_str(char *str, size_t str_len)
{
    struct raw_data_s *raw_data = (struct raw_data_s *) malloc(sizeof(struct raw_data_s) + str_len + 1);
    if (raw_data == NULL) {
        return NULL;
    }
    raw_data->data_len = str_len;
    raw_data->current_pos = 0;
    memcpy(raw_data->data, str, str_len);
    return raw_data;
}

void parser_raw_data_offset(struct raw_data_s *raw_data, size_t offset)
{
    size_t real_offset = offset;
    size_t unconsumed_len = raw_data->data_len - raw_data->current_pos;
    if (real_offset > unconsumed_len) {
        real_offset = unconsumed_len;
    }
    raw_data->current_pos += real_offset;
}
