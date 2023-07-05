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
#ifndef __HTTP_BODY_DECODER_H__
#define __HTTP_BODY_DECODER_H__

#include "../../../include/data_stream.h"

/**
  * Parse an HTTP chunked body
  *
  * @param buf input raw data
  * @param body_size_limit_bytes body size limit
  * @param result parse result data
  * @param body_size body size
  * @return parse_state_t
  */
parse_state_t parse_chunked(char** buf, size_t body_size_limit_bytes, char** result, size_t* body_size);

/**
  * parse an HTTP body based on content-length
  *
  * @param content_len_str hex string of content-length
  * @param data input raw data
  * @param body_size_limit_bytes body size limit
  * @param result parse result
  * @param body_size body size
  * @return
  */
parse_state_t parse_content(char* content_len_str, char** data, size_t body_size_limit_bytes,
                            char** result, size_t* body_size);

#endif // __HTTP_BODY_DECODER_H__