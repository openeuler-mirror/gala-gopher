/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: Vchanger
 * Create: 2024-10-10
 * Description:
 ******************************************************************************/
#ifndef __CRPC_INTERNAL_H__
#define __CRPC_INTERNAL_H__

#include "include/l7.h"

#define CRPC_HEADER_HEADVER_LEN      1
#define CRPC_HEADER_PROPERTY_LEN     3
#define CRPC_HEADER_REQUEST_ID_LEN   16

#define CRPC_DEBUG(fmt, ...) DEBUG("[CRPC PARSER] " fmt, ##__VA_ARGS__)
#define CRPC_INFO(fmt, ...)  INFO("[CRPC PARSER] " fmt, ##__VA_ARGS__)
#define CRPC_WARN(fmt, ...)  WARN("[CRPC PARSER] " fmt, ##__VA_ARGS__)
#define CRPC_ERROR(fmt, ...) ERROR("[CRPC PARSER] " fmt, ##__VA_ARGS__)

struct crpc_message_s {
    enum message_type_t type;
    char request_id[CRPC_HEADER_REQUEST_ID_LEN];
    u16 head_len;
    char matched;
    u32 message_len;
    int rpc_resp_code;            // Response code of rpc request
    int app_resp_code;            // Response code of the server application(reserved for future use)

    u64 timestamp_ns;
};

struct crpc_record_s {
    struct crpc_message_s *req_msg;
    struct crpc_message_s *resp_msg;
};

#endif // __CRPC_INTERNAL_H__
