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
 * Author: wo_cow
 * Create: 2023-03-17
 * Description: connection tracker header
 ******************************************************************************/
#ifndef __CONN_TRACKER_H__
#define __CONN_TRACKER_H__

#define MAX_MSG_LEN_SSL 1024

enum msg_event_rw_t {
    MSG_READ,
    MSG_WRITE,
};

struct ssl_msg_t {
    enum msg_event_rw_t msg_type;
    int fd;
    int tgid;
    int count;
    u64 ts_nsec;
    char msg[MAX_MSG_LEN_SSL];
};

void l7_libssl_msg_handler(void *ctx, int cpu, void *data, unsigned int size);
#endif

