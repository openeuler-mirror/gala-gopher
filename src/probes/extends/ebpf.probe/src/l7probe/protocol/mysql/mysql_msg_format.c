/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan
 * PSL v2. You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 * KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE. See the
 * Mulan PSL v2 for more details. Author: wangshuyuan Create: 2024-10-08
 * Description:
 * **************************************************************************** */
#include "mysql_msg_format.h"
#include <string.h>

struct mysql_packet_msg_s* init_mysql_msg_s(void)
{
    struct mysql_packet_msg_s *msg = (struct mysql_packet_msg_s*)calloc(1, sizeof(struct mysql_packet_msg_s));
    if (msg == NULL) {
        return NULL;
    }
    return msg;
}

void free_mysql_packet_msg_s(struct mysql_packet_msg_s* msg)
{
    if (msg == NULL) {
        return;
    }
    if (msg->msg != NULL) {
        free(msg->msg);
        msg->msg = NULL;
    }
    free(msg);
    msg = NULL;
}

struct mysql_command_req_resp_s* init_mysql_command_req_resp_s(void)
{
    struct mysql_command_req_resp_s *req_rsp =
        (struct mysql_command_req_resp_s*)calloc(1, sizeof(struct mysql_command_req_resp_s));
    if (req_rsp == NULL) {
        return NULL;
    }
    req_rsp->req = init_mysql_msg_s();
    if (req_rsp->req == NULL) {
        free_mysql_command_req_resp_s(req_rsp);
        return NULL;
    }
    req_rsp->rsp = init_mysql_msg_s();
    if (req_rsp->rsp == NULL) {
        free_mysql_command_req_resp_s(req_rsp);
        return NULL;
    }
    return req_rsp;
}

void free_mysql_command_req_resp_s(struct mysql_command_req_resp_s* req_rsp)
{
    if (req_rsp == NULL) {
        return;
    }
    if (req_rsp->req != NULL) {
        free_mysql_packet_msg_s(req_rsp->req);
        req_rsp->req = NULL;
    }
    if (req_rsp->rsp != NULL) {
        free_mysql_packet_msg_s(req_rsp->rsp);
        req_rsp->rsp = NULL;
    }
    free(req_rsp);
    req_rsp = NULL;
}

void free_mysql_record(struct mysql_command_req_resp_s* record)
{
    if (record == NULL) {
        return;
    }
    /* resp_msg was manually made in mysql_matcher_add_record(), so need to free
     * here. */
    if (record->rsp != NULL) {
        free_mysql_packet_msg_s(record->rsp);
        record->rsp = NULL;
    }
    free(record);
}