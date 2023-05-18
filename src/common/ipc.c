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
 * Author: Vchanger
 * Create: 2023-04-30
 * Description: ipc api
 ******************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "ipc.h"

#define __GOPHER_IPC_MSG_KEY  0x20230501
int create_ipc_msg_queue(int ipc_flag)
{
    int msqid;

    if ((msqid = msgget((key_t)__GOPHER_IPC_MSG_KEY, 0600 | ipc_flag)) == -1) {
        ERROR("[IPC] Create IPC message queue(ipc_flags = %d) failed.\n", ipc_flag);
        return -1;
    }

    return msqid;
}

void destroy_ipc_msg_queue(int msqid)
{
    if (msqid < 0) {
        return;
    }

    (void)msgctl(msqid, IPC_RMID, NULL);
}

int send_ipc_msg(int msqid, long msg_type, struct ipc_body_s* ipc_body)
{
    struct ipc_msg_s ipc_msg = {0};

    if (msqid < 0) {
        return -1;
    }

    if (msg_type < PROBE_BASEINFO || msg_type >= PROBE_TYPE_MAX) {
        return -1;
    }

    ipc_msg.msg_type = msg_type;
    (void)memcpy(&ipc_msg.ipc_body, ipc_body, sizeof(struct ipc_body_s));

    if (msgsnd(msqid, &ipc_msg, sizeof(struct ipc_body_s), 0) < 0) {
        ERROR("[IPC] send ipc message(msg_type = %d) failed.\n", msg_type);
        return -1;
    }

    return 0;
}

int recv_ipc_msg(int msqid, long msg_type, struct ipc_body_s *ipc_body)
{
    struct ipc_msg_s ipc_msg = {0};
    int msg_rcvd = 0;

    if (msqid < 0) {
        return -1;
    }

    /* Only deal with the last message within every check */
    while (msgrcv(msqid, &ipc_msg, sizeof(struct ipc_body_s), msg_type, IPC_NOWAIT) != -1) {
        msg_rcvd = 1;
    }

    if (msg_rcvd) {
        (void)memcpy(ipc_body, &ipc_msg.ipc_body, sizeof(struct ipc_body_s));
        return 0;
    }

    return -1;
}
