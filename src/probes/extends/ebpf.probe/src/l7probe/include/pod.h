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
 * Create: 2023-02-20
 * Description: pod definitions
 ******************************************************************************/
#ifndef __POD_H__
#define __POD_H__

#define MAX_CGRP_PATH 512

enum cgrp_event_t {
    CGRP_MK,
    CGRP_RM,
};

struct cgroup_msg_data_t {
    enum cgrp_event_t cgrp_event;
    char cgrp_path[MAX_CGRP_PATH];
};

void del_pods();
void l7_cgroup_msg_handler(void *ctx, int cpu, void *data, unsigned int size);


enum filter_op_t {
    FILTER_OP_ADD,
    FILTER_OP_RM,
};

int filter_pod_op(const char *pod_id, enum filter_op_t op);
int filter_container_op(const char *container_id, enum filter_op_t op);

#endif