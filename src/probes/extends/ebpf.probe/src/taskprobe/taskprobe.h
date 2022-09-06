/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: sinever
 * Create: 2021-10-25
 * Description: task_probe include file
 ******************************************************************************/
#ifndef __TASKPROBE__H
#define __TASKPROBE__H

#define PROBE_PROC_MAP_ENTRY_SIZE   128

enum task_type_e {
    TASK_TYPE_APP = 0,
    TASK_TYPE_KERN,
    TASK_TYPE_OS
};

/* daemon process be probed */
struct task_name_t {
    char name[TASK_COMM_LEN];
    enum task_type_e type;
};

/* process needed to be probed */
struct probe_process {
    char name[TASK_COMM_LEN];
};

void load_daemon_task_by_name(int fd, const char *name, int is_whole_word);

#endif
