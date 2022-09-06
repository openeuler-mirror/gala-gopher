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
 * Author: Mr.lu
 * Create: 2021-05-17
 * Description: kill_probe include file
 ******************************************************************************/
#ifndef __KILLPROBE__H
#define __KILLPROBE__H

#define KILL_INFO_MAX_NUM 100
#define MONITOR_PIDS_MAX_NUM 10

#define PROBE_CYCLE_SEC (5)

struct val_t {
   __u64 killer_pid;
   int signal;
   int killed_pid;
   char comm[TASK_COMM_LEN];
};

#endif