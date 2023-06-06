/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: algorithmofdish
 * Create: 2023-04-03
 * Description: header file for handling thread profiling event.
 ******************************************************************************/
#ifndef __PROFILING_EVENT_H__
#define __PROFILING_EVENT_H__

#include "tprofiling.h"

#define MAX_LEN_OF_PROFILE_EVT_TYPE 8

#define PROFILE_EVT_TYPE_FILE  "file"
#define PROFILE_EVT_TYPE_NET   "net"
#define PROFILE_EVT_TYPE_SCHED  "sched"
#define PROFILE_EVT_TYPE_LOCK "lock"
#define PROFILE_EVT_TYPE_ONCPU "oncpu"
#define PROFILE_EVT_TYPE_OTHER "other"

#define ERR_TP_NO_BUFF 2

int init_sys_boot_time(__u64 *sysBootTime);
void output_profiling_event(trace_event_data_t *evt_data);

#endif