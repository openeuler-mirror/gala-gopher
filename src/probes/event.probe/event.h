 /*
  * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
  * gala-gopher licensed under the Mulan PSL v2.
  * You can use this software according to the terms and conditions of the Mulan PSL v2.
  * You may obtain a copy of Mulan PSL v2 at:
  *     http://license.coscl.org.cn/MulanPSL2
  * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
  * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
  * PURPOSE.
  * See the Mulan PSL v2 for more details.
  * Author: D.Wang
  * Description: event.h
  */
#ifndef EVENTPROBE__H
#define EVENTPROBE__H

#include <linux/types.h>

#include "base.h"

#define EVENT_LEVEL_INFO  "INFO"
#define EVENT_LEVEL_WARN  "WARN"
#define EVENT_LEVEL_ERROR "ERROR"
#define EVENT_LEVEL_FATAL "FATAL"

struct event_data {
    __u64 timestamp;  // UNIX Epoch time in seconds since 00:00:00 UTC on 1 January 1970.
    char level[16];   // Event level: "INFO"|"WARN"|"ERROR"|"FATAL".
    char body[MAX_DATA_STR_LEN];
};

void PrintEventOutput(const struct event_data *event);

#endif
