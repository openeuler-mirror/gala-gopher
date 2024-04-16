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
 * Author: dowzyx
 * Create: 2023-01-06
 * Description: header for event config
 ******************************************************************************/
#ifndef __GOPHER_EVENT_CONFIG_H__
#define __GOPHER_EVENT_CONFIG_H__

#include "common.h"

#pragma once

#if 0
#define MAX_EVENT_NUM           512
#define MAX_ENTITY_NAME_LEN     128
#define MAX_METRIC_NAME_LEN     64
#define MAX_EVT_BODY_LEN        512   // same as __EVT_BODY_LEN
#define MAX_EVT_GRP_NAME_LEN    64

typedef struct {
    char metric[MAX_METRIC_NAME_LEN];
    char desc[MAX_EVT_BODY_LEN];
} jsonfieldsConfig;

typedef struct {
    char entity_name[MAX_ENTITY_NAME_LEN];
    int fields_num;
    jsonfieldsConfig json_fields[MAX_EVENT_NUM];
} eventConfig;

typedef struct {
    int num;
    eventConfig *events[MAX_EVENT_NUM];
} EventsConfig;

int events_config_init(EventsConfig **conf, char *lang_type);
int get_event_field(EventsConfig *conf, const char *entity, const char *metric, char *desc_fmt);
#endif

#endif
