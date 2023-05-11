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
 * Create: 2022-11-02
 * Description: header for whitelist config
 ******************************************************************************/
#ifndef __GOPHER_WHITELIST_CONFIG_H__
#define __GOPHER_WHITELIST_CONFIG_H__

#include "common.h"

#pragma once

#define PROC_NAME_MAX       64
#define PROC_MAX_RANGE      64
#define PROC_CMDLINE_MAX    4096
#define PROC_LIST_LEN_MAX   256

typedef struct {
    char comm[PROC_NAME_MAX];
    char cmd_line[PROC_CMDLINE_LEN];
} ApplicationConfig;

typedef struct {
    int apps_num;
    ApplicationConfig *apps[PROC_MAX_RANGE];
} ApplicationsConfig;

int parse_whitelist_config(ApplicationsConfig **conf, const char *path);
int is_str_match_pattern(const char *string, char *pattern);
void whitelist_config_destroy(ApplicationsConfig *conf);
int check_proc_probe_flag(ApplicationConfig *appsConfig, u32 appsConfig_len,
        const char *pid, const char *comm);
int get_probe_proc_whitelist(ApplicationConfig *appsconfig, u32 appsConfig_len,
        u32 proc_whitelist[], u32 proc_whitelist_len);
#endif
