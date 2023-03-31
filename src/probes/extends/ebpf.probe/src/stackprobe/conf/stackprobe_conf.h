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
 * Author: wo_cow
 * Create: 2022-10-14
 * Description: stackprobe conf header
 ******************************************************************************/
#ifndef __STACKPROBE_CONF_H__
#define __STACKPROBE_CONF_H__

#pragma once

#define PROC_NAME_MAX       64
#define FLAME_NAME_MAX      64
#define FLAME_MAX_RANGE     64
#define PROC_MAX_RANGE      64
#define PERIOD_MAX          600
#define PERIOD_MIN          30
#define SAMPLE_PERIOD_MAX   1000
#define SAMPLE_PERIOD_MIN   10

typedef enum {
    SWITCH_ON = 0,
    SWITCH_OFF
} Switch;

typedef struct {
    int period;
    int samplePeriod;
    char logDir[PATH_LEN];
    char svgDir[PATH_LEN];
    char flameDir[PATH_LEN];
    char debugDir[PATH_LEN];
    char pyroscopeServer[PATH_LEN];
    u32 whitelistEnable; // 0:disable 1:enable
} GeneralConfig;

typedef struct {
    u32 oncpu;
    u32 offcpu;
    u32 io;
    u32 memleak;
} FlameTypesConfig;

typedef struct {
    char comm[PROC_NAME_MAX];
    char debugDir[PATH_LEN];
    Switch swit;
} ApplicationConfig;

typedef struct {
    u32 confNum;
    ApplicationConfig *confs[PROC_MAX_RANGE];
} ApplicationsConfig;

typedef struct {
    GeneralConfig *generalConfig;
    FlameTypesConfig *flameTypesConfig;
    ApplicationsConfig *applicationsConfig;
} StackprobeConfig;

int configInit(StackprobeConfig **conf, const char *path);

#endif
