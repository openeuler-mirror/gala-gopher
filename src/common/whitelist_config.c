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
 * Description: parse whitelist config
 ******************************************************************************/
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <unistd.h>
#include <libconfig.h>
#include "common.h"
#include "whitelist_config.h"

static int config_load_applications(void *config, config_setting_t *settings);

ApplicationsConfig *whitelist_config_create(void)
{
    ApplicationsConfig *conf = NULL;
    conf = (ApplicationsConfig *)malloc(sizeof(ApplicationsConfig));
    if (conf == NULL) {
        return NULL;
    }
    memset(conf, 0, sizeof(ApplicationsConfig));
    return conf;
}

void whitelist_config_destroy(ApplicationsConfig *conf)
{
    if (conf == NULL) {
        return;
    }

    for (int i = 0; i < conf->apps_num; i++) {
        if (conf->apps[i] != NULL) {
            free(conf->apps[i]);
        }
    }
    free(conf);
    return;
}

static int config_load(ApplicationsConfig *conf, const char *conf_path)
{
    int ret = 0;
    config_t cfg;
    config_setting_t *settings = NULL;

    config_init(&cfg);
    ret = config_read_file(&cfg, conf_path);
    if (ret == 0) {
        ERROR("[WHITELIST] config read %s failed.\n", conf_path);
        goto ERR;
    }

    settings = config_lookup(&cfg, "application");
    if (settings == NULL) {
        ERROR("[WHITELIST] config lookup application failed.\n");
        goto ERR;
    }
    ret = config_load_applications(conf, settings);
    if (ret != 0) {
        ERROR("[WHITELIST] config load handle config_load_applications failed.\n");
        goto ERR;
    }

    config_destroy(&cfg);
    return 0;
ERR:
    config_destroy(&cfg);
    return -1;
}

static int config_load_applications(void *config, config_setting_t *settings)
{
    ApplicationsConfig *appsConfig = (ApplicationsConfig *)config;
    int ret = 0;
    const char *commStr = NULL;
    const char *cmdlineStr = NULL;

    int count = config_setting_length(settings);
    for (int i = 0; i < count; i++) {
        if (appsConfig->apps_num == PROC_MAX_RANGE) {
            ERROR("[WHITELIST] apps config list full.\n");
            return -1;
        }
        config_setting_t *_app = config_setting_get_elem(settings, i);

        ApplicationConfig *_appConfig = (ApplicationConfig *)malloc(sizeof(ApplicationConfig));
        if (_appConfig == NULL) {
            ERROR("[WHITELIST] failed to malloc memory for appConfig.\n");
            return -1;
        }
        memset(_appConfig, 0, sizeof(ApplicationConfig));
        appsConfig->apps[appsConfig->apps_num] = _appConfig;
        appsConfig->apps_num++;

        ret = config_setting_lookup_string(_app, "comm", &commStr);
        if (ret == 0) {
            ERROR("[WHITELIST] load config for whitelist app's comm failed.\n");
            return -1;
        }
        (void)strncpy(_appConfig->comm, commStr, PROC_NAME_MAX - 1);

        ret = config_setting_lookup_string(_app, "cmdline", &cmdlineStr);
        if (ret == 0) {
            ERROR("[WHITELIST] load config for whitelist app's cmdline failed.\n");
            return -1;
        }
        (void)strncpy(_appConfig->cmd_line, cmdlineStr, PROC_CMD_LINE_MAX - 1);
    }

    return 0;
}

int parse_whitelist_config(ApplicationsConfig **conf, const char *path)
{
    int ret;

    if (access(path, 0) < 0) {
        ERROR("[WHITELIST] config path error: %s.\n", path);
        return -1;
    }

    *conf = whitelist_config_create();
    if (*conf == NULL) {
        ERROR("[WHITELIST] whitelist config create failed.\n");
        return -1;
    }

    ret = config_load(*conf, path);
    if (ret != 0) {
        whitelist_config_destroy(*conf);
        ERROR("[WHITELIST] whitelist load configuration failed.\n");
        return -1;
    }

    return 0;
}