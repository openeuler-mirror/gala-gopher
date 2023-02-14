/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wo_cow
 * Create: 2022-10-14
 * Description: parse stackprobe.conf
 ******************************************************************************/
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <unistd.h>
#include <libconfig.h>
#include "common.h"
#include "stackprobe_conf.h"

static int configLoadGeneral(void *config, config_setting_t *settings);
static int configLoadFlameTypes(void *config, config_setting_t *settings);
static int configLoadApplications(void *config, config_setting_t *settings);

void configDestroy(StackprobeConfig *conf)
{
    if (conf == NULL) {
        return;
    }

    if (conf->generalConfig != NULL) {
        free(conf->generalConfig);
    }

    if (conf->flameTypesConfig != NULL) {
        free(conf->flameTypesConfig);
    }

    if (conf->applicationsConfig != NULL) {
        for (int i = 0; i < conf->applicationsConfig->confNum; i++) {
            if (conf->applicationsConfig->confs[i] != NULL) {
                free(conf->applicationsConfig->confs[i]);
            }
        }
        free(conf->applicationsConfig);
    }

    free(conf);
    return;
}

StackprobeConfig *configCreate(void)
{
    StackprobeConfig *conf = NULL;
    conf = (StackprobeConfig *)malloc(sizeof(StackprobeConfig));
    if (conf == NULL) {
        return NULL;
    }
    memset(conf, 0, sizeof(StackprobeConfig));

    conf->generalConfig = (GeneralConfig *)malloc(sizeof(GeneralConfig));
    if (conf->generalConfig == NULL) {
        goto ERR;
    }
    memset(conf->generalConfig, 0, sizeof(GeneralConfig));

    conf->flameTypesConfig = (FlameTypesConfig *)malloc(sizeof(FlameTypesConfig));
    if (conf->flameTypesConfig == NULL) {
        goto ERR;
    }
    memset(conf->flameTypesConfig, 0, sizeof(FlameTypesConfig));

    conf->applicationsConfig = (ApplicationsConfig *)malloc(sizeof(ApplicationsConfig));
    if (conf->applicationsConfig == NULL) {
        goto ERR;
    }
    memset(conf->applicationsConfig, 0, sizeof(ApplicationsConfig));

    return conf;
ERR:
    configDestroy(conf);
    return NULL;
}

typedef int (*configLoadFunc)(void *config, config_setting_t *settings);

typedef struct {
    void *config;
    char *sectionName;
    configLoadFunc func;
} configLoadHandle;

int configLoad(StackprobeConfig *conf, const char *confPath)
{
    configLoadHandle configLoadHandles[] = {
        { (void *)conf->generalConfig, "general", configLoadGeneral },
        { (void *)conf->flameTypesConfig, "flame_name", configLoadFlameTypes },
        { (void *)conf->applicationsConfig, "application", configLoadApplications }
    };

    int ret = 0;
    config_t cfg;
    config_setting_t *settings = NULL;

    config_init(&cfg);
    ret = config_read_file(&cfg, confPath);
    if (ret == 0) {
        ERROR("[STACKPROBE]: config read %s failed.\n", confPath);
        goto ERR;
    }

    u32 configUnitNum = sizeof(configLoadHandles) / sizeof(configLoadHandles[0]);
    for (int i = 0; i < configUnitNum; i++) {
        settings = config_lookup(&cfg, configLoadHandles[i].sectionName);
        if (settings == NULL) {
            ERROR("[STACKPROBE]: config lookup %s failed.\n", configLoadHandles[i].sectionName);
            goto ERR;
        }

        ret = configLoadHandles[i].func(configLoadHandles[i].config, settings);
        if (ret != 0) {
            ERROR("[STACKPROBE]: config load handle %s failed.\n", configLoadHandles[i].sectionName);
            goto ERR;
        }
    }

    config_destroy(&cfg);
    return 0;
ERR:
    config_destroy(&cfg);
    return -1;
}

int configInit(StackprobeConfig **conf, const char *path)
{
    int ret = 0;

    if (access(path, 0) < 0) {
        ERROR("[STACKPROBE]: config path error:%s.\n", path);
        return -1;
    }

    *conf = configCreate();
    if (*conf == NULL) {
        ERROR("[STACKPROBE]: configInit failed.\n");
        return -1;
    }

    ret = configLoad(*conf, path);
    if (ret != 0) {
        configDestroy(*conf);
        ERROR("[STACKPROBE]: load configuration failed.\n");
        return -1;
    }

    return 0;
}

static int configLoadGeneral(void *config, config_setting_t *settings)
{
    GeneralConfig *generalConfig = (GeneralConfig *)config;
    int ret = 0;
    const char *strVal = NULL;
    int intVal = 0;

    ret = config_setting_lookup_bool(settings, "whitelist_enable", &intVal);
    if (ret == 0) {
        ERROR("[STACKPROBE]: load config for general whitelist_enable failed.\n");
        return -1;
    }
    generalConfig->whitelistEnable = intVal;

    ret = config_setting_lookup_int(settings, "period", &intVal);
    if (ret == 0) {
        ERROR("[STACKPROBE]: load config for general period failed.\n");
        return -1;
    }
    if (intVal < PERIOD_MIN || intVal > PERIOD_MAX) {
        ERROR("[STACKPROBE]: Please check config for general period, val shold inside 30~600.\n");
        return -1;
    }
    generalConfig->period = intVal;

    ret = config_setting_lookup_string(settings, "log_dir", &strVal);
    if (ret == 0) {
        ERROR("[STACKPROBE]: load config for general log_dir failed.\n");
        return -1;
    }
    (void)strncpy(generalConfig->logDir, strVal, PATH_LEN - 1);

    ret = config_setting_lookup_string(settings, "svg_dir", &strVal);
    if (ret == 0) {
        ERROR("[STACKPROBE]: load config for general svg_dir failed.\n");
        return -1;
    }
    (void)strncpy(generalConfig->svgDir, strVal, PATH_LEN - 1);

    ret = config_setting_lookup_string(settings, "flame_dir", &strVal);
    if (ret == 0) {
        ERROR("[STACKPROBE]: load config for general flame_dir failed.\n");
        return -1;
    }
    (void)strncpy(generalConfig->flameDir, strVal, PATH_LEN - 1);

    ret = config_setting_lookup_string(settings, "debug_dir", &strVal);
    if (ret == 0) {
        ERROR("[STACKPROBE]: load config for general debug_dir failed.\n");
        return -1;
    }
    (void)strncpy(generalConfig->debugDir, strVal, PATH_LEN - 1);

    ret = config_setting_lookup_string(settings, "pyroscope_server", &strVal);
    if (ret == 0) {
        strVal = ""; // will not post to pyroscope
    }
    (void)strncpy(generalConfig->pyroscopeServer, strVal, PATH_LEN - 1);

    return 0;
}

static int configLoadFlameTypes(void *config, config_setting_t *settings)
{
    FlameTypesConfig *flameTypesConfig = (FlameTypesConfig *)config;
    int ret = 0;
    int intVal = 0;

    ret = config_setting_lookup_bool(settings, "oncpu", &intVal);
    if (ret == 0) {
        ERROR("[STACKPROBE]: load config for flame_name oncpu failed.\n");
        return -1;
    }
    flameTypesConfig->oncpu = intVal;

    ret = config_setting_lookup_bool(settings, "offcpu", &intVal);
    if (ret == 0) {
        ERROR("[STACKPROBE]: load config for flame_name offcpu failed.\n");
        return -1;
    }
    flameTypesConfig->offcpu = intVal;

    ret = config_setting_lookup_bool(settings, "io", &intVal);
    if (ret == 0) {
        ERROR("[STACKPROBE]: load config for flame_name io failed.\n");
        return -1;
    }
    flameTypesConfig->io = intVal;

    ret = config_setting_lookup_bool(settings, "memleak", &intVal);
    if (ret == 0) {
        ERROR("[STACKPROBE]: load config for flame_name memleak failed.\n");
        return -1;
    }
    flameTypesConfig->memleak = intVal;

    return 0;
}

static int configLoadApplications(void *config, config_setting_t *settings)
{
    ApplicationsConfig *applicationsConfig = (ApplicationsConfig *)config;
    int ret = 0;
    int count = 0;
    const char *strVal = NULL;

    count = config_setting_length(settings);
    for (int i = 0; i < count; i++) {
        if (applicationsConfig->confNum == FLAME_MAX_RANGE) {
            ERROR("[STACKPROBE]: applicationsConfig list full.\n");
            return -1;
        }
        config_setting_t *_elem = config_setting_get_elem(settings, i);

        ApplicationConfig *_applicationConf = (ApplicationConfig *)malloc(sizeof(ApplicationConfig));
        if (_applicationConf == NULL) {
            ERROR("[STACKPROBE]: failed to malloc memory for ApplicationConfig \n");
            return -1;
        }
        memset(_applicationConf, 0, sizeof(ApplicationConfig));
        applicationsConfig->confs[applicationsConfig->confNum] = _applicationConf;
        applicationsConfig->confNum++;

        ret = config_setting_lookup_string(_elem, "comm", &strVal);
        if (ret == 0) {
            ERROR("[STACKPROBE]: load config for application comm failed.\n");
            return -1;
        }
        (void)strncpy(_applicationConf->comm, strVal, PROC_NAME_MAX - 1);

        ret = config_setting_lookup_string(_elem, "debug_dir", &strVal);
        if (ret == 0) {
            ERROR("[STACKPROBE]: load config for application debug_dir failed.\n");
            return -1;
        }
        (void)strncpy(_applicationConf->debugDir, strVal, PATH_LEN - 1);

        ret = config_setting_lookup_string(_elem, "switch", &strVal);
        if (ret == 0) {
            ERROR("[STACKPROBE]: load config for application switch failed.\n");
            return -1;
        }
        if (strcmp(strVal, "on") == 0) {
            _applicationConf->swit = SWITCH_ON;
        } else {
            _applicationConf->swit = SWITCH_OFF;
        }
    }

    return 0;
}

