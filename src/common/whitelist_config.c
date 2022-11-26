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
#include <dirent.h>
#include <sys/types.h>
#include <libconfig.h>
#include "common.h"
#include "whitelist_config.h"

#define PROC_PATH           "/proc"
#define PROC_COMM_CMD       "/usr/bin/cat /proc/%s/comm 2> /dev/null"
#define PROC_COMM           "/proc/%s/comm"
#define PROC_CMDLINE_CMD    "/proc/%s/cmdline"

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
        (void)strncpy(_appConfig->cmd_line, cmdlineStr, PROC_CMDLINE_LEN - 1);
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

int get_proc_cmdline(const char *pid, char *buf, u32 buf_len)
{
    FILE *f = NULL;
    char path[LINE_BUF_LEN];
    int index = 0;

    (void)memset(buf, 0, buf_len);

    path[0] = 0;
    (void)snprintf(path, LINE_BUF_LEN, PROC_CMDLINE_CMD, pid);
    f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }
    /* parse line */
    while (!feof(f)) {
        if (index >= buf_len - 1) {
            buf[index] = '\0';
            break;
        }
        buf[index] = fgetc(f);
        if (buf[index] == '\"') {
            if (index > buf_len -2) {
                buf[index] = '\0';
                break;
            } else {
                buf[index] = '\\';
                buf[index + 1] =  '\"';
                index++;
            }
        } else if (buf[index] == '\0') {
            buf[index] = ' ';
        } else if (buf[index] == EOF) {
            buf[index] = '\0';
        }
        index++;
    }

    (void)fclose(f);
    return 0;
}

int get_proc_comm(const char *pid, char *buf)
{
    FILE *f = NULL;
    char fname_or_cmd[LINE_BUF_LEN];
    char line[LINE_BUF_LEN];

    fname_or_cmd[0] = 0;
    (void)snprintf(fname_or_cmd, LINE_BUF_LEN, PROC_COMM, pid);
    if (access((const char *)fname_or_cmd, 0) != 0) {
        return -1;
    }

    fname_or_cmd[0] = 0;
    line[0] = 0;
    (void)snprintf(fname_or_cmd, LINE_BUF_LEN, PROC_COMM_CMD, pid);
    f = popen(fname_or_cmd, "r");
    if (f == NULL) {
        ERROR("[WIHTELIST] proc cat fail, popen error.\n");
        return -1;
    }
    if (fgets(line, LINE_BUF_LEN, f) == NULL) {
        (void)pclose(f);
        ERROR("[WHITELIST] proc get_info fail, line is null.\n");
        return -1;
    }

    SPLIT_NEWLINE_SYMBOL(line);
    (void)strncpy(buf, line, PROC_NAME_MAX - 1);
    (void)pclose(f);
    return 0;
}

static inline int is_proc_subdir(const char *pid)
{
    if (*pid >= '1' && *pid <= '9') {
        return 0;
    }
    return -1;
}

int check_proc_probe_flag(ApplicationConfig *appsConfig, u32 appsConfig_len,
        const char *pid, const char *comm)
{
    u32 index;
    int ret;
    char cmdline[PROC_CMDLINE_MAX];

    for (index = 0; index < appsConfig_len; index++) {
        if (strstr(comm, appsConfig[index].comm) == NULL) {
            continue;
        }
        if (appsConfig[index].cmd_line == NULL) {
            return 1;
        }
        (void)memset(cmdline, 0, sizeof(cmdline));
        ret = get_proc_cmdline(pid, cmdline, sizeof(cmdline));
        if (ret != 0) {
            ERROR("[WHITELIST] check proc probe flag failed, get(%s)'s cmdline failed.\n", pid);
            break;
        }
        if (strstr(cmdline, appsConfig[index].cmd_line) != NULL) {
            return 1;
        } else {
            return 0;
        }
    }
    return 0;
}

int get_probe_proc_whitelist(ApplicationConfig *appsConfig, u32 appsConfig_len,
        u32 proc_whitelist[], u32 proc_whitelist_len)
{
    DIR *dir = NULL;
    struct dirent *entry;
    char comm[PROC_NAME_MAX];
    int list_len = 0;
    
    dir = opendir(PROC_PATH);
    if (dir == NULL) {
        return -1;
    }

    while (entry = readdir(dir)) {
        if (is_proc_subdir(entry->d_name) == -1) {
            continue;
        }

        (void)get_proc_comm(entry->d_name, comm);

        if (check_proc_probe_flag(appsConfig, appsConfig_len, entry->d_name, comm) != 1) {
            continue;
        } else {
            proc_whitelist[list_len] = (u32)atoi(entry->d_name);
            list_len++;            
        }
        if (list_len >= proc_whitelist_len) {
            ERROR("[WHITELIST] probe proc list is full.\n");
            break;
        }
    }

    closedir(dir);
    return 0;
}
