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
 * Author: luzhihao
 * Create: 2022-04-12
 * Description:
 ******************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include "common.h"

#define KERN_CONFIG_CAT   "/usr/bin/cat /boot/config-$(uname -r) | grep -wn %s awk -F \":\" '{print $2}'"

#define CONFIG_NAME_LEN     128
#define COMMAND_LEN         256
#define BUF_LEN             256

struct kern_config {
    char name[CONFIG_NAME_LEN];
    char is_on;
};

static void __do_parse_config(struct kern_config *config, char buf[])
{
    char *p1, *p2;

    p1 = strchr(buf, '=');
    p2 = strchr(buf, '#');
    if ((p1 != NULL) && (p2 == NULL)) {
        p1++;
        if (*p1 == 'y') {
            config->is_on = 1;
            return;
        }
    }

    config->is_on = 0;
    return;
}

static int __do_grep_config(struct kern_config *config, char buf[], unsigned int buf_len)
{
    char command[COMMAND_LEN];
    FILE *f;

    command[0] = 0;
    buf[0] = 0;
    (void)snprintf(command, COMMAND_LEN, KERN_CONFIG_CAT, config->name);
    f = popen_chroot(command, "r");
    if (f == NULL) {
        return -1;
    }

    if (fgets(buf, buf_len, f) == NULL) {
        (void)pclose(f);
        return -1;
    }

    (void)pclose(f);
    return 0;
}

bool kern_config_is_on(char *name)
{
    int ret;
    char buf[BUF_LEN];
    struct kern_config config;

    config.name[0] = 0;
    (void)snprintf(config.name, CONFIG_NAME_LEN, "CONFIG_%s", name);

    ret = __do_grep_config(&config, buf, BUF_LEN);
    if (ret != 0)
        return false;

    __do_parse_config(&config, buf);
    return (config.is_on == 1);
}

