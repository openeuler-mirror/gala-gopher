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
  * Description: event infomation egress probe
  */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "nprobe_fprintf.h"
#include "common.h"
#include "event.h"

#define LOG_MESSAGES "/var/log/messages"
#define CMD_FILE_LINE_NUM "/usr/bin/wc -l %s | awk '{print $1}'"
#define CMD_EVENT_CODE_ABNORMAL "/usr/bin/sed -n '%u,%up' %s |grep 'code=\\[[1-9][0-9]*\\]'"

#define LEN_BUF	  64
#define LEN_CMD	  128
#define LEN_LINE  1024
#define TIME_INTERVAL 1000

static int g_nextLineNum = 0;

void PrintEventOutput(const struct event_data *event)
{
    char timestamp[LEN_BUF] = {0};
    sprintf(timestamp, "%llu", event->timestamp);

    nprobe_fprintf(stdout, "|%s|%s|%s|%s|\n", "event", timestamp, event->level, event->body);
}

static int GetFileLineNum(void)
{
    int ret;
    FILE *f = NULL;
    char count[LEN_BUF];
    char cmd[LEN_CMD] = {0};

    sprintf(cmd, CMD_FILE_LINE_NUM, LOG_MESSAGES);

    f = popen(cmd, "r");
    if (f == NULL) {
        return -1;
    }

    if (!feof(f)) {
        if (fgets(count, LEN_BUF, f) == NULL) {
            (void)pclose(f);
            return -1;
        }
    }

    ret = atoi(count);

    (void)pclose(f);

    return ret;
}

static void MakeEvent(const char * log)
{
    struct event_data event = {0};

    time_t now;
    time(&now);
    event.timestamp = now*TIME_INTERVAL*TIME_INTERVAL*TIME_INTERVAL;

    strcpy(event.body, log);
    strcpy(event.level, EVENT_LEVEL_ERROR);
    PrintEventOutput(&event);
}

static int FilterLogEvent(void)
{
    FILE *f = NULL;
    char line[LEN_LINE];
    char cmd[LEN_CMD] = {0};

    int lineNum = GetFileLineNum();
    if (lineNum < 1) {
       return -1;
    }

    // init g_next_line_num, from current file bottom line
    if (g_nextLineNum == 0) {
        g_nextLineNum = lineNum;
    }
    if (g_nextLineNum - lineNum == 1) {    // file line readed
        return 0;
    } else if (g_nextLineNum - lineNum > 1) { // log file rewrite from beginning
        g_nextLineNum = 1;
    }

    sprintf(cmd, CMD_EVENT_CODE_ABNORMAL, g_nextLineNum, lineNum, LOG_MESSAGES);

    f = popen(cmd, "r");
    if (f == NULL) {
        return -1;
    }

    while (!feof(f)) {
        if (fgets(line, LINE_BUF_LEN, f) == NULL) {
            goto out;
        }
        if (strlen(line) > 0) {
            if (line[strlen(line)-1] == '\n') {
                line[strlen(line)-1] = '\0';
            }
            MakeEvent(line);
            sprintf(line, "");
        }
    }

out:
    g_nextLineNum = lineNum + 1;

    (void)pclose(f);

    return 0;
}

int main(int argc, char **argv)
{
    int ret = FilterLogEvent();
    if (ret != 0) {
        return -1;
    }

    return 0;
}
