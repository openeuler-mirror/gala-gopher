/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: Hubble_Zhu
 * Create: 2021-04-12
 * Description:
 ******************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "probe_mng.h"

#define PROBE_START_DELAY 5
#define PROBE_LKUP_PID_RETRY_MAX 2
#define PROBE_LKUP_PID_DELAY 2

FILE* __DoRunExtProbe(struct probe_s *probe)
{
    char command[MAX_COMMAND_LEN];
    FILE *f = NULL;

    command[0] = 0;
    (void)snprintf(command, MAX_COMMAND_LEN - 1, "%s", probe->bin);
repeat:
    f = popen(command, "r");
    if (feof(f) != 0 || ferror(f) != 0) {
        pclose(f);
        f = NULL;
        sleep(PROBE_START_DELAY);
        goto repeat;
    }
    return f;
}

#define EXTEND_PROBE_PROCID_CMD  "ps -ef | grep -w %s | grep -v grep | awk '{print $2}'"
static int lkup_and_set_probe_pid(struct probe_s *probe)
{
    int pid;
    char cmd[COMMAND_LEN];
    char pid_str[INT_LEN];


    if (probe->bin == NULL) {
        return -1;
    }

    cmd[0] = 0;
    (void)snprintf(cmd, COMMAND_LEN, EXTEND_PROBE_PROCID_CMD, probe->bin);
    if (exec_cmd((const char *)cmd, pid_str, INT_LEN) < 0) {
        return -1;
    }
    pid = atoi(pid_str);
    (void)pthread_rwlock_wrlock(&probe->rwlock);
    probe->pid = pid;
    (void)pthread_rwlock_unlock(&probe->rwlock);
    return (pid > 0) ? 0 : -1;
}

static void sendOutputToIngresss(struct probe_s *probe, char *buffer, uint32_t bufferSize)
{
    int ret = 0;
    char *dataStr = NULL;
    uint32_t index = 0;

    for (int i = 0; i < bufferSize; i++) {
        if (dataStr == NULL) {
            dataStr = (char *)malloc(MAX_DATA_STR_LEN);
            if (dataStr == NULL) {
                break;
            }
            // memset(dataStr, 0, sizeof(MAX_DATA_STR_LEN));
            index = 0;
        }

        if (buffer[i] == '\n') {
            dataStr[index] = '\0';
            ret = FifoPut(probe->fifo, (void *)dataStr);
            if (ret != 0) {
                ERROR("[E-PROBE %s] fifo full.\n", probe->name);
                (void)free(dataStr);
                dataStr = NULL;
                break;
            }

            uint64_t msg = 1;
            ret = write(probe->fifo->triggerFd, &msg, sizeof(uint64_t));
            if (ret != sizeof(uint64_t)) {
                ERROR("[E-PROBE %s] send trigger msg to eventfd failed.\n", probe->name);
                break;
            }

            // reset dataStr
            DEBUG("[E-PROBE %s] send data to ingresss succeed.(content=%s)\n", probe->name, dataStr);
            dataStr = NULL;
        } else {
            dataStr[index] = buffer[i];
            index++;
        }
    }
}

static void parseExtendProbeOutput(struct probe_s *probe, FILE *f)
{
    int ret = 0;
    char buffer[MAX_DATA_STR_LEN];
    uint32_t bufferSize = 0;

    while (feof(f) == 0 && ferror(f) == 0) {
        if (IS_STOPPING_PROBE(probe)) {
            break;
        }
        if (fgets(buffer, sizeof(buffer), f) == NULL)
            continue;

        if (buffer[0] != '|') {
            continue;
        }

        if ((bufferSize = strlen(buffer)) >= MAX_DATA_STR_LEN) {
            ERROR("[E-PROBE %s] stdout buf(len:%u) is too long\n", probe->name, bufferSize);
            continue;
        }
        sendOutputToIngresss(probe, buffer, bufferSize);
    }
}

int RunExtendProbe(struct probe_s *probe)
{
    int ret = 0, retry = 0;
    FILE *f = NULL;

    f = __DoRunExtProbe(probe);
    SET_PROBE_FLAGS(probe, PROBE_FLAGS_RUNNING);
    UNSET_PROBE_FLAGS(probe, PROBE_FLAGS_STOPPED);

retry:
    if (lkup_and_set_probe_pid(probe) && retry <= PROBE_LKUP_PID_RETRY_MAX) {
        /* The process may still be inaccessible here, so just retry */
        sleep(PROBE_LKUP_PID_DELAY);
        retry++;
        goto retry;
    }

    parseExtendProbeOutput(probe, f);

    SET_PROBE_FLAGS(probe, PROBE_FLAGS_STOPPED);
    UNSET_PROBE_FLAGS(probe, PROBE_FLAGS_RUNNING);
    pclose(f);
    return 0;
}

void *extend_probe_thread_cb(void *arg)
{
    int ret = 0;
    struct probe_s *probe = (struct probe_s *)arg;

    char thread_name[MAX_THREAD_NAME_LEN];
    snprintf(thread_name, MAX_THREAD_NAME_LEN - 1, "[EPROBE]%s", probe->name);
    prctl(PR_SET_NAME, thread_name);

    (void)RunExtendProbe(probe);
}