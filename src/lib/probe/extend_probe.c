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
 * Author: Hubble_Zhu
 * Create: 2021-04-12
 * Description:
 ******************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <time.h>

#include "probe_mng.h"

#define PROBE_START_DELAY           5
#define PROBE_LKUP_PID_RETRY_MAX    4
#define PROBE_LKUP_PID_DELAY        1

static FILE* __DoRunExtProbe(const struct probe_s *probe)
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

static void sendOutputToIngresss(struct probe_s *probe, char *buffer, uint32_t bufferSize)
{
    int ret = 0;
    char *dataStr;

    buffer[bufferSize - 1] = '\0';
    dataStr = strdup(buffer);
    if (dataStr == NULL) {
        return;
    }

    ret = FifoPut(probe->fifo, (void *)dataStr);
    if (ret) {
        ERROR("[E-PROBE %s] fifo put failed.\n", probe->name);
        (void)free(dataStr);
    }

    return;
}

static void writeIngressEvt(struct probe_s *probe)
{
    uint64_t msg = 1;
    int ret = write(probe->fifo->triggerFd, &msg, sizeof(uint64_t));
    if (ret != sizeof(uint64_t)) {
        ERROR("[E-PROBE %s] send trigger msg to eventfd failed.\n", probe->name);
    }
    return;
}

static void parseExtendProbeOutput(struct probe_s *probe, FILE *f)
{
#define __WRITE_EVT_PERIOD  5
    char buffer[MAX_DATA_STR_LEN];
    size_t bufferSize = 0;
    time_t last_wr_event = (time_t)0, current = (time_t)0;
    time_t secs;

    while (feof(f) == 0 && ferror(f) == 0) {
        if (FifoFull(probe->fifo)) {
            writeIngressEvt(probe);
            sleep(1);   // Rate limiting for probes
            continue;
        }

        if (fgets(buffer, sizeof(buffer), f) == NULL) {
            continue;
        }

        if (buffer[0] != '|') {
            convert_output_to_log(buffer, MAX_DATA_STR_LEN);
            continue;
        }

        bufferSize = strlen(buffer);
        if (bufferSize == 0 || buffer[bufferSize - 1] != '\n') {
            ERROR("[E-PROBE %s] stdout buf is empty or exceeds max length %lu\n", probe->name, bufferSize);
            continue;
        }

        sendOutputToIngresss(probe, buffer, bufferSize);
        if (last_wr_event == (time_t)0) {
            writeIngressEvt(probe);
            last_wr_event = (time_t)time(NULL);
        } else {
            current = (time_t)time(NULL);
            if (current > last_wr_event) {
                secs = current - last_wr_event;
                if (secs >= __WRITE_EVT_PERIOD) {
                    writeIngressEvt(probe);
                    last_wr_event = current;
                }
            }
        }
    }
    return;
}

static void RunExtendProbe(struct probe_s *probe)
{
    int retry = 0;
    FILE *f = NULL;

    f = __DoRunExtProbe(probe);
    if (f == NULL) {
        goto out;
    }

retry:
    if ((lkup_and_set_probe_pid(probe) != 0) && retry <= PROBE_LKUP_PID_RETRY_MAX) {
        /* The process may still be inaccessible here, so just retry */
        sleep(PROBE_LKUP_PID_DELAY);
        retry++;
        goto retry;
    }

    parseExtendProbeOutput(probe, f);

out:
    clear_ipc_msg((long)(probe->probe_type == PROBE_CUSTOM) ? (PROBE_CUSTOM_IPC + probe->custom.index) : probe->probe_type);
    if (f) {
        pclose(f);
    }
    set_probe_status_stopped(probe);
    return;
}

void *extend_probe_thread_cb(void *arg)
{
    struct probe_s *probe = (struct probe_s *)arg;

    char thread_name[MAX_THREAD_NAME_LEN];
    snprintf(thread_name, MAX_THREAD_NAME_LEN - 1, "[EPROBE]%s", probe->name);
    prctl(PR_SET_NAME, thread_name);

    RunExtendProbe(probe);
}
