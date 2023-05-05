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

#include "extend_probe.h"
#include "probe_mng.h"

#define PROBE_START_DELAY 5

ExtendProbe *ExtendProbeCreate(void)
{
    ExtendProbe *probe = NULL;
    probe = (ExtendProbe *)malloc(sizeof(ExtendProbe));
    if (probe == NULL)
        return NULL;
    memset(probe, 0, sizeof(ExtendProbe));

    probe->fifo = FifoCreate(MAX_FIFO_SIZE);
    if (probe->fifo == NULL) {
        free(probe);
        return NULL;
    }
    return probe;
}

void ExtendProbeDestroy(ExtendProbe *probe)
{
    if (probe == NULL)
        return;

    if (probe->fifo != NULL)
        FifoDestroy(probe->fifo);

    free(probe);
    return;
}

FILE* __DoRunExtProbe(ExtendProbe *probe)
{
    char command[MAX_COMMAND_LEN];
    FILE *f = NULL;

    command[0] = 0;
    (void)snprintf(command, MAX_COMMAND_LEN - 1, "%s %s", probe->executeCommand, probe->executeParam);
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

int RunExtendProbe(ExtendProbe *probe)
{
    int ret = 0;
    FILE *f = NULL;
    char buffer[MAX_DATA_STR_LEN];
    uint32_t bufferSize = 0;

    char *dataStr = NULL;
    uint32_t index = 0;

    f = __DoRunExtProbe(probe);
    probe->is_exist = 1;

    while (feof(f) == 0 && ferror(f) == 0) {
        if (fgets(buffer, sizeof(buffer), f) == NULL)
            continue;

        if (buffer[0] != '|') {
            //INFO("[%s]: %s", probe->name, buffer);
            continue;
        }

        if ((bufferSize = strlen(buffer)) >= MAX_DATA_STR_LEN) {
            ERROR("[E-PROBE %s] stdout buf(len:%u) is too long\n", probe->name, bufferSize);
            continue;
        }
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

    probe->is_exist = 0;
    pclose(f);
    return 0;
}

ExtendProbeMgr *ExtendProbeMgrCreate(uint32_t size)
{
    ExtendProbeMgr *mgr = NULL;
    mgr = (ExtendProbeMgr *)malloc(sizeof(ExtendProbeMgr));
    if (mgr == NULL)
        return NULL;
    memset(mgr, 0, sizeof(ExtendProbeMgr));

    mgr->probes = (ExtendProbe **)malloc(sizeof(ExtendProbe *) * size);
    if (mgr->probes == NULL) {
        free(mgr);
        return NULL;
    }
    memset(mgr->probes, 0, sizeof(ExtendProbe *) * size);

    mgr->size = size;
    return mgr;
}

void ExtendProbeMgrDestroy(ExtendProbeMgr *mgr)
{
    if (mgr == NULL)
        return;

    if (mgr->probes != NULL) {
        for (int i = 0; i < mgr->probesNum; i++)
            ExtendProbeDestroy(mgr->probes[i]);
        free(mgr->probes);
    }
    free(mgr);
    return;
}

int ExtendProbeMgrPut(ExtendProbeMgr *mgr, ExtendProbe *probe)
{
    if (mgr->probesNum == mgr->size)
        return -1;

    mgr->probes[mgr->probesNum] = probe;
    mgr->probesNum++;
    return 0;
}

ExtendProbe *ExtendProbeMgrGet(ExtendProbeMgr *mgr, const char *probeName)
{
    for (int i = 0; i < mgr->probesNum; i++) {
        if (strcmp(mgr->probes[i]->name, probeName) == 0)
            return mgr->probes[i];
    }
    return NULL;
}

FILE* New__DoRunExtProbe(struct probe_s *probe)
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

int New_RunExtendProbe(struct probe_s *probe)
{
    int ret = 0;
    FILE *f = NULL;
    char buffer[MAX_DATA_STR_LEN];
    uint32_t bufferSize = 0;

    char *dataStr = NULL;
    uint32_t index = 0;

    f = New__DoRunExtProbe(probe);
    SET_PROBE_FLAGS(probe, PROBE_FLAGS_RUNNING);

    while (feof(f) == 0 && ferror(f) == 0) {
        if (IS_STOPPING_PROBE(probe)) {
            break;
        }
        if (fgets(buffer, sizeof(buffer), f) == NULL)
            continue;

        if (buffer[0] != '|') {
            //INFO("[%s]: %s", probe->name, buffer);
            continue;
        }

        if ((bufferSize = strlen(buffer)) >= MAX_DATA_STR_LEN) {
            ERROR("[E-PROBE %s] stdout buf(len:%u) is too long\n", probe->name, bufferSize);
            continue;
        }
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

    (void)New_RunExtendProbe(probe);
}