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
#include <sys/epoll.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include "logs.h"
#include "ingress.h"

IngressMgr *IngressMgrCreate(void)
{
    IngressMgr *mgr = NULL;
    mgr = (IngressMgr *)malloc(sizeof(IngressMgr));
    if (mgr == NULL) {
        return NULL;
    }
    memset(mgr, 0, sizeof(IngressMgr));
    return mgr;
}

void IngressMgrDestroy(IngressMgr *mgr)
{
    if (mgr == NULL) {
        return;
    }

    free(mgr);
    return;
}

static int IngressInit(IngressMgr *mgr)
{
    struct epoll_event event;
    uint32_t ret = 0;

    mgr->epoll_fd = epoll_create(MAX_EPOLL_SIZE);
    if (mgr->epoll_fd < 0) {
        return -1;
    }

    // add all probe triggerFd into mgr->epoll_fd
    ProbeMgr *probeMgr = mgr->probeMgr;
    for (int i = 0; i < probeMgr->probesNum; i++) {
        Probe *probe = probeMgr->probes[i];
        event.events = EPOLLIN;
        event.data.ptr = probe->fifo;

        ret = epoll_ctl(mgr->epoll_fd, EPOLL_CTL_ADD, probe->fifo->triggerFd, &event);
        if (ret < 0) {
            ERROR("[INGRESS] add EPOLLIN event failed, probe %s.\n", probe->name);
            return -1;
        }

        INFO("[INGRESS] Add EPOLLIN event success, probe %s.\n", probe->name);
    }

    // add all extend probe triggerfd into mgr->epoll_fd
    ExtendProbeMgr *extendProbeMgr = mgr->extendProbeMgr;
    for (int i = 0; i < extendProbeMgr->probesNum; i++) {
        ExtendProbe *extendProbe = extendProbeMgr->probes[i];
        event.events = EPOLLIN;
        event.data.ptr = extendProbe->fifo;

        ret = epoll_ctl(mgr->epoll_fd, EPOLL_CTL_ADD, extendProbe->fifo->triggerFd, &event);
        if (ret < 0) {
            ERROR("[INGRESS] add EPOLLIN event failed, extend probe %s.\n", extendProbe->name);
            return -1;
        }

        INFO("[INGRESS] Add EPOLLIN event success, extend probe %s.\n", extendProbe->name);
    }

    return 0;
}

static int IngressData2Egress(IngressMgr *mgr, IMDB_Table *table, IMDB_Record* rec, const char *dataStr)
{
    int ret = 0;

    // format data to json
    char *jsonStr = malloc(MAX_DATA_STR_LEN);
    if (jsonStr == NULL) {
        ERROR("[INGRESS] alloc jsonStr failed.\n");
        return -1;
    }
    ret = IMDB_Rec2Json(mgr->imdbMgr, table, rec, dataStr, jsonStr, MAX_DATA_STR_LEN);
    if (ret != 0) {
        ERROR("[INGRESS] reformat dataStr to json failed.\n");
        goto err;
    }

    uint64_t msg = 1;
    if (strcmp(table->entity_name, "event") == 0) {
        ret = FifoPut(mgr->egressMgr->event_fifo, (void *)jsonStr);
        if (ret != 0) {
            ERROR("[INGRESS] egress event fifo full.\n");
            goto err;
        }
        ret = write(mgr->egressMgr->event_fifo->triggerFd, &msg, sizeof(uint64_t));
        if (ret != sizeof(uint64_t)) {
            ERROR("[INGRESS] send trigger msg to egress event_fifo fd failed.\n");
            return -1;
        }
    } else {
        ret = FifoPut(mgr->egressMgr->metric_fifo, (void *)jsonStr);
        if (ret != 0) {
            ERROR("[INGRESS] egress metric fifo full.\n");
            goto err;
        }
        ret = write(mgr->egressMgr->metric_fifo->triggerFd, &msg, sizeof(uint64_t));
        if (ret != sizeof(uint64_t)) {
            ERROR("[INGRESS] send trigger msg to egress metric_fifo fd failed.\n");
            return -1;
        }
    }
    return 0;

err:
    (void)free(jsonStr);
    return -1;
}

static int IngressEventWrite2Logs(IMDB_DataBaseMgr *mgr, IMDB_Table *table, IMDB_Record* rec, const char *dataStr)
{
    int ret = 0;
    int str_len = 0;

    // format data to json
    char *jsonStr = malloc(MAX_DATA_STR_LEN);
    if (jsonStr == NULL) {
        ERROR("[EVENTLOG] alloc jsonStr failed.\n");
        return -1;
    }
    ret = IMDB_Rec2Json(mgr, table, rec, dataStr, jsonStr, MAX_DATA_STR_LEN);
    if (ret != 0) {
        ERROR("[EVENTLOG] reformat dataStr to json failed.\n");
        goto err;
    }

    str_len = strlen(jsonStr);
    ret = wr_event_logs(jsonStr, str_len);
    if (ret < 0) {
        ERROR("[EVENTLOG] write event logs fail.\n");
        goto err;
    }

err:
    (void)free(jsonStr);
    return ret;
}

static int GetTableNameAndContent(const char* buf, char *tblName, size_t size, char **content)
{
    size_t len;
    const char *p1, *p2;

    *content = NULL;
    if ((buf == NULL) || (buf[0] != '|'))
        return -1;

    p1 = buf + 1;
    p2 = (const char *)strchr(p1, '|');
    if (p2 == NULL)
        return -1;

    if (p2 <= p1)
        return -1;

    len = (size_t)(p2 - p1);
    if (len >= size)
        return -1;

    (void)memcpy(tblName, p1, len);
    tblName[len] = 0;
    *content = (char *)p2;
    return 0;
}

static int isRecordCanSend2Egress(IngressMgr *mgr, IMDB_Table *table)
{
    if (mgr->egressMgr == NULL) {
        return 0;
    }
    if (strcmp(table->name, "event") == 0 && mgr->egressMgr->event_kafkaMgr == NULL) {
        return 0;
    }
    if (strcmp(table->name, "event") != 0 && mgr->egressMgr->metric_kafkaMgr == NULL) {
        return 0;
    }
    return 1;
}

static int isEventWriteLogs(IngressMgr *mgr, IMDB_Table *table)
{
    if (strcmp(table->name, "event") == 0 && mgr->event_out_channel == OUT_CHNL_LOGS) {
        return 1;
    }
    return 0;
}

static int IngressDataProcesssInput(Fifo *fifo, IngressMgr *mgr)
{
    // read data from fifo
    char *dataStr, *content;
    int ret = 0;
    char tblName[MAX_IMDB_TABLE_NAME_LEN];
    IMDB_Table* table;
    IMDB_Record* rec;

    uint64_t val = 0;
    ret = read(fifo->triggerFd, &val, sizeof(val));
    if (ret < 0) {
        ERROR("[INGRESS] Read event from triggerfd failed.\n");
        return -1;
    }

    while (FifoGet(fifo, (void **)&dataStr) == 0) {
        if (dataStr == NULL)
            continue;

        // skip string not start with '|'
        ret = GetTableNameAndContent((const char*)dataStr, tblName, MAX_IMDB_TABLE_NAME_LEN, &content);
        if (ret < 0 || (content == NULL)) {
            ERROR("[INGRESS] Get dirty data str: %s\n", dataStr);
            goto next;
        }

        table = IMDB_DataBaseMgrFindTable(mgr->imdbMgr, tblName);
        if (table == NULL)
            goto next;

        rec = NULL;

        if (table->recordKeySize > 0 && mgr->imdbMgr->writeLogsOn) {
            // save data to imdb
            rec = IMDB_DataBaseMgrCreateRec(mgr->imdbMgr, table, content);
            if (rec == NULL) {
                ERROR("[INGRESS] insert data into imdb failed.\n");
                goto next;
            }
        }

        if (isEventWriteLogs(mgr, table) == 1) {
            // write event data to logs
            ret = IngressEventWrite2Logs(mgr->imdbMgr, table, rec, content);
            if (ret != 0) {
                ERROR("[INGRESS] write event to logs failed.\n");
            } else {
                DEBUG("[INGRESS] write event to logs succeed.(tbl=%s,content=%s)\n", table->name, content);
            }
        }

        if (isRecordCanSend2Egress(mgr, table) == 1) {
            // send data to egress
            ret = IngressData2Egress(mgr, table, rec, content);
            if (ret != 0) {
                ERROR("[INGRESS] send data to egress failed.\n");
            } else {
                DEBUG("[INGRESS] send data to egress succeed.(tbl=%s,content=%s)\n", table->name, content);
            }
        }
next:
        free(dataStr);
    }

    return 0;
}

static int IngressDataProcesss(IngressMgr *mgr)
{
    struct epoll_event events[MAX_EPOLL_EVENTS_NUM];
    int events_num;
    Fifo *fifo = NULL;
    uint32_t ret = 0;

    events_num = epoll_wait(mgr->epoll_fd, events, MAX_EPOLL_EVENTS_NUM, -1);
    if ((events_num < 0) && (errno != EINTR)) {
        ERROR("Ingress Msg wait failed: %s.\n", strerror(errno));
        return events_num;
    }

    for (int i = 0; ((i < events_num) && (i < MAX_EPOLL_EVENTS_NUM)); i++) {
        if (events[i].events != EPOLLIN)
            continue;

        fifo = (Fifo *)events[i].data.ptr;
        if (fifo == NULL)
            continue;

        ret = IngressDataProcesssInput(fifo, mgr);
        if (ret != 0) {
            return -1;
        }
    }
    return 0;
}

void IngressMain(IngressMgr *mgr)
{
    int ret = 0;
    ret = IngressInit(mgr);
    if (ret != 0) {
        ERROR("[INGRESS] ingress init failed.\n");
        return;
    }
    DEBUG("[INGRESS] ingress init success.\n");

    for (;;) {
        ret = IngressDataProcesss(mgr);
        if (ret != 0) {
            ERROR("[INGRESS] ingress data process failed.\n");
            return;
        }
    }
}

#if 0
int IngressRemovePorbe(IngressMgr *mgr, ExtendProbe *probe)
{
    int ret;

    if (probe->fifo == NULL)
        return 0;

    ret = epoll_ctl(mgr->epoll_fd, EPOLL_CTL_DEL, probe->fifo->triggerFd, NULL);
    if (ret != 0) {
        ERROR("[INGRESS] remove probe(%s) trigger fd failed(fd=%d, ret=%d).\n", probe->name,
                        probe->fifo->triggerFd, ret);
        return -1;
    }
    ret = close(probe->fifo->triggerFd);
    if (ret != 0) {
        ERROR("[INGRESS] close probe(%s) trigger fd failed(fd=%d, ret=%d).\n", probe->name,
                        probe->fifo->triggerFd, ret);
        return -1;
    }
    probe->fifo->triggerFd = 0;
    return 0;
}

int IngressAddPorbe(IngressMgr *mgr, ExtendProbe *probe)
{
    int ret;
    struct epoll_event event;

    if (probe->fifo == NULL)
        return 0;

    probe->fifo->triggerFd = eventfd(0, 0);

    event.events = EPOLLIN;
    event.data.ptr = probe->fifo;
    ret = epoll_ctl(mgr->epoll_fd, EPOLL_CTL_ADD, probe->fifo->triggerFd, &event);
    if (ret != 0) {
        ERROR("[INGRESS] add probe(%s) trigger fd failed(fd=%d, ret=%d).\n", probe->name,
                            probe->fifo->triggerFd, ret);
        return -1;
    }

    return 0;
}
#endif
