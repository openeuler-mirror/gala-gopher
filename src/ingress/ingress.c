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
#include "event2json.h"
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

    if (mgr->epoll_fd > 0) {
        close(mgr->epoll_fd);
    }
    free(mgr);
    return;
}

static int IngressInit(IngressMgr *mgr)
{
    mgr->epoll_fd = epoll_create(MAX_EPOLL_SIZE);
    if (mgr->epoll_fd < 0) {
        return -1;
    }

    mgr->probsMgr->ingress_epoll_fd = mgr->epoll_fd;
    return 0;
}

static int LogData2Egress(IngressMgr *mgr, const char *logData)
{
    int ret = 0;
    char *jsonFmt = NULL;
    uint64_t msg = 1;

    jsonFmt = malloc(MAX_DATA_STR_LEN);
    if (jsonFmt == NULL) {
        ERROR("[INGRESS] alloc jsonFmt failed.\n");
        return -1;
    }

    if (LogData2Json(mgr, logData, jsonFmt, MAX_DATA_STR_LEN)) {
        ERROR("[INGRESS] transfer log data to json format failed.\n");
        free(jsonFmt);
        return -1;
    }

    ret = FifoPut(mgr->egressMgr->event_fifo, (void *)jsonFmt);
    if (ret != 0) {
        ERROR("[INGRESS] egress event fifo full.\n");
        free(jsonFmt);
        return -1;
    }
    ret = write(mgr->egressMgr->event_fifo->triggerFd, &msg, sizeof(uint64_t));
    if (ret != sizeof(uint64_t)) {
        ERROR("[INGRESS] send trigger msg to egress event_fifo fd failed.\n");
        free(jsonFmt);
        return -1;
    }

    return 0;
}

static int EventData2Egress(IngressMgr *mgr, const char *content)
{
    int ret = 0;

    // format data to json
    char *jsonStr = malloc(MAX_DATA_STR_LEN);
    if (jsonStr == NULL) {
        ERROR("[INGRESS] alloc jsonStr failed.\n");
        return -1;
    }

    ret = EventData2Json(mgr, content, jsonStr, MAX_DATA_STR_LEN);
    if (ret) {
        ERROR("[INGRESS] transfer event data to json failed.\n");
        goto err;
    }

    uint64_t msg = 1;
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
    return 0;

err:
    (void)free(jsonStr);
    return -1;
}

static int MetricData2Egress(IngressMgr *mgr, IMDB_Table *table, IMDB_Record* rec)
{
    int ret = 0;

    // format data to json
    char *jsonStr = malloc(MAX_DATA_STR_LEN);
    if (jsonStr == NULL) {
        ERROR("[INGRESS] alloc jsonStr failed.\n");
        return -1;
    }
    ret = IMDB_Record2Json(mgr->imdbMgr, table, rec, jsonStr, MAX_DATA_STR_LEN);
    if (ret != 0) {
        ERROR("[INGRESS] reformat imdb record to json failed.\n");
        goto err;
    }

    uint64_t msg = 1;
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
    return 0;

err:
    (void)free(jsonStr);
    return -1;
}

static int IngressEventWrite2Logs(IngressMgr *mgr, const char *content)
{
    int ret = 0;

    // format data to json
    char *jsonStr = malloc(MAX_DATA_STR_LEN);
    if (jsonStr == NULL) {
        ERROR("[EVENTLOG] alloc jsonStr failed.\n");
        return -1;
    }

    ret = EventData2Json(mgr, content, jsonStr, MAX_DATA_STR_LEN);
    if (ret) {
        ERROR("[EVENTLOG] reformat dataStr to json failed.\n");
        goto err;
    }

    ret = wr_event_logs(jsonStr, strlen(jsonStr));
    if (ret < 0) {
        ERROR("[EVENTLOG] write event logs failed.\n");
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

// process log (one telemetry category in otel) message
static int ProcessOtelLogData(IngressMgr *mgr, const char *content)
{
#ifdef KAFKA_CHANNEL
    int ret = 0;
    if (mgr->egressMgr && mgr->egressMgr->event_kafkaMgr) {
        // send log data to egress
        ret = LogData2Egress(mgr, content);
        if (ret) {
            ERROR("[INGRESS] send log data to egress failed.\n");
            return -1;
        } else {
            DEBUG("[INGRESS] send log data to egress succeed.(content=%s)\n", content);
        }
    }
#endif
    return 0;
}

static int ProcessEventData(IngressMgr *mgr, const char *content)
{
    int ret = 0;

    if (mgr->event_out_channel == OUT_CHNL_LOGS) {
        // write event data to logs
        ret = IngressEventWrite2Logs(mgr, content);
        if (ret != 0) {
            ERROR("[INGRESS] write event to logs failed.\n");
            return -1;
        } else {
            DEBUG("[INGRESS] write event to logs succeed.(content=%s)\n", content);
        }
    }

#ifdef KAFKA_CHANNEL
    if (mgr->egressMgr && mgr->egressMgr->event_kafkaMgr) {
        // send data to egress
        ret = EventData2Egress(mgr, content);
        if (ret != 0) {
            ERROR("[INGRESS] send event data to egress failed.\n");
            return -1;
        }
    }
#endif
    return 0;
}

static int ProcessMetricData(IngressMgr *mgr, const char *content, const char *tblName, struct probe_s *probe)
{
    IMDB_Table* table;
    IMDB_Record* rec = NULL;
    int ret = 0;

    table = IMDB_DataBaseMgrFindTable(mgr->imdbMgr, tblName);
    if (table == NULL) {
        ERROR("[INGRESS] failed to find tablename \"%s\" of metrics reported by probe %s\n",
              tblName, probe ? probe->name : "unknown");
        return -1;
    }

    if (probe) {
        IMDB_TableUpdateExtLabelConf(table, &probe->ext_label_conf);
    }

    if (mgr->imdbMgr->writeLogsType == METRIC_LOG_PROM || mgr->imdbMgr->writeLogsType == METRIC_LOG_JSON) {
        // save metric to imdb
        rec = IMDB_DataBaseMgrCreateRec(mgr->imdbMgr, table, content);
        if (rec == NULL) {
            return -1;
        }
    }

#ifdef KAFKA_CHANNEL
    if (mgr->egressMgr && mgr->egressMgr->metric_kafkaMgr) {
        // send metric to egress
        ret = MetricData2Egress(mgr, table, rec);
        if (ret) {
            ERROR("[INGRESS] send metric data to egress failed.\n");
            return -1;
        } else {
            DEBUG("[INGRESS] send metric data to egress succeed.(tbl=%s,content=%s)\n", table->name, content);
        }
    }
#endif
    return 0;
}

static int IngressDataProcesssInput(Fifo *fifo, IngressMgr *mgr)
{
    // read data from fifo
    char *dataStr, *content;
    int ret = 0;
    char tblName[MAX_IMDB_TABLE_NAME_LEN];

    uint64_t val = 0;
    ret = read(fifo->triggerFd, &val, sizeof(val));
    if (ret < 0) {
        ERROR("[INGRESS] Read event from triggerfd failed.\n");
        return -1;
    }

    while (FifoGet(fifo, (void **)&dataStr) == 0) {
        if (dataStr == NULL)
            continue;

        ret = GetTableNameAndContent((const char*)dataStr, tblName, MAX_IMDB_TABLE_NAME_LEN, &content);
        if (ret < 0 || (content == NULL)) {
            ERROR("[INGRESS] Get dirty data str: %s\n", dataStr);
            free(dataStr);
            continue;
        }

        if (strcmp(tblName, "log") == 0) {
            (void)ProcessOtelLogData(mgr, content);
        } else if (strcmp(tblName, "event") == 0) {
            (void)ProcessEventData(mgr, content);
        } else {
            (void)ProcessMetricData(mgr, content, tblName, (struct probe_s *)fifo->probe);
        }

        free(dataStr);
    }

    return 0;
}

static int IngressDataProcesss(IngressMgr *mgr)
{
    struct epoll_event events[MAX_EPOLL_EVENTS_NUM];
    int events_num;
    Fifo *fifo = NULL;
    int ret = 0;

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
