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
#include <time.h>
#include <sys/stat.h>
#include "base.h"
#include "config.h"
#include "args.h"
#include "resource.h"

#if GALA_GOPHER_INFO("inner func")
static int ConfigMgrInit(ResourceMgr *resourceMgr);
static void ConfigMgrDeinit(ResourceMgr *resourceMgr);
static int ProbeMngInit(ResourceMgr *resourceMgr);
static void ProbeMngDeinit(ResourceMgr *resourceMgr);
static int MeasurementMgrInit(ResourceMgr *resourceMgr);
static void MeasurementMgrDeinit(ResourceMgr *resourceMgr);
static int FifoMgrInit(ResourceMgr *resourceMgr);
static void FifoMgrDeinit(ResourceMgr *resourceMgr);
static int KafkaMgrInit(ResourceMgr *resourceMgr);
static void KafkaMgrDeinit(ResourceMgr *resourceMgr);
static int IMDBMgrInit(ResourceMgr *resourceMgr);
static void IMDBMgrDeinit(ResourceMgr *resourceMgr);
static int IngressMgrInit(ResourceMgr *resourceMgr);
static void IngressMgrDeinit(ResourceMgr *resourceMgr);
static int EgressMgrInit(ResourceMgr *resourceMgr);
static void EgressMgrDeinit(ResourceMgr *resourceMgr);
static int WebServerInit(ResourceMgr *resourceMgr);
static void WebServerDeinit(ResourceMgr *resourceMgr);
static int RestServerInit(ResourceMgr *resourceMgr);
static void RestServerDeinit(ResourceMgr *resourceMgr);
static int LogsMgrInit(ResourceMgr *resourceMgr);
static void LogsMgrDeinit(ResourceMgr *resourceMgr);
static int EventMgrInit(ResourceMgr *resourceMgr);
static void EventMgrDeinit(ResourceMgr *resourceMgr);
#endif

typedef struct tagSubModuleInitor {
    int (*subModuleInitFunc)(ResourceMgr *);
    void (*subModuleDeinitFunc)(ResourceMgr *);
} SubModuleInitor;

extern char* g_galaConfPath;

SubModuleInitor gSubModuleInitorTbl[] = {
    { ConfigMgrInit,        ConfigMgrDeinit },      // config must be the first
    { ProbeMngInit,         ProbeMngDeinit },
    { MeasurementMgrInit,   MeasurementMgrDeinit },
    { FifoMgrInit,          FifoMgrDeinit },
#ifdef KAFKA_CHANNEL
    { KafkaMgrInit,         KafkaMgrDeinit },       // kafka must precede egress
#endif
    { IMDBMgrInit,          IMDBMgrDeinit },        // IMDB must precede ingress
    { EgressMgrInit,        EgressMgrDeinit },      // egress must precede ingress
    { IngressMgrInit,       IngressMgrDeinit },
    { WebServerInit,        WebServerDeinit },
    { RestServerInit,       RestServerDeinit },
    { LogsMgrInit,          LogsMgrDeinit },
    { EventMgrInit,         EventMgrDeinit }
};

ResourceMgr *ResourceMgrCreate(void)
{
    ResourceMgr *mgr = NULL;
    mgr = (ResourceMgr *)malloc(sizeof(ResourceMgr));
    if (mgr == NULL)
        return NULL;
    memset(mgr, 0, sizeof(ResourceMgr));
    return mgr;
}

void ResourceMgrDestroy(ResourceMgr *resourceMgr)
{
    if (resourceMgr != NULL)
        free(resourceMgr);

    if (g_galaConfPath != NULL) {
        free(g_galaConfPath);
        g_galaConfPath = NULL;
    }
    return;
}

int ResourceMgrInit(ResourceMgr *resourceMgr)
{
    if (resourceMgr == NULL)
        return -1;

    int ret = 0;
    size_t initTblSize = sizeof(gSubModuleInitorTbl) / sizeof(gSubModuleInitorTbl[0]);
    for (int i = 0; i < initTblSize; i++) {
        ret = gSubModuleInitorTbl[i].subModuleInitFunc(resourceMgr);
        if (ret != 0)
            return -1;
    }

    return 0;
}

static void ResourceMgrDeleteTimer(ResourceMgr *mgr)
{
    struct itimerspec its;

    if (mgr->keeplive_timer == 0)
        return;

    (void)memset(&its, 0, sizeof(its));

    (void)timer_settime(mgr->keeplive_timer, 0, &its, NULL);

    (void)timer_delete(mgr->keeplive_timer);
    mgr->keeplive_timer = 0;
}

void ResourceMgrDeinit(ResourceMgr *resourceMgr)
{
    if (resourceMgr == NULL)
        return;

    ResourceMgrDeleteTimer(resourceMgr);

    size_t initTblSize = sizeof(gSubModuleInitorTbl) / sizeof(gSubModuleInitorTbl[0]);
    for (int i = 0; i < initTblSize; i++)
        gSubModuleInitorTbl[i].subModuleDeinitFunc(resourceMgr);

    return;
}

#if GALA_GOPHER_INFO("inner func")
static int ConfigMgrInit(ResourceMgr *resourceMgr)
{
    int ret = 0;
    ConfigMgr *configMgr = NULL;

    configMgr = ConfigMgrCreate();
    if (configMgr == NULL) {
        ERROR("[RESOURCE] create config mgr failed.\n");
        return -1;
    }

    ret = ConfigMgrLoad(configMgr, g_galaConfPath);
    if (ret != 0) {
        ConfigMgrDestroy(configMgr);
        ERROR("[RESOURCE] load gala configuration failed.\n");
        return -1;
    }

    resourceMgr->configMgr = configMgr;
    return 0;
}

static void ConfigMgrDeinit(ResourceMgr *resourceMgr)
{
    ConfigMgrDestroy(resourceMgr->configMgr);
    resourceMgr->configMgr = NULL;
    return;
}

static int ProbeMngInit(ResourceMgr *resourceMgr)
{
    int ret = 0;

    struct probe_mng_s *probe_mng = NULL;

    probe_mng = create_probe_mng();
    if (probe_mng == NULL)
        return -1;

    resourceMgr->probe_mng = probe_mng;
    return 0;
}

static void ProbeMngDeinit(ResourceMgr *resourceMgr)
{
    destroy_probe_mng();
    resourceMgr->probe_mng = NULL;
}

static int MeasurementMgrInit(ResourceMgr *resourceMgr)
{
    int ret = 0;
    MeasurementMgr *mmMgr = NULL;

    mmMgr = MeasurementMgrCreate(resourceMgr->configMgr->imdbConfig->maxTablesNum,
                                    resourceMgr->configMgr->imdbConfig->maxMetricsNum);
    if (mmMgr == NULL) {
        ERROR("[RESOURCE] create mmMgr failed.\n");
        return -1;
    }

    // load table meta info
    ret = MeasurementMgrLoad(mmMgr, GALA_META_DIR_PATH);
    if (ret != 0) {
        MeasurementMgrDestroy(mmMgr);
        ERROR("[RESOURCE] load meta dir failed.\n");
        return -1;
    }
    INFO("[RESOURCE] load meta directory success.\n");

    mmMgr->meta_out_channel = resourceMgr->configMgr->metaOutConfig->outChnl;

    resourceMgr->mmMgr = mmMgr;
    return 0;
}

static void MeasurementMgrDeinit(ResourceMgr *resourceMgr)
{
    MeasurementMgrDestroy(resourceMgr->mmMgr);
    resourceMgr->mmMgr = NULL;
    return;
}

static int FifoMgrInit(ResourceMgr *resourceMgr)
{
    FifoMgr *fifoMgr = NULL;

    fifoMgr = FifoMgrCreate(MAX_FIFO_NUM);
    if (fifoMgr == NULL) {
        ERROR("[RESOURCE] create fifoMgr failed.\n");
        return -1;
    }

    resourceMgr->fifoMgr = fifoMgr;
    return 0;
}

static void FifoMgrDeinit(ResourceMgr *resourceMgr)
{
    FifoMgrDestroy(resourceMgr->fifoMgr);
    resourceMgr->fifoMgr = NULL;
    return;
}

#ifdef KAFKA_CHANNEL
static int KafkaMgrInit(ResourceMgr *resourceMgr)
{
    ConfigMgr *configMgr = NULL;
    KafkaMgr *kafkaMgr = NULL;

    configMgr = resourceMgr->configMgr;

    /* init metric_kafka */
    if (configMgr->metricOutConfig->outChnl == OUT_CHNL_KAFKA) {
        kafkaMgr = KafkaMgrCreate(configMgr, "kafka_topic");
        if (kafkaMgr == NULL) {
            ERROR("[RESOURCE] create kafkaMgr of metric failed.\n");
            return -1;
        }
        resourceMgr->metric_kafkaMgr = kafkaMgr;
        INFO("[RESOURCE] create kafkaMgr of metric success.\n");
    } else {
        INFO("[RESOURCE] metric out_channel isn't kafka, skip create kafkaMgr.\n");
    }
    /* init meta_kafka */
    kafkaMgr = NULL;
    if (configMgr->metaOutConfig->outChnl == OUT_CHNL_KAFKA) {
        kafkaMgr = KafkaMgrCreate(configMgr, "metadata_topic");
        if (kafkaMgr == NULL) {
            ERROR("[RESOURCE] create kafkaMgr of meta failed.\n");
            return -1;
        }
        resourceMgr->meta_kafkaMgr = kafkaMgr;
        if (resourceMgr->mmMgr) {
            resourceMgr->mmMgr->meta_kafkaMgr = resourceMgr->meta_kafkaMgr;
        }
        INFO("[RESOURCE] create kafkaMgr of meta success.\n");
    } else {
        INFO("[RESOURCE] meta out_channel isn't kafka, skip create kafkaMgr.\n");
    }
    /* init event_kafka */
    kafkaMgr = NULL;
    if (configMgr->eventOutConfig->outChnl == OUT_CHNL_KAFKA) {
        kafkaMgr = KafkaMgrCreate(configMgr, "event_topic");
        if (kafkaMgr == NULL) {
            ERROR("[RESOURCE] create kafkaMgr of event failed.\n");
            return -1;
        }
        resourceMgr->event_kafkaMgr = kafkaMgr;
        INFO("[RESOURCE] create kafkaMgr of event success.\n");
    } else {
        INFO("[RESOURCE] event out_channel isn't kafka, skip create kafkaMgr.\n");
    }

    return 0;
}

static void KafkaMgrDeinit(ResourceMgr *resourceMgr)
{
    KafkaMgrDestroy(resourceMgr->metric_kafkaMgr);
    resourceMgr->metric_kafkaMgr = NULL;

    KafkaMgrDestroy(resourceMgr->meta_kafkaMgr);
    resourceMgr->meta_kafkaMgr = NULL;

    KafkaMgrDestroy(resourceMgr->event_kafkaMgr);
    resourceMgr->event_kafkaMgr = NULL;

    return;
}
#endif

static int IMDBMgrTableLoad(IMDB_Table *table, Measurement *mm)
{
    int ret = 0;
    IMDB_Record *meta = IMDB_RecordCreate(mm->fieldsNum);
    if (meta == NULL) {
        return -1;
    }

    IMDB_Metric *metric = NULL;
    uint32_t keyNum = 0;
    for (int i = 0; i < mm->fieldsNum; i++) {
        metric = IMDB_MetricCreate(mm->fields[i].name, mm->fields[i].description, mm->fields[i].type);
        if (metric == NULL) {
            goto ERR;
        }

        ret = IMDB_RecordAddMetric(meta, metric);
        if (ret != 0) {
            goto ERR;
        }

        metric = NULL;
        if (strcmp(mm->fields[i].type, METRIC_TYPE_KEY) == 0) {
            keyNum++;
        }
    }

    ret = IMDB_TableSetMeta(table, meta);
    if (ret != 0) {
        goto ERR;
    }

    ret = IMDB_TableSetRecordKeySize(table, keyNum);
    if (ret != 0) {
        goto ERR;
    }

    IMDB_TableSetEntityName(table, mm->entity);

    return 0;
ERR:
    IMDB_RecordDestroy(meta);
    IMDB_MetricDestroy(metric);
    return -1;
}

static int IMDBMgrDatabaseLoad(IMDB_DataBaseMgr *imdbMgr, MeasurementMgr *mmMgr, uint32_t recordsCapability)
{
    int ret = 0;

    IMDB_Table *table;
    for (int i = 0; i < mmMgr->measurementsNum; i++) {
        table = IMDB_TableCreate(mmMgr->measurements[i]->name, recordsCapability);
        if (table == NULL)
            return -1;

        ret = IMDBMgrTableLoad(table, mmMgr->measurements[i]);
        if (ret != 0)
            return -1;

        ret = IMDB_DataBaseMgrAddTable(imdbMgr, table);
        if (ret != 0)
            return -1;
    }

    return 0;
}

static int IMDBMgrInit(ResourceMgr *resourceMgr)
{
    int ret = 0;
    ConfigMgr *configMgr = resourceMgr->configMgr;
    IMDB_DataBaseMgr *imdbMgr = NULL;
    imdbMgr = IMDB_DataBaseMgrCreate(configMgr->imdbConfig->maxTablesNum);
    if (imdbMgr == NULL) {
        ERROR("[RESOURCE] create IMDB database mgr failed.\n");
        return -1;
    }

    IMDB_DataBaseMgrSetRecordTimeout(configMgr->imdbConfig->recordTimeout);

    ret = IMDBMgrDatabaseLoad(imdbMgr, resourceMgr->mmMgr, configMgr->imdbConfig->maxRecordsNum);
    if (ret != 0) {
        IMDB_DataBaseMgrDestroy(imdbMgr);
        return -1;
    }

    resourceMgr->imdbMgr = imdbMgr;
    return 0;
}

static void IMDBMgrDeinit(ResourceMgr *resourceMgr)
{
    IMDB_DataBaseMgrDestroy(resourceMgr->imdbMgr);
    resourceMgr->imdbMgr = NULL;
    return;
}

static int IngressMgrInit(ResourceMgr *resourceMgr)
{
    IngressMgr *ingressMgr = NULL;

    ingressMgr = IngressMgrCreate();
    if (ingressMgr == NULL) {
        ERROR("[RESOURCE] create ingressMgr failed.\n");
        return -1;
    }

    ingressMgr->fifoMgr = resourceMgr->fifoMgr;
    ingressMgr->mmMgr = resourceMgr->mmMgr;
    ingressMgr->probsMgr = resourceMgr->probe_mng;
    ingressMgr->imdbMgr = resourceMgr->imdbMgr;

    ingressMgr->egressMgr = resourceMgr->egressMgr;
    ingressMgr->event_out_channel = resourceMgr->configMgr->eventOutConfig->outChnl;

    resourceMgr->ingressMgr = ingressMgr;
    return 0;
}

static void IngressMgrDeinit(ResourceMgr *resourceMgr)
{
    IngressMgrDestroy(resourceMgr->ingressMgr);
    resourceMgr->ingressMgr = NULL;
    return;
}

static int EgressMgrInit(ResourceMgr *resourceMgr)
{
    EgressMgr *egressMgr = NULL;

    egressMgr = EgressMgrCreate();
    if (egressMgr == NULL) {
        ERROR("[RESOURCE] create egressMgr failed.\n");
        return -1;
    }

#ifdef KAFKA_CHANNEL
    egressMgr->metric_kafkaMgr = resourceMgr->metric_kafkaMgr;
    egressMgr->event_kafkaMgr = resourceMgr->event_kafkaMgr;
#endif
    egressMgr->interval = resourceMgr->configMgr->egressConfig->interval;
    egressMgr->timeRange = resourceMgr->configMgr->egressConfig->timeRange;

    resourceMgr->egressMgr = egressMgr;
    return 0;
}

static void EgressMgrDeinit(ResourceMgr *resourceMgr)
{
    EgressMgrDestroy(resourceMgr->egressMgr);
    resourceMgr->egressMgr = NULL;
    return;
}

static int WebServerInit(ResourceMgr *resourceMgr)
{
    int ret;
    ConfigMgr *configMgr = resourceMgr->configMgr;
    http_server_mgr_s *web_server_mgr;

    if (configMgr->metricOutConfig->outChnl != OUT_CHNL_WEB_SERVER) {
        INFO("[RESOURCE] metirc out channel isn't web_server, skip create webServer.\n");
        return 0;
    }

    web_server_mgr = (http_server_mgr_s *)calloc(1, sizeof(http_server_mgr_s));
    if (web_server_mgr == NULL) {
        ERROR("[RESOURCE] create web server mgr failed.\n");
        return -1;
    }

    resourceMgr->web_server_mgr = web_server_mgr;
    ret = init_web_server_mgr(web_server_mgr, configMgr->webServerConfig);
    if (ret) {
        return -1;
    }

    if (resourceMgr->imdbMgr) {
        resourceMgr->imdbMgr->writeLogsType = METRIC_LOG_PROM;
    }

    return 0;
}

static void WebServerDeinit(ResourceMgr *resourceMgr)
{
    destroy_http_server_mgr(resourceMgr->web_server_mgr);
    resourceMgr->web_server_mgr = NULL;
    return;
}

static int RestServerInit(ResourceMgr *resourceMgr)
{
    int ret;
    ConfigMgr *configMgr = resourceMgr->configMgr;
    http_server_mgr_s *rest_server_mgr;

    if (configMgr->globalConfig->restApiOn == 0) {
        INFO("[RESOURCE] config rest_api_on is false, skip create rest server.\n");
        return 0;
    }

    rest_server_mgr = (http_server_mgr_s *)calloc(1, sizeof(http_server_mgr_s));
    if (rest_server_mgr == NULL) {
        ERROR("[RESOURCE] create rest server mgr failed\n");
        return -1;
    }

    resourceMgr->rest_server_mgr = rest_server_mgr;
    ret = init_rest_server_mgr(rest_server_mgr, configMgr->restServerConfig);
    if (ret) {
        return -1;
    }

    return 0;
}

static void RestServerDeinit(ResourceMgr *resourceMgr)
{
    destroy_http_server_mgr(resourceMgr->rest_server_mgr);
    resourceMgr->rest_server_mgr = NULL;
    return;
}

static int LogsMgrInit(ResourceMgr *resourceMgr)
{
    ConfigMgr *configMgr = resourceMgr->configMgr;
    LogsMgr *logsMgr = NULL;
    int is_metric_out_log, is_meta_out_log, is_event_out_log;
    OutChannelType metric_out_chnl = configMgr->metricOutConfig->outChnl;

    is_metric_out_log = (metric_out_chnl == OUT_CHNL_WEB_SERVER ||
                         metric_out_chnl == OUT_CHNL_LOGS ||
                         metric_out_chnl == OUT_CHNL_JSON) ? 1 : 0;
    is_event_out_log = (configMgr->eventOutConfig->outChnl == OUT_CHNL_LOGS) ? 1 : 0;
    is_meta_out_log = (configMgr->metaOutConfig->outChnl == OUT_CHNL_LOGS) ? 1 : 0;

    logsMgr = create_log_mgr(configMgr->globalConfig->logFileName, is_metric_out_log, is_event_out_log);
    if (logsMgr == NULL) {
        ERROR("[RESOURCE] create logsMgr failed.\n");
        return -1;
    }

    mode_t old_mask = umask(S_IWGRP | S_IROTH | S_IWOTH | S_IXOTH);

    // metricTotalSize divided by 2 because there is a backup file
    logsMgr->metrics_logs_filesize = configMgr->logsConfig->metricTotalSize * 1024 * 1024;
    (void)snprintf(logsMgr->debug_path, sizeof(logsMgr->debug_path), "%s", configMgr->logsConfig->debugDir);
    (void)snprintf(logsMgr->metrics_path, sizeof(logsMgr->metrics_path), "%s", configMgr->logsConfig->metricDir);
    (void)snprintf(logsMgr->event_path, sizeof(logsMgr->event_path), "%s", configMgr->logsConfig->eventDir);
    (void)snprintf(logsMgr->meta_path, sizeof(logsMgr->meta_path), "%s", configMgr->logsConfig->metaDir);

    if (init_log_mgr(logsMgr, is_meta_out_log, configMgr->globalConfig->logLevel) < 0) {
        return -1;
    }
    resourceMgr->logsMgr = logsMgr;
    if (is_metric_out_log == 1) {
        if (resourceMgr->imdbMgr) {
            if (metric_out_chnl == OUT_CHNL_WEB_SERVER || metric_out_chnl == OUT_CHNL_LOGS) {
                resourceMgr->imdbMgr->writeLogsType = METRIC_LOG_PROM;
            }

            if (metric_out_chnl == OUT_CHNL_JSON) {
                resourceMgr->imdbMgr->writeLogsType = METRIC_LOG_JSON;
            }
        }
    }
    umask(old_mask);
    return 0;
}

static void LogsMgrDeinit(ResourceMgr *resourceMgr)
{
    destroy_log_mgr(resourceMgr->logsMgr);
    resourceMgr->logsMgr = NULL;
}

static int EventMgrInit(ResourceMgr *resourceMgr)
{
    ConfigMgr *configMgr = resourceMgr->configMgr;
    init_event_mgr(configMgr->eventOutConfig->timeout);
    return 0;
}

static void EventMgrDeinit(ResourceMgr *resourceMgr)
{
    return;
}

#endif
