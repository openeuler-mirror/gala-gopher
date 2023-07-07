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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libconfig.h>

#include "config.h"

ConfigMgr *ConfigMgrCreate(void)
{
    ConfigMgr *mgr = NULL;
    mgr = (ConfigMgr *)malloc(sizeof(ConfigMgr));
    if (mgr == NULL) {
        return NULL;
    }
    memset(mgr, 0, sizeof(ConfigMgr));

    mgr->globalConfig = (GlobalConfig *)malloc(sizeof(GlobalConfig));
    if (mgr->globalConfig == NULL) {
        goto ERR;
    }
    memset(mgr->globalConfig, 0, sizeof(GlobalConfig));

    mgr->ingressConfig = (IngressConfig *)malloc(sizeof(IngressConfig));
    if (mgr->ingressConfig == NULL) {
        goto ERR;
    }
    memset(mgr->ingressConfig, 0, sizeof(IngressConfig));

    mgr->egressConfig = (EgressConfig *)malloc(sizeof(EgressConfig));
    if (mgr->egressConfig == NULL) {
        goto ERR;
    }
    memset(mgr->egressConfig, 0, sizeof(EgressConfig));

    mgr->kafkaConfig = (KafkaConfig *)malloc(sizeof(KafkaConfig));
    if (mgr->kafkaConfig == NULL) {
        goto ERR;
    }
    memset(mgr->kafkaConfig, 0, sizeof(KafkaConfig));

    mgr->imdbConfig = (IMDBConfig *)malloc(sizeof(IMDBConfig));
    if (mgr->imdbConfig == NULL) {
        goto ERR;
    }
    memset(mgr->imdbConfig, 0, sizeof(IMDBConfig));

    mgr->webServerConfig = (WebServerConfig *)malloc(sizeof(WebServerConfig));
    if (mgr->webServerConfig == NULL) {
        goto ERR;
    }
    memset(mgr->webServerConfig, 0, sizeof(WebServerConfig));

    mgr->restServerConfig = (RestServerConfig *)malloc(sizeof(RestServerConfig));
    if (mgr->restServerConfig == NULL) {
        goto ERR;
    }
    memset(mgr->restServerConfig, 0, sizeof(RestServerConfig));

    mgr->logsConfig = (LogsConfig *)malloc(sizeof(LogsConfig));
    if (mgr->logsConfig == NULL) {
        goto ERR;
    }
    memset(mgr->logsConfig, 0, sizeof(LogsConfig));

    mgr->metricOutConfig = (OutConfig *)malloc(sizeof(OutConfig));
    if (mgr->metricOutConfig == NULL) {
        goto ERR;
    }
    memset(mgr->metricOutConfig, 0, sizeof(OutConfig));

    mgr->eventOutConfig = (OutConfig *)malloc(sizeof(OutConfig));
    if (mgr->eventOutConfig == NULL) {
        goto ERR;
    }
    memset(mgr->eventOutConfig, 0, sizeof(OutConfig));

    mgr->metaOutConfig = (OutConfig *)malloc(sizeof(OutConfig));
    if (mgr->metaOutConfig == NULL) {
        goto ERR;
    }
    memset(mgr->metaOutConfig, 0, sizeof(OutConfig));

    return mgr;
ERR:
    ConfigMgrDestroy(mgr);
    return NULL;
}

void ConfigMgrDestroy(ConfigMgr *mgr)
{
    if (mgr == NULL) {
        return;
    }

    if (mgr->globalConfig != NULL) {
        free(mgr->globalConfig);
    }

    if (mgr->kafkaConfig != NULL) {
        free(mgr->kafkaConfig);
    }

    if (mgr->imdbConfig != NULL) {
        free(mgr->imdbConfig);
    }

    if (mgr->webServerConfig != NULL) {
        free(mgr->webServerConfig);
    }

    if (mgr->restServerConfig != NULL) {
        free(mgr->restServerConfig);
    }

    if (mgr->logsConfig != NULL) {
        free(mgr->logsConfig);
    }

    if (mgr->metricOutConfig != NULL) {
        free(mgr->metricOutConfig);
    }

    if (mgr->eventOutConfig != NULL) {
        free(mgr->eventOutConfig);
    }

    if (mgr->metaOutConfig != NULL) {
        free(mgr->metaOutConfig);
    }

    free(mgr);
    return;
}

static int ConfigMgrLoadGlobalConfig(void *config, config_setting_t *settings)
{
    GlobalConfig *globalConfig = (GlobalConfig *)config;
    uint32_t ret = 0;

    const char *strVal;
    ret = config_setting_lookup_string(settings, "log_file_name", &strVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for log_file_name failed.\n");
        return -1;
    }

    (void)snprintf(globalConfig->logFileName, sizeof(globalConfig->logFileName), "%s", strVal);

    ret = config_setting_lookup_string(settings, "log_level", &strVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for log_level failed.\n");
        return -1;
    }
    (void)snprintf(globalConfig->logLevel, sizeof(globalConfig->logLevel), "%s", strVal);

    ret = config_setting_lookup_string(settings, "pin_path", &strVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for pin path failed.\n");
        return -1;
    }

    (void)snprintf(globalConfig->bpfPinPath, sizeof(globalConfig->bpfPinPath), "%s", strVal);
    return 0;
}

static int ConfigMgrLoadIngressConfig(void *config, config_setting_t *settings)
{
    IngressConfig *ingressConfig = (IngressConfig *)config;
    uint32_t ret = 0;

    uint32_t intVal = 0;
    ret = config_setting_lookup_int(settings, "interval", &intVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for ingress interval failed.\n");
        return -1;
    }
    ingressConfig->interval = intVal;

    return 0;
}

static int ConfigMgrLoadEgressConfig(void *config, config_setting_t *settings)
{
    EgressConfig *egressConfig = (EgressConfig *)config;
    uint32_t ret = 0;

    uint32_t intVal = 0;
    ret = config_setting_lookup_int(settings, "interval", &intVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for egress interval failed.\n");
        return -1;
    }
    egressConfig->interval = intVal;

    ret = config_setting_lookup_int(settings, "time_range", &intVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for egress time_range failed.\n");
        return -1;
    }
    egressConfig->timeRange = intVal;

    return 0;
}

static int ConfigMgrLoadKafkaConfig(void *config, config_setting_t *settings)
{
    KafkaConfig *kafkaConfig = (KafkaConfig *)config;
    uint32_t ret = 0;
    const char *strVal = NULL;
    uint32_t intVal = 0;

    ret = config_setting_lookup_string(settings, "kafka_broker", &strVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for kafka_broker failed.\n");
        return -1;
    }
    (void)snprintf(kafkaConfig->broker, sizeof(kafkaConfig->broker), "%s", strVal);

    ret = config_setting_lookup_int(settings, "batch_num_messages", &intVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for batch.num.messages failed.\n");
        return -1;
    }
    kafkaConfig->batchNumMessages = intVal;

    ret = config_setting_lookup_string(settings, "compression_codec", &strVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for compression.codec failed.\n");
        return -1;
    }
    (void)snprintf(kafkaConfig->compressionCodec, sizeof(kafkaConfig->compressionCodec), "%s", strVal);

    ret = config_setting_lookup_int(settings, "queue_buffering_max_messages", &intVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for queue.buffering.max.messages failed.\n");
        return -1;
    }
    kafkaConfig->queueBufferingMaxMessages = intVal;

    ret = config_setting_lookup_int(settings, "queue_buffering_max_kbytes", &intVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for queue.buffering.max.kbytes failed.\n");
        return -1;
    }
    kafkaConfig->queueBufferingMaxKbytes = intVal;

    ret = config_setting_lookup_int(settings, "queue_buffering_max_ms", &intVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for queue.buffering.max.ms failed.\n");
        return -1;
    }
    kafkaConfig->queueBufferingMaxMs = intVal;

    return 0;
}

static int ConfigMgrLoadIMDBConfig(void *config, config_setting_t *settings)
{
    IMDBConfig *imdbConfig = (IMDBConfig *)config;
    uint32_t ret = 0;
    uint32_t intVal = 0;

    ret = config_setting_lookup_int(settings, "max_tables_num", &intVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for imdbConfig max_tables_num failed.\n");
        return -1;
    }
    imdbConfig->maxTablesNum = intVal;

    ret = config_setting_lookup_int(settings, "max_records_num", &intVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for imdbConfig max_records_num failed.\n");
        return -1;
    }
    imdbConfig->maxRecordsNum = intVal;

    ret = config_setting_lookup_int(settings, "max_metrics_num", &intVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for imdbConfig max_metrics_num failed.\n");
        return -1;
    }
    imdbConfig->maxMetricsNum = intVal;

    ret = config_setting_lookup_int(settings, "record_timeout", &intVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for imdbConfig record_timeout failed, use default setting instead.\n");
    } else {
        imdbConfig->recordTimeout = intVal;
    }

    return 0;
}

static int ConfigMgrLoadWebServerConfig(void *config, config_setting_t *settings)
{
    WebServerConfig *webServerConfig = (WebServerConfig *)config;
    uint32_t ret = 0;
    const char *strVal = NULL;
    int intVal = 0;

    ret = config_setting_lookup_int(settings, "port", &intVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for webServerConfig port failed.\n");
        return -1;
    }
    webServerConfig->port = (uint16_t)intVal;

    return 0;
}

static int ConfigMgrLoadRestServerConfig(void *config, config_setting_t *settings)
{
    RestServerConfig *restServerConfig = (RestServerConfig *)config;
    uint32_t ret = 0;
    const char *strVal = NULL;
    uint32_t intVal = 0;

    ret = config_setting_lookup_int(settings, "port", &intVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for restServerConfig port failed.\n");
        return -1;
    }
    restServerConfig->port = (uint16_t)intVal;

    ret = config_setting_lookup_string(settings, "ssl_auth", &strVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for restServerConfig ssl_auth failed.\n");
        return -1;
    }
    if (strcmp(strVal, "on") == 0) {
        restServerConfig->sslAuth = 1;
    }

    ret = config_setting_lookup_string(settings, "private_key", &strVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for restServerConfig private_key failed.\n");
        return -1;
    }
    (void)snprintf(restServerConfig->privateKey, sizeof(restServerConfig->privateKey), "%s", strVal);

    ret = config_setting_lookup_string(settings, "cert_file", &strVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for restServerConfig cert_file failed.\n");
        return -1;
    }
    (void)snprintf(restServerConfig->certFile, sizeof(restServerConfig->certFile), "%s", strVal);

    ret = config_setting_lookup_string(settings, "ca_file", &strVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for restServerConfig ca_file failed.\n");
        return -1;
    }
    (void)snprintf(restServerConfig->caFile, sizeof(restServerConfig->caFile), "%s", strVal);

    return 0;
}

static int ConfigMgrLoadLogsConfig(void *config, config_setting_t *settings)
{
    LogsConfig *logsConfig = (LogsConfig *)config;
    uint32_t ret = 0;
    const char *strVal = NULL;

    ret = config_setting_lookup_string(settings, "metric_dir", &strVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for metric_dir failed.\n");
        return -1;
    }
    (void)snprintf(logsConfig->metricDir, sizeof(logsConfig->metricDir), "%s", strVal);

    ret = config_setting_lookup_string(settings, "event_dir", &strVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for event_dir failed.\n");
        return -1;
    }
    (void)snprintf(logsConfig->eventDir, sizeof(logsConfig->eventDir), "%s", strVal);

    ret = config_setting_lookup_string(settings, "meta_dir", &strVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for meta_dir failed.\n");
        return -1;
    }
    (void)snprintf(logsConfig->metaDir, sizeof(logsConfig->metaDir), "%s", strVal);

    ret = config_setting_lookup_string(settings, "debug_dir", &strVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for debug_dir failed.\n");
        return -1;
    }
    (void)snprintf(logsConfig->debugDir, sizeof(logsConfig->debugDir), "%s", strVal);

    return 0;
}

static int ConfigMgrLoadOutConfig(void *config, config_setting_t *settings)
{
    OutConfig *outConfig = (OutConfig  *)config;
    uint32_t ret = 0;
    const char *strVal = NULL;
    int timeout = 0;

    ret = config_setting_lookup_string(settings, "out_channel", &strVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for out_channel failed.\n");
        return -1;
    }
    if (!strcmp(strVal, "logs")) {
        outConfig->outChnl = OUT_CHNL_LOGS;
    } else if (!strcmp(strVal, "kafka")) {
        outConfig->outChnl = OUT_CHNL_KAFKA;
    } else if (!strcmp(strVal, "web_server")) {
        outConfig->outChnl = OUT_CHNL_WEB_SERVER;
    } else {
        outConfig->outChnl = -1;
        WARN("[CONFIG] config out_channel:%s invalid\n", strVal);
    }

    ret = config_setting_lookup_string(settings, "kafka_topic", &strVal);
    if (ret == 0) {
        ERROR("[CONFIG] load config for out kafka_topic failed.\n");
        return -1;
    }
    (void)snprintf(outConfig->kafka_topic, sizeof(outConfig->kafka_topic), "%s", strVal);

    ret = config_setting_lookup_int(settings, "timeout", &timeout);
    if (ret > 0) {
        outConfig->timeout = (uint32_t)timeout;
    }

    ret = config_setting_lookup_string(settings, "desc_language", &strVal);
    if (ret > 0) {
        (void)snprintf(outConfig->lang_type, sizeof(outConfig->lang_type), "%s", strVal);
    }

    return 0;
}

typedef int (*ConfigLoadFunc)(void *config, config_setting_t *settings);

typedef struct {
    void *config;
    char *sectionName;
    ConfigLoadFunc func;
} ConfigLoadHandle;

int ConfigMgrLoad(const ConfigMgr *mgr, const char *confPath)
{
    ConfigLoadHandle configLoadHandles[] = {
        { (void *)mgr->globalConfig, "global", ConfigMgrLoadGlobalConfig },
        { (void *)mgr->ingressConfig, "ingress", ConfigMgrLoadIngressConfig },
        { (void *)mgr->egressConfig, "egress", ConfigMgrLoadEgressConfig },
        { (void *)mgr->kafkaConfig, "kafka", ConfigMgrLoadKafkaConfig },
        { (void *)mgr->imdbConfig, "imdb", ConfigMgrLoadIMDBConfig },
        { (void *)mgr->webServerConfig, "web_server", ConfigMgrLoadWebServerConfig },
        { (void *)mgr->restServerConfig, "rest_api_server", ConfigMgrLoadRestServerConfig },
        { (void *)mgr->logsConfig, "logs", ConfigMgrLoadLogsConfig },
        { (void *)mgr->metricOutConfig, "metric", ConfigMgrLoadOutConfig },
        { (void *)mgr->eventOutConfig, "event", ConfigMgrLoadOutConfig },
        { (void *)mgr->metaOutConfig, "meta", ConfigMgrLoadOutConfig }
    };

    int ret = 0;
    config_t cfg;
    config_setting_t *settings = NULL;

    config_init(&cfg);
    ret = config_read_file(&cfg, confPath);
    if (ret == 0) {
        ERROR("[CONFIG] config read %s failed.\n", confPath);
        goto ERR;
    }

    uint32_t configUnitNum = sizeof(configLoadHandles) / sizeof(configLoadHandles[0]);
    for (int i = 0; i < configUnitNum; i++) {
        settings = config_lookup(&cfg, configLoadHandles[i].sectionName);
        if (settings == NULL) {
            ERROR("[CONFIG] config lookup %s failed.\n", configLoadHandles[i].sectionName);
            goto ERR;
        }

        ret = configLoadHandles[i].func(configLoadHandles[i].config, settings);
        if (ret != 0) {
            ERROR("[CONFIG] config load handle %s failed.\n", configLoadHandles[i].sectionName);
            goto ERR;
        }
    }

    config_destroy(&cfg);
    return 0;
ERR:
    config_destroy(&cfg);
    return -1;
}

