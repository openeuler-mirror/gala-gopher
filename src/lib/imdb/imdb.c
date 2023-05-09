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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "common.h"
#include "imdb.h"

static uint32_t g_recordTimeout = 60;       // default timeout: 60 seconds
TgidProcInfo_Table *tgid_infos = NULL;  // LRU cache of process tgid hash table

IMDB_Metric *IMDB_MetricCreate(char *name, char *description, char *type)
{
    int ret = 0;
    IMDB_Metric *metric = NULL;
    metric = (IMDB_Metric *)malloc(sizeof(IMDB_Metric));
    if (metric == NULL) {
        return NULL;
    }

    memset(metric, 0, sizeof(IMDB_Metric));
    ret = snprintf(metric->name, MAX_IMDB_METRIC_NAME_LEN, name);
    if (ret < 0) {
        free(metric);
        return NULL;
    }

    ret = snprintf(metric->description, MAX_IMDB_METRIC_DESC_LEN, description);
    if (ret < 0) {
        free(metric);
        return NULL;
    }

    ret = snprintf(metric->type, MAX_IMDB_METRIC_TYPE_LEN, type);
    if (ret < 0) {
        free(metric);
        return NULL;
    }

    return metric;
}

int IMDB_MetricSetValue(IMDB_Metric *metric, char *val)
{
    int ret = 0;
    ret = snprintf(metric->val, MAX_IMDB_METRIC_VAL_LEN, val);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

void IMDB_MetricDestroy(IMDB_Metric *metric)
{
    if (metric == NULL) {
        return;
    }

    free(metric);
    return;
}

IMDB_Record *IMDB_RecordCreate(uint32_t capacity)
{
    IMDB_Record *record = NULL;
    if (capacity == 0) {
        return NULL;
    }
    record = (IMDB_Record *)malloc(sizeof(IMDB_Record));
    if (record == NULL) {
        return NULL;
    }
    memset(record, 0, sizeof(IMDB_Record));

    record->metrics = (IMDB_Metric **)malloc(sizeof(IMDB_Metric *) * capacity);
    if (record->metrics == NULL) {
        free(record);
        return NULL;
    }
    memset(record->metrics, 0, sizeof(IMDB_Metric *) * capacity);

    record->metricsCapacity = capacity;
    return record;
}

IMDB_Record *IMDB_RecordCreateWithKey(uint32_t capacity, uint32_t keySize)
{
    if (keySize == 0) {
        return NULL;
    }

    IMDB_Record *record = IMDB_RecordCreate(capacity);

    if (record != NULL) {
        record->key = (char *)malloc(sizeof(char) * keySize);
        if (record->key == NULL) {
            IMDB_RecordDestroy(record);
            return NULL;
        }
        memset(record->key, 0, sizeof(char) * keySize);
        record->keySize = keySize;
    }

    return record;
}

int IMDB_RecordAddMetric(IMDB_Record *record, IMDB_Metric *metric)
{
    if (record->metricsNum == record->metricsCapacity) {
        return -1;
    }

    record->metrics[record->metricsNum] = metric;
    record->metricsNum++;
    return 0;
}

int IMDB_RecordAppendKey(IMDB_Record *record, uint32_t keyIdx, char *val)
{
    int ret = 0;
    uint32_t offset = keyIdx * MAX_IMDB_METRIC_VAL_LEN;

    if (offset + MAX_IMDB_METRIC_VAL_LEN > record->keySize) {
        return -1;
    }

    ret = snprintf(record->key + offset, MAX_IMDB_METRIC_VAL_LEN, val);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

void IMDB_RecordUpdateTime(IMDB_Record *record, time_t seconds)
{
    record->updateTime = seconds;
    return;
}

void IMDB_RecordDestroy(IMDB_Record *record)
{
    if (record == NULL)
        return;

    if (record->key != NULL) {
        free(record->key);
    }

    if (record->metrics != NULL) {
        for (int i = 0; i < record->metricsNum; i++) {
            IMDB_MetricDestroy(record->metrics[i]);
        }
        free(record->metrics);
    }
    free(record);
    return;
}

IMDB_Table *IMDB_TableCreate(char *name, uint32_t capacity)
{
    IMDB_Table *table = NULL;
    table = (IMDB_Table *)malloc(sizeof(IMDB_Table));
    if (table == NULL) {
        return NULL;
    }
    memset(table, 0, sizeof(IMDB_Table));

    table->records = (IMDB_Record **)malloc(sizeof(IMDB_Record *));
    if (table->records == NULL) {
        free(table);
        return NULL;
    }
    *(table->records) = NULL;     // necessary

    table->recordsCapability = capacity;
    (void)strncpy(table->name, name, MAX_IMDB_TABLE_NAME_LEN - 1);
    return table;
}

void IMDB_TableSetEntityName(IMDB_Table *table, char *entity_name)
{
    (void)strncpy(table->entity_name, entity_name, MAX_IMDB_TABLE_NAME_LEN - 1);
    return;
}

int IMDB_TableSetMeta(IMDB_Table *table, IMDB_Record *metaRecord)
{
    table->meta = metaRecord;
    return 0;
}

int IMDB_TableSetRecordKeySize(IMDB_Table *table, uint32_t keyNum)
{
    table->recordKeySize = keyNum * MAX_IMDB_METRIC_VAL_LEN;
    return 0;
}

int IMDB_TableAddRecord(IMDB_Table *table, IMDB_Record *record)
{
    IMDB_Record *old_record;

    old_record = HASH_findRecord((const IMDB_Record **)table->records, (const IMDB_Record *)record);
    if (old_record != NULL) {
        HASH_deleteRecord(table->records, old_record);
        IMDB_RecordDestroy(old_record);
    }

    if (HASH_recordCount((const IMDB_Record **)table->records) >= table->recordsCapability) {
        ERROR("[IMDB] Can not add new record to table %s: table full.\n", table->name);
        return -1;
    }
    IMDB_RecordUpdateTime(record, (time_t)time(NULL));
    HASH_addRecord(table->records, record);

    return 0;
}

void IMDB_TableDestroy(IMDB_Table *table)
{
    if (table == NULL) {
        return;
    }

    if (table->records != NULL) {
        HASH_deleteAndFreeRecords(table->records);
        free(table->records);
    }

    if (table->meta != NULL) {
        IMDB_RecordDestroy(table->meta);
    }

    free(table);
    return;
}


IMDB_DataBaseMgr *IMDB_DataBaseMgrCreate(uint32_t capacity)
{
    int ret = 0;
    IMDB_DataBaseMgr *mgr = NULL;
    mgr = (IMDB_DataBaseMgr *)malloc(sizeof(IMDB_DataBaseMgr));
    if (mgr == NULL) {
        return NULL;
    }

    memset(mgr, 0, sizeof(IMDB_DataBaseMgr));

    ret = get_system_uuid(mgr->nodeInfo.systemUuid, sizeof(mgr->nodeInfo.systemUuid));
    if (ret != 0) {
        ERROR("[IMDB] Can not get system uuid.\n");
        free(mgr);
        return NULL;
    }

    mgr->tables = (IMDB_Table **)malloc(sizeof(IMDB_Table *) * capacity);
    if (mgr->tables == NULL) {
        free(mgr);
        return NULL;
    }
    memset(mgr->tables, 0, sizeof(IMDB_Table *) * capacity);

    mgr->tblsCapability = capacity;
    ret = pthread_rwlock_init(&mgr->rwlock, NULL);
    if (ret != 0) {
        free(mgr->tables);
        free(mgr);
        return NULL;
    }

    return mgr;
}

void IMDB_DataBaseMgrSetRecordTimeout(uint32_t timeout)
{
    if (timeout > 0) {
        g_recordTimeout = timeout;
    }

    return;
}

void IMDB_DataBaseMgrDestroy(IMDB_DataBaseMgr *mgr)
{
    if (mgr == NULL) {
        return;
    }

    if (mgr->tables != NULL) {
        for (int i = 0; i < mgr->tablesNum; i++) {
            IMDB_TableDestroy(mgr->tables[i]);
        }
        free(mgr->tables);
    }
    (void)pthread_rwlock_destroy(&mgr->rwlock);
    free(mgr);
    return;
}

int IMDB_DataBaseMgrAddTable(IMDB_DataBaseMgr *mgr, IMDB_Table* table)
{
    if (mgr->tablesNum == mgr->tblsCapability) {
        return -1;
    }

    for (int i = 0; i < mgr->tablesNum; i++) {
        if (strcmp(mgr->tables[i]->name, table->name) == 0)
            return -1;
    }

    mgr->tables[mgr->tablesNum] = table;
    mgr->tablesNum++;
    return 0;
}

IMDB_Table *IMDB_DataBaseMgrFindTable(IMDB_DataBaseMgr *mgr, char *tableName)
{
    for (int i = 0; i < mgr->tablesNum; i++) {
        if (strcmp(mgr->tables[i]->name, tableName) == 0) {
            return mgr->tables[i];
        }
    }

    return NULL;
}

static int IMDB_DataBaseMgrParseContent(IMDB_DataBaseMgr *mgr, IMDB_Table *table,
                                        IMDB_Record *record, char *content, char needKey)
{
    int ret = 0;
    IMDB_Metric *metric;

    char *token, *buffer;
    char delim[] = "|";
    char *buffer_head = NULL;

    uint32_t keyIdx = 0, index = 0;

    buffer = strdup(content);
    if (buffer == NULL) {
        goto ERR;
    }
    buffer_head = buffer;

    // start analyse record string
    for (token = strsep(&buffer, delim); token != NULL; token = strsep(&buffer, delim)) {
        if (strcmp(token, "\n") == 0)
            break;

        if (strcmp(token, "") == 0) {
            if (index == 0) {
                continue;   // first metrics
            } else {
                token = INVALID_METRIC_VALUE;
            }
        }

        // if index > metricNum, it's invalid
        if (index >= table->meta->metricsNum) {
            break;
        }
        // fill record by the rest substrings
        metric = IMDB_MetricCreate(table->meta->metrics[index]->name,
                                   table->meta->metrics[index]->description,
                                   table->meta->metrics[index]->type);
        if (metric == NULL) {
            ERROR("[IMDB] Can't create metrics(%s, %s).\n", table->name,
                table->meta->metrics[index]->name);
            goto ERR;
        }

        ret = IMDB_MetricSetValue(metric, token);
        if (ret != 0) {
            ERROR("[IMDB] Set metrics value failed.(%s, %s).\n", table->name, metric->name);
            IMDB_MetricDestroy(metric);
            goto ERR;
        }

        ret = IMDB_RecordAddMetric(record, metric);
        if (ret != 0) {
            ERROR("[IMDB] Add metrics failed.(%s, %s).\n", table->name, metric->name);
            IMDB_MetricDestroy(metric);
            goto ERR;
        }

        if (needKey && strcmp(METRIC_TYPE_KEY, table->meta->metrics[index]->type) == 0) {
            ret = IMDB_RecordAppendKey(record, keyIdx, token);
            if (ret < 0) {
                ERROR("[IMDB] Can not set record key.\n");
                goto ERR;
            }
            keyIdx++;
        }

        index += 1;
    }
    if (buffer_head != NULL) {
        free(buffer_head);
    }
    return 0;

ERR:
    if (buffer_head != NULL) {
        free(buffer_head);
    }
    return -1;
}

IMDB_Record* IMDB_DataBaseMgrCreateRec(IMDB_DataBaseMgr *mgr, IMDB_Table *table, char *content)
{
    pthread_rwlock_wrlock(&mgr->rwlock);

    int ret = 0;
    IMDB_Record *record;

    record = IMDB_RecordCreateWithKey(table->meta->metricsCapacity, table->recordKeySize);
    if (record == NULL) {
        goto ERR;
    }

    ret = IMDB_DataBaseMgrParseContent(mgr, table, record, content, 1);
    if (ret != 0) {
        ERROR("[IMDB]Raw ingress data to rec failed(CREATEREC).\n");
        goto ERR;
    }
    ret = IMDB_TableAddRecord(table, record);
    if (ret != 0) {
        goto ERR;
    }

    pthread_rwlock_unlock(&mgr->rwlock);
    return record;

ERR:
    pthread_rwlock_unlock(&mgr->rwlock);
    if (record != NULL) {
        IMDB_RecordDestroy(record);
    }

    return NULL;
}

int IMDB_DataBaseMgrAddRecord(IMDB_DataBaseMgr *mgr, char *recordStr)
{
    pthread_rwlock_wrlock(&mgr->rwlock);

    int ret = 0;
    IMDB_Table *table = NULL;
    IMDB_Record *record = NULL;
    IMDB_Metric *metric = NULL;

    int index = -1;
    char *token = NULL;
    char delim[] = "|";
    char *buffer = NULL;
    char *buffer_head = NULL;

    uint32_t keyIdx = 0;

    buffer = strdup(recordStr);
    if (buffer == NULL) {
        goto ERR;
    }
    buffer_head = buffer;

    // start analyse record string
    for (token = strsep(&buffer, delim); token != NULL; token = strsep(&buffer, delim)) {
        if (strcmp(token, "") == 0) {
            if (index == -1) {
                continue;
            } else {
                token = INVALID_METRIC_VALUE;
            }
        }

        if (strcmp(token, "\n") == 0) {
            continue;
        }
        // mark table name as the -1 substring so that metrics start at 0
        // find table by the first substring
        if (index == -1) {
            table = IMDB_DataBaseMgrFindTable(mgr, token);
            if (table == NULL) {
                ERROR("[IMDB] Can not find table named %s.\n", token);
                free(buffer_head);
                goto ERR;
            }

            if (table->recordKeySize == 0) {
                ERROR("[IMDB] Can not add record to table %s: no key type of metric set.\n", token);
                free(buffer_head);
                goto ERR;
            }

            record = IMDB_RecordCreateWithKey(table->meta->metricsCapacity, table->recordKeySize);
            if (record == NULL) {
                ERROR("[IMDB] Can not create record.\n");
                free(buffer_head);
                goto ERR;
            }

            index += 1;
            continue;
        }

        // if index > metricNum, it's invalid
        if (index >= table->meta->metricsNum) {
            break;
        }
        // fill record by the rest substrings
        metric = IMDB_MetricCreate(table->meta->metrics[index]->name,
                                   table->meta->metrics[index]->description,
                                   table->meta->metrics[index]->type);
        if (metric == NULL) {
            ERROR("[IMDB] Can't create metrics.\n");
            free(buffer_head);
            goto ERR;
        }

        ret = IMDB_MetricSetValue(metric, token);
        if (ret != 0) {
            free(buffer_head);
            IMDB_MetricDestroy(metric);
            goto ERR;
        }

        ret = IMDB_RecordAddMetric(record, metric);
        if (ret != 0) {
            free(buffer_head);
            IMDB_MetricDestroy(metric);
            goto ERR;
        }

        if (strcmp(METRIC_TYPE_KEY, table->meta->metrics[index]->type) == 0) {
            ret = IMDB_RecordAppendKey(record, keyIdx, token);
            if (ret < 0) {
                ERROR("[IMDB] Can not set record key.\n");
                free(buffer_head);
                goto ERR;
            }
            keyIdx++;
        }

        index += 1;
    }

    ret = IMDB_TableAddRecord(table, record);
    if (ret != 0) {
        free(buffer_head);
        goto ERR;
    }

    free(buffer_head);

    pthread_rwlock_unlock(&mgr->rwlock);
    return 0;
ERR:
    pthread_rwlock_unlock(&mgr->rwlock);
    if (record != NULL) {
        IMDB_RecordDestroy(record);
    }
    return -1;
}

// return 0 if satisfy, return -1 if not
static int MetricTypeSatisfyPrometheus(IMDB_Metric *metric)
{
    const char prometheusTypes[][MAX_IMDB_METRIC_TYPE_LEN] = {
        "counter",
        "gauge",
        "histogram",
        "summary"
    };

    int size = sizeof(prometheusTypes) / sizeof(prometheusTypes[0]);
    for (int i = 0; i < size; i++) {
        if (strcmp(metric->type, prometheusTypes[i]) == 0) {
            return 0;
        }
    }

    return -1;
}

static int MetricTypeIsLabel(IMDB_Metric *metric)
{
    const char *label[] = {METRIC_TYPE_LABEL, METRIC_TYPE_KEY};
    for (int i = 0; i < sizeof(label) / sizeof(label[0]); i++) {
        if (strcmp(metric->type, label[i]) == 0) {
            return 1;
        }
    }

    return 0;
}

static int MetricNameIsTgid(IMDB_Metric *metric)
{
    const char *tgid = "tgid";
    if (strcmp(metric->name, tgid) == 0) {
        return 1;
    }

    return 0;
}

#if 1

static int IMDB_BuildEntiyID(const IMDB_DataBaseMgr *mgr,
                             const char *entityName,
                             const char *entityId,
                             char *buffer, uint32_t maxLen)
{
    int size = (int)maxLen;
    char *p = buffer;
    const char *fmt = "%s_%s_%s";  // MACHINEID_ENTITYNAME_ENTITYID

    if (entityName == NULL || entityId == NULL) {
        return -1;
    }

    return __snprintf(&p, size, &size, fmt, mgr->nodeInfo.systemUuid, entityName, entityId);
}

static int IMDB_BuildEventID(const IMDB_DataBaseMgr *mgr,
                             const char *entityName,
                             const char *entityId,
                             time_t timestamp,
                             char *buffer, uint32_t maxLen)
{
    int size = (int)maxLen;
    char *p = buffer;
    const char *fmt = "%lld_%s_%s_%s";  // TIMESTAMP_MACHINEID_ENTITYNAME_ENTITYID

    if (entityName == NULL || entityId == NULL) {
        return -1;
    }

    return __snprintf(&p, size, &size, fmt, timestamp, mgr->nodeInfo.systemUuid, entityName, entityId);
}

static int IMDB_BuildEventType(char *buffer, uint32_t maxLen)
{
    int size = (int)maxLen;
    char *p = buffer;
    const char *fmt = "%s";  // "sys" or "app", gopher only use "sys"

    return __snprintf(&p, size, &size, fmt, "sys");
}

static int IMDB_BuildTmStamp(char *buffer, uint32_t maxLen, time_t *timestamp)
{
    int size = (int)maxLen;
    time_t now;
    char *p = buffer;
    const char *fmt = "\"Timestamp\": %lld";  // "Timestamp": 1586960586000000000

    (void)time(&now);
    *timestamp = now * THOUSAND;
    return __snprintf(&p, size, &size, fmt, *timestamp);
}

// eg: gala_gopher_tcp_link_rx_bytes
static int IMDB_BuildMetrics(const char *entity_name,
                             const char *metrcisName,
                             char *buffer, uint32_t maxLen)
{
    int size = (int)maxLen;
    const char *fmt = "gala_gopher_%s_%s";  // entityName_metricsName

    if (entity_name == NULL || metrcisName == NULL) {
        return -1;
    }

    return __snprintf(&buffer, size, &size, fmt, entity_name, metrcisName);
}

// eg: gala_gopher_tcp_link_rx_bytes(label) 128 1586960586000000000
static int IMDB_BuildPrometheusMetrics(const IMDB_Metric *metric, char *buffer, uint32_t maxLen,
                                       const char *entity_name, const char *labels)
{
    int ret, len;
    char *p = buffer;
    int size = (int)maxLen;
    time_t now;
    const char *fmt = "%s %s %lld\n";  // Metrics##labels MetricsVal timestamp

    ret = IMDB_BuildMetrics(entity_name, metric->name, buffer, (uint32_t)size);
    if (ret < 0) {
        return ret;
    }

    len = strlen(buffer);
    p += len;
    size -= len;
    (void)time(&now);
    ret = __snprintf(&p, size, &size, fmt, labels, metric->val, now * THOUSAND);
    if (ret < 0) {
        return ret;
    }

    return (int)((int)maxLen - size);   // Returns the number of printed characters
}

                                    
static int IMDB_BuildPrometheusLabel(const IMDB_DataBaseMgr *mgr,
                                     IMDB_Record *record,
                                     char *buffer,
                                     uint32_t maxLen)
{
    char *p = buffer;
    int ret;
    int size = maxLen;
    char first_flag = 1;
    int tgid_idx = -1;

    ret = __snprintf(&p, size, &size, "%s", "{");
    if (ret < 0) {
        goto err;
    }

    for (int i = 0; i < record->metricsNum; i++) {
        if (MetricNameIsTgid(record->metrics[i]) == 1) {
            tgid_idx = i;
        }

        if (MetricTypeIsLabel(record->metrics[i]) == 0) {
            continue;
        }

        if (!strcmp(record->metrics[i]->val, INVALID_METRIC_VALUE)) {
            // ignore label whose value is (null)
            continue;
        }

        if (first_flag) {
            ret = __snprintf(&p, size, &size, "%s=\"%s\"",
                            record->metrics[i]->name, record->metrics[i]->val);
        } else {
            ret = __snprintf(&p, size, &size, ",%s=\"%s\"",
                            record->metrics[i]->name, record->metrics[i]->val);
        }
        if (ret < 0) {
            goto err;
        }
        first_flag = 0;
    }

    if (mgr->podInfoSwitch == POD_INFO_ON && tgid_idx >= 0) {
        ProcInfo *info = look_up_proc_info_by_tgid(&tgid_infos, record->metrics[tgid_idx]->val);
        if (strlen(info->container_name) > 0) {
            ret = __snprintf(&p, size, &size, ",container_name=\"%s\"", info->container_name);
            if (ret < 0) {
                goto err;
            }
        }

        if (strlen(info->pod_name) > 0) {
            ret = __snprintf(&p, size, &size, ",pod_name=\"%s\"", info->pod_name);
            if (ret < 0) {
                goto err;
            }
        }
    }

    // append machine_id
    ret = __snprintf(&p, size, &size, ",machine_id=\"%s\"", mgr->nodeInfo.systemUuid);
    if (ret < 0) {
        goto err;
    }

    ret = __snprintf(&p, size, &size, "%s", "}");
    if (ret < 0) {
        goto err;
    }

    return 0;
err:
    return ret;
}

#endif

#if 1

static void RequeueTable(IMDB_Table **tables, uint32_t tablesNum)
{
    IMDB_Table* firstTbl = tables[0];

    for (int i = 1; i < tablesNum; i++) {
        tables[i - 1] = tables[i];
    }

    tables[tablesNum - 1] = firstTbl;
    firstTbl->weighting = 0;    // Set to the highest priority.
    return;
}

static void IMDB_AdjustTblPrio(IMDB_DataBaseMgr *mgr)
{
    int nameLen, num_adjust = 0;
    char tblName[MAX_IMDB_TABLE_NAME_LEN];

    if (!mgr->tables[0]->weighting) {
        return; // No need adjust
    }

    nameLen = strlen(mgr->tables[0]->name);
    (void)memcpy(tblName, mgr->tables[0]->name, nameLen);
    tblName[nameLen] = 0;

    do {
        RequeueTable(mgr->tables, mgr->tablesNum);
        num_adjust++;
        
        if (!mgr->tables[0]->weighting) {
            break; // End of adjustment
        }
        
        if (strcmp(mgr->tables[0]->name, tblName) == 0) {
            break; // End of adjustment
        }
        
        if (num_adjust >= mgr->tablesNum) {
            break; // Error, End of adjustment
        }
    } while (1);
    return;
}

static int IMDB_Rec2Prometheus(IMDB_DataBaseMgr *mgr, IMDB_Record *record, char *entity_name,
                               char *buffer, uint32_t maxLen)
{
    int ret = 0;
    int total = 0;
    char *curBuffer = buffer;
    uint32_t curMaxLen = maxLen;

    char labels[MAX_LABELS_BUFFER_SIZE] = {0};
    ret = IMDB_BuildPrometheusLabel(mgr, record, labels, MAX_LABELS_BUFFER_SIZE);
    if (ret < 0) {
        ERROR("[IMDB] table of (%s) build label fail, ret: %d\n", entity_name, ret);
        goto ERR;
    }

    for (int i = 0; i < record->metricsNum; i++) {
        ret = MetricTypeSatisfyPrometheus(record->metrics[i]);
        if (ret != 0) {
            continue;
        }

        if (!strcmp(record->metrics[i]->val, INVALID_METRIC_VALUE)) {
            // Do not report metric whose value is (null)
            continue;
        }

        ret = IMDB_BuildPrometheusMetrics(record->metrics[i], curBuffer, curMaxLen, entity_name, labels);
        if (ret < 0) {
            break;  /* buffer is full, break loop */
        }

        curBuffer += ret;
        curMaxLen -= ret;
        total += ret;
    }

ERR:
    return total;
}



static int IMDB_Tbl2Prometheus(IMDB_DataBaseMgr *mgr, IMDB_Table *table, char *buffer, uint32_t maxLen)
{
    int ret = 0;
    int total = 0;
    IMDB_Record *record, *tmp;
    char *curBuffer = buffer;
    uint32_t curMaxLen = maxLen;
    uint32_t period_records = DEFAULT_PERIOD_RECORD_NUM;
    uint32_t index = 0;

    if (HASH_recordCount((const IMDB_Record **)table->records) == 0) {
        return 0;
    }
    HASH_ITER(hh, *table->records, record, tmp) {
        // check record num
        if (index >= period_records) {
            break;
        }
        // check timeout
        if (record->updateTime + g_recordTimeout < time(NULL)) {
            // remove invalid record
            HASH_deleteRecord(table->records, record);
            IMDB_RecordDestroy(record);
            continue;
        }

        ret = IMDB_Rec2Prometheus(mgr, record, table->entity_name, curBuffer, curMaxLen);
        if (ret < 0) {
            ERROR("[IMDB] table(%s) record to string fail.\n", table->name);
            return -1;
        }
        if (ret == 0) {
            break;  /* buffer is full, break loop */
        }

        curBuffer += ret;
        curMaxLen -= ret;
        total += ret;

        // delete record after to string
        HASH_deleteRecord(table->records, record);
        IMDB_RecordDestroy(record);

        index++;
    }

    ret = snprintf(curBuffer, curMaxLen, "\n");
    if (ret < 0) {
        ERROR("[IMDB] table(%s) add endsym fail.\n", table->name);
        return -1;
    }
    curBuffer += 1;
    curMaxLen -= 1;
    total += 1;

    return total;
}

int IMDB_DataBase2Prometheus(IMDB_DataBaseMgr *mgr, char *buffer, uint32_t maxLen, uint32_t *buf_len)
{
    pthread_rwlock_wrlock(&mgr->rwlock);

    int ret = 0;
    char *cursor = buffer;
    uint32_t curMaxLen = maxLen;

    for (int i = 0; i < mgr->tablesNum; i++) {
        ret = IMDB_Tbl2Prometheus(mgr, mgr->tables[i], cursor, curMaxLen);
        if (ret < 0 || ret >= curMaxLen) {
            goto ERR;
        }

        if (ret > 0) {
            mgr->tables[i]->weighting++;
        }
        cursor += ret;
        curMaxLen -= ret;
    }
    IMDB_AdjustTblPrio(mgr);
    *buf_len = maxLen - curMaxLen;
    pthread_rwlock_unlock(&mgr->rwlock);
    return 0;
ERR:

    pthread_rwlock_unlock(&mgr->rwlock);
    return -1;
}

#endif

static int IMDB_Record2Json(const IMDB_DataBaseMgr *mgr, const IMDB_Table *table, const IMDB_Record *record,
                            char *jsonStr, uint32_t jsonStrLen)
{
    int ret = 0;
    char *json_cursor = jsonStr;
    int maxLen = (int)jsonStrLen;

    time_t now;
    (void)time(&now);

    jsonStr[0] = 0;
    ret = snprintf(json_cursor, maxLen, "{\"timestamp\": %lld", now * THOUSAND);
    if (ret < 0)  {
        return -1;
    }
    json_cursor += ret;
    maxLen -= ret;
    if (maxLen < 0)  {
        return -1;
    }

    ret = snprintf(json_cursor, maxLen, ", \"machine_id\": \"%s\"", mgr->nodeInfo.systemUuid);
    if (ret < 0)  {
        return -1;
    }
    json_cursor += ret;
    maxLen -= ret;
    if (maxLen < 0)  {
        return -1;
    }

    ret = snprintf(json_cursor, maxLen, ", \"entity_name\": \"%s\"", table->entity_name);
    if (ret < 0)  {
        return -1;
    }
    json_cursor += ret;
    maxLen -= ret;
    if (maxLen < 0)  {
        return -1;
    }

    for (int i = 0; i < record->metricsNum; i++) {
        ret = snprintf(json_cursor, maxLen, ", \"%s\": \"%s\"", record->metrics[i]->name, record->metrics[i]->val);
        if (ret < 0)  {
            return -1;
        }
        json_cursor += ret;
        maxLen -= ret;
        if (maxLen < 0)  {
            return -1;
        }
    }

    ret = snprintf(json_cursor, maxLen, "}");
    if (ret < 0) {
        return -1;
    }

    return 0;
}

#define __EVT_TBL_ENTITYNAME "EntityName"
#define __EVT_TBL_ENTITYID "EntityID"
#define __EVT_TBL_METRICS "metrics"
#define __EVT_TBL_SECTXT "SeverityText"
#define __EVT_TBL_SECNUM "SeverityNumber"
#define __EVT_TBL_BODY "Body"

static const char* IMDB_GetEvtVal(IMDB_Record *record, const char *metricsName)
{
    int i;

    for (i = 0; i < record->metricsNum; i++) {
        if (strcmp(record->metrics[i]->name, metricsName) == 0) {
            return (const char *)record->metrics[i]->val;
        }
    }
    return NULL;
}

// 对entityID中出现的特殊字符进行替换，替换为':'
static void transfer_entityID(char *entityID)
{
    int i, j;
    char special_symbols[] = {'/'};     // 不支持的符号集合，可以新增
    int sym_size = sizeof(special_symbols) / sizeof(special_symbols[0]);

    for (i = 0; i < strlen(entityID); i++) {
        for (j = 0; j < sym_size; j++) {
            if (entityID[i] == special_symbols[j]) {
                entityID[i] = ':';
            }
        }
    }
    return;
}

/*

{
  "Timestamp": 1586960586000000000,
  "event_id": "1586xxx_xxxx"
  "Attributes": {
    "entity_id": "xx",
    "event_id": "1586xxx_xxxx",
    "event_type": "sys",
    "data": [....],     // optional
    "duration": 30,     // optional
    "occurred count": 6,// optional
  },
  "Resource": {
    "metric": "gala_gopher_tcp_link_health_rx_bytes",
  },
  "SeverityText": "WARN",
  "SeverityNumber": 13,
  "Body": "20200415T072306-0700 WARN Entity(xx)  occurred gala_gopher_tcp_link_health_rx_bytes event."
}

*/
static int IMDB_Evt2Json(const IMDB_DataBaseMgr *mgr,
                                  IMDB_Table *table,
                                  IMDB_Record *record,
                                  char *jsonStr,
                                  uint32_t jsonStrLen)
{
    char *p = jsonStr;
    int len = jsonStrLen;
    int ret = 0;
    time_t timestamp;
    const char *entityName = IMDB_GetEvtVal(record, __EVT_TBL_ENTITYNAME);
    const char *entityID = IMDB_GetEvtVal(record, __EVT_TBL_ENTITYID);
    const char *metrics = IMDB_GetEvtVal(record, __EVT_TBL_METRICS);
    const char *secTxt = IMDB_GetEvtVal(record, __EVT_TBL_SECTXT);
    const char *secNum = IMDB_GetEvtVal(record, __EVT_TBL_SECNUM);
    const char *body = IMDB_GetEvtVal(record, __EVT_TBL_BODY);

    transfer_entityID((char *)entityID);

    ret = __snprintf(&p, len, &len, "%s", "{");
    if (ret < 0) {
        goto err;
    }

    ret = IMDB_BuildTmStamp(p, len, &timestamp);
    if (ret < 0) {
        goto err;
    }

    // Readdressing end of string
    len = strlen(jsonStr);
    p = jsonStr + len;
    len = jsonStrLen - len;

    ret = __snprintf(&p, len, &len, "%s", ", \"event_id\": \"");
    if (ret < 0) {
        goto err;
    }

    ret = IMDB_BuildEventID(mgr, entityName, entityID, timestamp, p, len);
    if (ret < 0) {
        goto err;
    }

    // Readdressing end of string
    len = strlen(jsonStr);
    p = jsonStr + len;
    len = jsonStrLen - len;

    ret = __snprintf(&p, len, &len, "%s", "\", \"Attributes\": { \"entity_id\": \"");
    if (ret < 0) {
        goto err;
    }

    ret = IMDB_BuildEntiyID(mgr, entityName, entityID, p, len);
    if (ret < 0) {
        goto err;
    }

    // Readdressing end of string
    len = strlen(jsonStr);
    p = jsonStr + len;
    len = jsonStrLen - len;

    ret = __snprintf(&p, len, &len, "%s", "\", \"event_id\": \"");
    if (ret < 0) {
        goto err;
    }

    ret = IMDB_BuildEventID(mgr, entityName, entityID, timestamp, p, len);
    if (ret < 0) {
        goto err;
    }

    // Readdressing end of string
    len = strlen(jsonStr);
    p = jsonStr + len;
    len = jsonStrLen - len;

    ret = __snprintf(&p, len, &len, "%s", "\", \"event_type\": \"");
    if (ret < 0) {
        goto err;
    }

    ret = IMDB_BuildEventType(p, len);
    if (ret < 0) {
        goto err;
    }

    // Readdressing end of string
    len = strlen(jsonStr);
    p = jsonStr + len;
    len = jsonStrLen - len;

    ret = __snprintf(&p, len, &len, "%s", "\"}, \"Resource\": { \"metric\": \"");
    if (ret < 0) {
        goto err;
    }

    ret = IMDB_BuildMetrics(entityName, metrics, p, len);
    if (ret < 0) {
        goto err;
    }

    // Readdressing end of string
    len = strlen(jsonStr);
    p = jsonStr + len;
    len = jsonStrLen - len;

    ret = __snprintf(&p, len, &len, "\"}, \"SeverityText\": \"%s\",", secTxt);
    if (ret < 0) {
        goto err;
    }

    ret = __snprintf(&p, len, &len, "\"SeverityNumber\": %s,", secNum);
    if (ret < 0) {
        goto err;
    }

    ret = __snprintf(&p, len, &len, "\"Body\": \"%s\"}", body);

err:
    return ret;
}

int IMDB_Rec2Json(IMDB_DataBaseMgr *mgr, IMDB_Table *table,
                        IMDB_Record* rec, const char *dataStr, char *jsonStr, uint32_t jsonStrLen)
{
    int ret = 0;
    int createRecFlag = 0;
    IMDB_Record *record = rec;

    if (record == NULL) {
        record = IMDB_RecordCreate(table->meta->metricsCapacity);
        if (record == NULL) {
            goto ERR;
        }
        createRecFlag = 1;
        ret = IMDB_DataBaseMgrParseContent(mgr, table, record, (char *)dataStr, 0);
        if (ret != 0) {
            ERROR("[IMDB]Raw ingress data to rec failed(REC2JSON).\n");
            goto ERR;
        }
    }

    // ‘event’ log to json
    if (strcmp(table->entity_name, "event") == 0) {
        ret = IMDB_Evt2Json(mgr, table, record, jsonStr, jsonStrLen);
    } else {
        ret = IMDB_Record2Json(mgr, table, record, jsonStr, jsonStrLen);
    }

    if (ret != 0) {
        ERROR("[IMDB]Rec to json failed.\n");
        goto ERR;
    }

    if (createRecFlag) {
        IMDB_RecordDestroy(record);
    }

    return 0;
ERR:
    if (createRecFlag) {
        IMDB_RecordDestroy(record);
    }
    return -1;
}

IMDB_Record *HASH_findRecord(const IMDB_Record **records, const IMDB_Record *record)
{
    IMDB_Record *r;
    HASH_FIND(hh, *records, record->key, record->keySize, r);
    return r;
}

void HASH_addRecord(IMDB_Record **records, IMDB_Record *record)
{
    HASH_ADD_KEYPTR(hh, *records, record->key, record->keySize, record);
    return;
}

void HASH_deleteRecord(IMDB_Record **records, IMDB_Record *record)
{
    if (records == NULL || record == NULL)  {
        return;
    }

    HASH_DEL(*records, record);
    return;
}

void HASH_deleteAndFreeRecords(IMDB_Record **records)
{
    if (records == NULL)  {
        return;
    }

    IMDB_Record *r, *tmp;
    HASH_ITER(hh, *records, r, tmp) {
        HASH_deleteRecord(records, r);
        IMDB_RecordDestroy(r);
    }
    return;
}

uint32_t HASH_recordCount(const IMDB_Record **records)
{
    uint32_t num = 0;
    num = (uint32_t)HASH_COUNT(*records);
    return num;
}
