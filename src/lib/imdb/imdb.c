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
#include "java_support.h"
#include "histogram.h"
#include "strbuf.h"
#include "container.h"
#include "meta.h"
#include "imdb.h"

static uint32_t g_recordTimeout = 60;       // default timeout: 60 seconds
#define IMDB_BUILD_ERR           (-1)
#define IMDB_BUFFER_FULL         (-2)

IMDB_Metric *IMDB_MetricCreate(char *name, char *description, char *type)
{
    int ret = 0;
    IMDB_Metric *metric = NULL;
    metric = (IMDB_Metric *)malloc(sizeof(IMDB_Metric));
    if (metric == NULL) {
        return NULL;
    }

    memset(metric, 0, sizeof(IMDB_Metric));
    ret = snprintf(metric->name, MAX_IMDB_METRIC_NAME_LEN, "%s", name);
    if (ret < 0) {
        free(metric);
        return NULL;
    }

    ret = snprintf(metric->description, MAX_IMDB_METRIC_DESC_LEN, "%s", description);
    if (ret < 0) {
        free(metric);
        return NULL;
    }

    ret = snprintf(metric->type, MAX_IMDB_METRIC_TYPE_LEN, "%s", type);
    if (ret < 0) {
        free(metric);
        return NULL;
    }

    return metric;
}

int IMDB_MetricSetValue(IMDB_Metric *metric, char *val)
{
    int ret = 0;
    ret = snprintf(metric->val, MAX_IMDB_METRIC_VAL_LEN, "%s", val);
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

    ret = snprintf(record->key + offset, MAX_IMDB_METRIC_VAL_LEN, "%s", val);
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

    if (pthread_rwlock_init(&table->ext_label_conf.rwlock, NULL)) {
        free(table->records);
        free(table);
        return NULL;
    }

    table->recordsCapability = capacity;
    (void)snprintf(table->name, sizeof(table->name), "%s", name);
    return table;
}

void IMDB_TableSetEntityName(IMDB_Table *table, char *entity_name)
{
    (void)snprintf(table->entity_name, sizeof(table->entity_name), "%s", entity_name);
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

void IMDB_TableUpdateExtLabelConf(IMDB_Table *table, struct ext_label_conf *conf)
{
    (void)pthread_rwlock_rdlock(&conf->rwlock);
    (void)pthread_rwlock_wrlock(&table->ext_label_conf.rwlock);
    if (table->ext_label_conf.last_update_time < conf->last_update_time) {
        table->ext_label_conf.last_update_time = conf->last_update_time;
        if (copy_ext_label_conf(&table->ext_label_conf, conf)) {
            WARN("[IMDB] Can not update extend label config to table %s.\n", table->name);
        }
    }
    (void)pthread_rwlock_unlock(&table->ext_label_conf.rwlock);
    (void)pthread_rwlock_unlock(&conf->rwlock);
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

    destroy_ext_label_conf_locked(&table->ext_label_conf);
    (void)pthread_rwlock_destroy(&table->ext_label_conf.rwlock);

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
        goto err;
    }

    /* Silence here when failed to get system ip and leave it handled afterwards */
    (void)get_system_ip(mgr->nodeInfo.hostIP, MAX_IMDB_HOSTIP_LEN);
    (void)get_system_hostname(mgr->nodeInfo.hostName, sizeof(mgr->nodeInfo.hostName));

    mgr->tables = (IMDB_Table **)malloc(sizeof(IMDB_Table *) * capacity);
    if (mgr->tables == NULL) {
        goto err;
    }
    memset(mgr->tables, 0, sizeof(IMDB_Table *) * capacity);

    mgr->tgids = (TGID_Record **)malloc(sizeof(TGID_Record *));
    if (mgr->tgids == NULL) {
        goto err;
    }
    *(mgr->tgids) = NULL;     // necessary

    mgr->tblsCapability = capacity;
    ret = pthread_rwlock_init(&mgr->rwlock, NULL);
    if (ret != 0) {
        goto err;
    }

    return mgr;
err:
    if (mgr->tgids) {
        free(mgr->tgids);
    }
    if (mgr->tables) {
        free(mgr->tables);
    }
    free(mgr);
    return NULL;
}

#define __IMDB_TGID_CACHE_SIZE  1024

void IMDB_TgidAddRecord(const IMDB_DataBaseMgr *mgr, TGID_Record *record)
{
    if (H_COUNT(*(mgr->tgids)) > __IMDB_TGID_CACHE_SIZE) {
        TGID_Record *r, *tmp;
        H_ITER(*(mgr->tgids), r, tmp) {
            HASH_DEL(*(mgr->tgids), r);
            free(r);
            break;
        }
    }

    H_ADD_KEYPTR(*(mgr->tgids), &record->key, sizeof(TGID_RecordKey), record);
    return;
}

TGID_Record* IMDB_TgidLkupRecord(const IMDB_DataBaseMgr *mgr, const char* tgid)
{
    TGID_Record *record = NULL;
    TGID_RecordKey key = {0};

    strncpy(key.tgid, tgid, INT_LEN);
    key.startup_ts = get_proc_startup_ts(strtol(tgid, NULL, 10));

    if (key.startup_ts == 0) {
        return NULL;
    }

    H_FIND(*(mgr->tgids), &key, sizeof(TGID_RecordKey), record);
    return record;
}

static void tgid_record_set_cmdline(TGID_Record *record, int pid)
{
    struct java_property_s java_prop;
    int ret;

    if (strcmp(record->comm, "java") == 0) {
        memset(&java_prop, 0, sizeof(java_prop));
        ret = get_java_property(pid, &java_prop);
        if (ret == 0) {
            (void)snprintf(record->cmdline, sizeof(record->cmdline), "%s", java_prop.mainClassName);
        } else {
            (void)get_proc_cmdline(pid, record->cmdline, sizeof(record->cmdline));
        }
    } else {
        (void)get_proc_cmdline(pid, record->cmdline, sizeof(record->cmdline));
    }
}

static void tgid_record_set_container_info(TGID_Record *record, IMDB_DataBaseMgr *mgr)
{
    char container_id[CONTAINER_ABBR_ID_LEN + 1];
    struct container_cache *con_cache = NULL;
    int ret;

    container_id[0] = 0;
    ret = get_container_id_by_pid_cpuset(record->key.tgid, container_id, CONTAINER_ABBR_ID_LEN + 1);
    if (ret == 0) {
        strncpy(record->container_id, container_id, CONTAINER_ABBR_ID_LEN);
    }
    // add container cache and pod cache
    if (container_id[0]) {
        con_cache = lkup_container_cache(mgr->container_caches, container_id);
        if (!con_cache) {
            con_cache = create_container_cache(&mgr->container_caches, container_id);
        }
    }
    if (con_cache && con_cache->pod_id[0]) {
        if (!lkup_pod_cache(mgr->pod_caches, con_cache->pod_id)) {
            (void)create_pod_cache(&mgr->pod_caches, con_cache->pod_id, con_cache->container_id);
        }
    }
}

static TGID_Record* IMDB_TgidCreateRecord(IMDB_DataBaseMgr *mgr, const char* tgid)
{
    int ret;
    int pid;
    u64 startup_ts;
    char comm[TASK_COMM_LEN + 1];
    TGID_Record *record;

    comm[0] = 0;
    pid = strtol(tgid, NULL, 10);

    ret = get_proc_comm(pid, comm, TASK_COMM_LEN + 1);
    if (ret) {
        return NULL;
    }

    startup_ts = get_proc_startup_ts(pid);
    if (startup_ts == 0) {
        return NULL;
    }

    record = (TGID_Record *)malloc(sizeof(TGID_Record));
    if (record == NULL) {
        return NULL;
    }
    (void)memset(record, 0, sizeof(TGID_Record));
    record->key.startup_ts = startup_ts;
    strncpy(record->key.tgid, tgid, INT_LEN);
    strncpy(record->comm, comm, TASK_COMM_LEN);
    tgid_record_set_cmdline(record, pid);
    tgid_record_set_container_info(record, mgr);

    IMDB_TgidAddRecord(mgr, record);
    return record;
}

void IMDB_deleteAndFreeTgids(TGID_Record **tgids)
{
    if (tgids == NULL)  {
        return;
    }

    TGID_Record *r, *tmp;
    H_ITER(*tgids, r, tmp) {
        HASH_DEL(*tgids, r);
        free(r);
    }
    return;
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

    if (mgr->tgids != NULL) {
        IMDB_deleteAndFreeTgids(mgr->tgids);
        free(mgr->tgids);
        mgr->tgids = NULL;
    }

    if (mgr->container_caches != NULL) {
        free_container_caches(&mgr->container_caches);
    }
    if (mgr->pod_caches != NULL) {
        free_pod_caches(&mgr->pod_caches);
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

IMDB_Table *IMDB_DataBaseMgrFindTable(IMDB_DataBaseMgr *mgr, const char *tableName)
{
    for (int i = 0; i < mgr->tablesNum; i++) {
        if (strcmp(mgr->tables[i]->name, tableName) == 0) {
            return mgr->tables[i];
        }
    }

    return NULL;
}

static int IMDB_DataBaseMgrParseContent(IMDB_DataBaseMgr *mgr, IMDB_Table *table,
                                        IMDB_Record *record, const char *content, char needKey)
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
    strsep(&buffer, delim);
    for (token = strsep(&buffer, delim); token != NULL; token = strsep(&buffer, delim)) {
        if (strcmp(token, "\n") == 0)
            break;

        if (strcmp(token, "") == 0) {
            if (index == 0) {
                ERROR("[IMDB] Key can't be null(%s).\n", buffer);
                goto ERR;
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

IMDB_Record* IMDB_DataBaseMgrCreateRec(IMDB_DataBaseMgr *mgr, IMDB_Table *table, const char *content)
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

// return 0 if satisfy, return -1 if not
static int MetricTypeSatisfyPrometheus(IMDB_Metric *metric)
{
    const char prometheusTypes[][MAX_IMDB_METRIC_TYPE_LEN] = {
        "counter",
        "gauge",
        "histogram",
        "summary"
    };

    size_t size = sizeof(prometheusTypes) / sizeof(prometheusTypes[0]);
    for (size_t i = 0; i < size; i++) {
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
    if (strcasecmp(metric->name, META_FIELD_NAME_PROC) == 0) {
        return 1;
    }
    return 0;
}

static int MetricNameIsContainerId(IMDB_Metric *metric)
{
    if (strcasecmp(metric->name, META_FIELD_NAME_CONTAINER_ID) == 0) {
        return 1;
    }
    return 0;
}

#if 1

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
    int ret;
    size_t len;
    char *p = buffer;
    int size = (int)maxLen;
    time_t now;
    const char *fmt = "{%s} %s %lld\n";  // Metrics##labels MetricsVal timestamp

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

static int append_pod_level_labels(struct container_cache *con_cache, char **buffer_ptr, int *size_ptr,
                                   IMDB_DataBaseMgr *mgr, IMDB_Table *table, char type_json)
{
    int ret = 0;
    struct pod_cache *pod_cache = NULL;
    struct pod_label_cache *pod_label_cache = NULL;
    struct pod_label_elem *pod_label;
    int i;
    const char *fmt = type_json ? ",\"%s\":\"%s\"" : ",%s=\"%s\"";
    const char *podname_fmt = type_json ? ",\"%s\":\"%s/%s\"" : ",%s=\"%s/%s\"";

    if (con_cache->pod_id[0] == 0) {
        return 0;
    }
    pod_cache = lkup_pod_cache(mgr->pod_caches, con_cache->pod_id);
    if (!pod_cache) {
        pod_cache = create_pod_cache(&mgr->pod_caches, con_cache->pod_id, con_cache->container_id);
        if (!pod_cache) {
            DEBUG("[IMDB] Failed to create pod cache(pod_id=%s)\n", con_cache->pod_id);
            return 0;
        }
    }

    ret = __snprintf(buffer_ptr, *size_ptr, size_ptr, fmt,
        META_COMMON_LABEL_POD_ID, pod_cache->pod_id);
    if (ret < 0) {
        return IMDB_BUFFER_FULL;
    }
    ret = __snprintf(buffer_ptr, *size_ptr, size_ptr, podname_fmt,
        META_COMMON_LABEL_POD_NAME, pod_cache->pod_namespace, pod_cache->pod_name);
    if (ret < 0) {
        return IMDB_BUFFER_FULL;
    }
    ret = __snprintf(buffer_ptr, *size_ptr, size_ptr, fmt,
        META_COMMON_LABEL_POD_NAMESPACE, pod_cache->pod_namespace);
    if (ret < 0) {
        return IMDB_BUFFER_FULL;
    }

    // append user-defined pod labels
#define __POD_LABEL_DEFAULT_VAL "not found"
    (void)pthread_rwlock_rdlock(&table->ext_label_conf.rwlock);
    for (i = 0; i < table->ext_label_conf.pod_label_num; i++) {
        pod_label = &table->ext_label_conf.pod_labels[i];
        pod_label_cache = lkup_pod_label_cache(pod_cache->pod_labels, pod_label->key);

        if (pod_label_cache) {
            ret = __snprintf(buffer_ptr, *size_ptr, size_ptr, fmt,
                pod_label->key, pod_label_cache->val);
        } else {
            ret = __snprintf(buffer_ptr, *size_ptr, size_ptr, fmt,
                pod_label->key, __POD_LABEL_DEFAULT_VAL);
        }
        if (ret < 0) {
            (void)pthread_rwlock_unlock(&table->ext_label_conf.rwlock);
            return IMDB_BUFFER_FULL;
        }
    }
    (void)pthread_rwlock_unlock(&table->ext_label_conf.rwlock);

    return 0;
}

static int append_container_level_labels(const char *container_id, char **buffer_ptr, int *size_ptr,
    IMDB_DataBaseMgr *mgr, IMDB_Table *table, char is_con_id_appended, char type_json)
{
    int ret = 0;
    struct container_cache *con_cache = NULL;
    const char *fmt = type_json ? ",\"%s\":\"%s\"" : ",%s=\"%s\"";

    if (!container_id || container_id[0] == 0) {
        return 0;
    }
    con_cache = lkup_container_cache(mgr->container_caches, container_id);
    if (!con_cache) {
        con_cache = create_container_cache(&mgr->container_caches, container_id);
        if (!con_cache) {
            DEBUG("[IMDB] Failed to create container cache(container_id=%s)\n", container_id);
            return 0;
        }
    }

    if (!is_con_id_appended) {
        ret = __snprintf(buffer_ptr, *size_ptr, size_ptr, fmt,
            META_COMMON_LABEL_CONTAINER_ID, con_cache->container_id);
        if (ret < 0) {
            return IMDB_BUFFER_FULL;
        }
    }
    ret = __snprintf(buffer_ptr, *size_ptr, size_ptr, fmt,
        META_COMMON_LABEL_CONTAINER_NAME, con_cache->container_name);
    if (ret < 0) {
        return IMDB_BUFFER_FULL;
    }

    ret = __snprintf(buffer_ptr, *size_ptr, size_ptr, fmt,
        META_COMMON_LABEL_CONTAINER_IMAGE, con_cache->container_image);
    if (ret < 0) {
        return IMDB_BUFFER_FULL;
    }

    ret = append_pod_level_labels(con_cache, buffer_ptr, size_ptr, mgr, table, type_json);
    if (ret < 0) {
        DEBUG("[IMDB] Failed to append pod-level labels(pod_id=%s)\n", con_cache->pod_id);
        return ret;
    }

    return 0;
}

static int append_proc_level_labels(const char *tgid_str, char **buffer_ptr, int *size_ptr,
                                    IMDB_DataBaseMgr *mgr, IMDB_Table *table, char type_json)
{
    TGID_Record *tgidRecord;
    int ret = 0;
    const char *cmd_fmt = type_json ? ",\"%s\":\"%s\"" : ",%s=\"%s\"";
    const char *stime_fmt = type_json ? ",\"%s\":%llu" : ",%s=\"%llu\"";

    tgidRecord = IMDB_TgidLkupRecord(mgr, tgid_str);
    if (tgidRecord == NULL) {
        tgidRecord = IMDB_TgidCreateRecord(mgr, tgid_str);
    }
    if (tgidRecord == NULL) {
        DEBUG("[IMDB] Failed to create tgid cache(tgid=%s)\n", tgid_str);
        return IMDB_BUILD_ERR;
    }

    ret = __snprintf(buffer_ptr, *size_ptr, size_ptr, cmd_fmt,
        META_COMMON_LABEL_PROC_COMM, tgidRecord->comm);
    if (ret < 0) {
        return IMDB_BUFFER_FULL;
    }

    if (is_entity_proc(table->entity_name)) {
        ret = __snprintf(buffer_ptr, *size_ptr, size_ptr, cmd_fmt,
            META_PROC_LABEL_CMDLINE, tgidRecord->cmdline);
        if (ret < 0) {
            return IMDB_BUFFER_FULL;
        }
        ret = __snprintf(buffer_ptr, *size_ptr, size_ptr, stime_fmt,
            META_PROC_LABEL_START_TIME, tgidRecord->key.startup_ts);
        if (ret < 0) {
            return IMDB_BUFFER_FULL;
        }
    }

    ret = append_container_level_labels(tgidRecord->container_id, buffer_ptr, size_ptr, mgr, table, 0, type_json);
    if (ret < 0) {
        ERROR("[IMDB] Failed to append container-level labels(container_id=%s)\n", tgidRecord->container_id);
        return ret;
    }

    return 0;
}

static int append_custom_labels(IMDB_Table *table, char **buffer_ptr, int *size_ptr, char type_json)
{
    struct custom_label_elem *custom_label;
    int ret;
    int i;
    const char *fmt = type_json ? ",\"%s\":\"%s\"" : ",%s=\"%s\"";

    (void)pthread_rwlock_rdlock(&table->ext_label_conf.rwlock);
    for (i = 0; i < table->ext_label_conf.custom_label_num; i++) {
        custom_label = &table->ext_label_conf.custom_labels[i];
        ret = __snprintf(buffer_ptr, *size_ptr, size_ptr, fmt, custom_label->key, custom_label->val);
        if (ret < 0) {
            (void)pthread_rwlock_unlock(&table->ext_label_conf.rwlock);
            return IMDB_BUFFER_FULL;
        }
    }
    (void)pthread_rwlock_unlock(&table->ext_label_conf.rwlock);
    return 0;
}

static int append_machine_id_label(IMDB_DataBaseMgr *mgr, char **buffer_ptr, int *size_ptr, char type_json)
{
    int ret;
    const char *fmt = type_json ? ",\"%s\":\"%s-%s\"" : ",%s=\"%s-%s\"";

    if (mgr->nodeInfo.hostIP[0] == 0) {
        ret = get_system_ip(mgr->nodeInfo.hostIP, MAX_IMDB_HOSTIP_LEN);
        if (ret) {
            ERROR("[IMDB] Can not get system ip\n");
            return IMDB_BUILD_ERR;
        }
    }

    ret = __snprintf(buffer_ptr, *size_ptr, size_ptr, fmt,
                     META_COMMON_KEY_HOST_ID, mgr->nodeInfo.systemUuid, mgr->nodeInfo.hostIP);
    if (ret) {
        return IMDB_BUFFER_FULL;
    }
    return 0;
}

static int IMDB_BuildLabels(IMDB_DataBaseMgr *mgr,
                            IMDB_Record *record,
                            IMDB_Table *table,
                            char *buffer,
                            uint32_t maxLen,
                            char type_json)
{
    char *p = buffer;
    int ret;
    uint32_t size = maxLen;
    char first_flag = 1;
    int tgid_idx = -1;
    char *tgid_str = NULL;
    int con_id_idx = -1;
    char *con_id = NULL;
    int i;
    const char *first_fmt = type_json ? "\"%s\":\"%s\"" : "%s=\"%s\"";
    const char *fmt = type_json ? ",\"%s\":\"%s\"" : ",%s=\"%s\"";

    for (i = 0; i < record->metricsNum; i++) {
        if (MetricNameIsTgid(record->metrics[i]) == 1) {
            tgid_idx = i;
        }
        if (MetricNameIsContainerId(record->metrics[i])) {
            con_id_idx = i;
        }

        if (MetricTypeIsLabel(record->metrics[i]) == 0) {
            continue;
        }

        if (!strcmp(record->metrics[i]->val, INVALID_METRIC_VALUE)) {
            // ignore label whose value is (null)
            continue;
        }

        if (first_flag) {
            ret = __snprintf(&p, size, &size, first_fmt,
                            record->metrics[i]->name, record->metrics[i]->val);
        } else {
            ret = __snprintf(&p, size, &size, fmt,
                            record->metrics[i]->name, record->metrics[i]->val);
        }
        if (ret < 0) {
            return IMDB_BUFFER_FULL;
        }
        first_flag = 0;
    }

    // At least one key label needs to be filled.
    if (first_flag) {
        return IMDB_BUILD_ERR;
    }

    // Append 'COMM, Container and POD' label for ALL process-level metrics.
    if (tgid_idx >= 0) {
        tgid_str = (char *)(record->metrics[tgid_idx]->val);
        ret = append_proc_level_labels(tgid_str, &p, &size, mgr, table, type_json);
        if (ret < 0) {
            DEBUG("[IMDB] Failed to append process-level labels(tgid=%s, ret=%d)\n", tgid_str, ret);
            return ret;
        }
    }

    if (con_id_idx >= 0) {
        con_id = (char *)(record->metrics[con_id_idx]->val);
        ret = append_container_level_labels(con_id, &p, &size, mgr, table, 1, type_json);
        if (ret < 0) {
            DEBUG("[IMDB] Failed to append container-level labels(container_id=%s, ret=%d)\n", con_id, ret);
            return ret;
        }
    }

    ret = append_custom_labels(table, &p, &size, type_json);
    if (ret < 0) {
        ERROR("[IMDB] Failed to append custom labels(ret=%d)\n", ret);
        return ret;
    }

    ret = append_machine_id_label(mgr, &p, &size, type_json);
    if (ret < 0) {
        ERROR("[IMDB] Failed to append machine_id label(ret=%d)\n", ret);
        return ret;
    }

    return 0;
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
    size_t nameLen;
    int num_adjust = 0;
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

static int append_label(strbuf_t *labels_buf, const char *key, const char *val)
{
    int ret;
    int left_size;

    if (labels_buf->len == 0 || labels_buf->len >= labels_buf->size) {
        return -1;
    }

    left_size = labels_buf->size - labels_buf->len;
    ret = snprintf(labels_buf->buf + labels_buf->len, left_size, ",%s=\"%s\"", key, val);
    if (ret < 0 || ret >= left_size) {
        labels_buf->buf[labels_buf->len] = '\0';
        return -1;
    }
    labels_buf->len += ret;

    return 0;
}

#define __HISTO_LABEL_NAME      "le"
#define __HISTO_LABEL_VAL_INF   "+Inf"
static int append_label_histo_le(strbuf_t *labels_buf, u64 val)
{
    char buf[INT_LEN];
    buf[0] = 0;
    (void)snprintf(buf, sizeof(buf), "%llu", val);
    return append_label(labels_buf, __HISTO_LABEL_NAME, buf);
}

static int append_label_histo_le_inf(strbuf_t *labels_buf)
{
    return append_label(labels_buf, __HISTO_LABEL_NAME, __HISTO_LABEL_VAL_INF);
}

static int IMDB_BuildPrometheusHistoMetrics(const IMDB_Metric *metric, char *buffer, uint32_t maxLen,
    const char *entity_name, strbuf_t *labels_buf)
{
    int ret;
    size_t len;
    char *p = buffer;
    int size = (int)maxLen;
    int orig_labels_len;
    time_t now;
    const char *fmt = "{%s} %llu %lld\n";  // Metrics##labels MetricsVal timestamp

    struct histo_bucket_s *bkt = NULL;
    size_t bkt_sz = 0;
    u64 sum = 0, bkt_sum = 0;
    int i;

    ret = deserialize_histo(metric->val, &bkt, &bkt_sz, &bkt_sum);
    if (ret) {
        ERROR("[IMDB] Failed to deserialize histogram metric %s\n", metric->name);
        return -1;
    }

    (void)time(&now);
    for (i = 0; i < bkt_sz + 1; i++) {
        ret = IMDB_BuildMetrics(entity_name, metric->name, p, (uint32_t)size);
        if (ret < 0) {
            free(bkt);
            return ret;
        }
        len = strlen(p);
        p += len;
        size -= len;

        orig_labels_len = labels_buf->len;
        if (i == bkt_sz) {
            ret = append_label_histo_le_inf(labels_buf);
        } else {
            sum += bkt[i].count;
            ret = append_label_histo_le(labels_buf, bkt[i].max);
        }
        if (ret) {
            free(bkt);
            return -1;
        }

        ret = __snprintf(&p, size, &size, fmt, labels_buf->buf, sum, now * THOUSAND);
        if (ret < 0) {
            free(bkt);
            return ret;
        }

        // restore labels
        labels_buf->buf[orig_labels_len] = '\0';
        labels_buf->len = orig_labels_len;
    }
    free(bkt);

    return (int)((int)maxLen - size);   // Returns the number of printed characters
}

static int IMDB_Rec2Prometheus(IMDB_DataBaseMgr *mgr, IMDB_Record *record, IMDB_Table *table,
                               char *buffer, uint32_t maxLen)
{
    int ret = 0;
    int total = 0;
    char *curBuffer = buffer;
    uint32_t curMaxLen = maxLen;
    strbuf_t labels_buf;

    char labels[MAX_LABELS_BUFFER_SIZE] = {0};
    ret = IMDB_BuildLabels(mgr, record, table, labels, MAX_LABELS_BUFFER_SIZE, 0);
    if (ret < 0) {
        DEBUG("[IMDB] table of (%s) build label fail, ret: %d\n", table->entity_name, ret);
        return -1;
    }
    labels_buf.buf = labels;
    labels_buf.len = strlen(labels);
    labels_buf.size = MAX_LABELS_BUFFER_SIZE;

    for (int i = 0; i < record->metricsNum; i++) {
        ret = MetricTypeSatisfyPrometheus(record->metrics[i]);
        if (ret != 0) {
            continue;
        }

        if (!strcmp(record->metrics[i]->val, INVALID_METRIC_VALUE)) {
            // Do not report metric whose value is (null)
            continue;
        }

        if (strcmp(record->metrics[i]->type, "histogram") == 0) {
            ret = IMDB_BuildPrometheusHistoMetrics(record->metrics[i], curBuffer, curMaxLen, table->entity_name, &labels_buf);
        } else {
            ret = IMDB_BuildPrometheusMetrics(record->metrics[i], curBuffer, curMaxLen, table->entity_name, labels);
        }

        if (ret < 0) {
            break;  /* buffer is full, break loop */
        }

        curBuffer += ret;
        curMaxLen -= ret;
        total += ret;
    }

    return total;
}

static int IMDB_BuildJsonHistosBkt(const IMDB_Metric *metric, char **buffer, int *maxLen)
{
    int ret, i;
    char buf[INT_LEN];
    struct histo_bucket_s *bkt = NULL;
    size_t bkt_sz = 0;
    u64 count = 0, bkt_sum = 0;
    char first_flag = 1;

    ret = deserialize_histo(metric->val, &bkt, &bkt_sz, &bkt_sum);
    if (ret) {
        ERROR("[IMDB] Failed to deserialize histogram metric %s\n", metric->name);
        return IMDB_BUILD_ERR;
    }

    for (i = 0; i < bkt_sz; i++) {
        buf[0] = 0;
        (void)snprintf(buf, sizeof(buf), "%llu", bkt[i].max);
        count += bkt[i].count;
        if (first_flag) {
            ret = __snprintf(buffer, *maxLen, maxLen, "\"%s\":%llu", buf, count);
        } else {
            ret = __snprintf(buffer, *maxLen, maxLen, ",\"%s\":%llu", buf, count);
        }
        if (ret < 0) {
            free(bkt);
            return IMDB_BUFFER_FULL;
        }
        first_flag = 0;
    }

    free(bkt);
    ret = __snprintf(buffer, *maxLen, maxLen, ",\"count\":%llu,\"sum\":%llu}", count, bkt_sum);
    if (ret < 0) {
        return IMDB_BUFFER_FULL;
    }
    return 0;
}

static int IMDB_BuildJsonHistos(IMDB_DataBaseMgr *mgr, IMDB_Record *record, IMDB_Table *table,
                                char **buffer, int *maxLen)
{
    int ret = 0;
    char first_flag = 1;

    ret = __snprintf(buffer, *maxLen, maxLen, "%s", "\"histos\":{");
    if (ret) {
        return IMDB_BUFFER_FULL;
    }

    for (int i = 0; i < record->metricsNum; i++) {
        if (strcmp(record->metrics[i]->type, "histogram") != 0) {
            continue;
        }

        if (first_flag) {
            ret = __snprintf(buffer, *maxLen, maxLen, "\"%s\":{",
                            record->metrics[i]->name);
        } else {
            ret = __snprintf(buffer, *maxLen, maxLen, ",\"%s\":{",
                            record->metrics[i]->name);
        }
        if (ret < 0) {
            return IMDB_BUFFER_FULL;
        }
        ret = IMDB_BuildJsonHistosBkt(record->metrics[i], buffer, maxLen);
        if (ret < 0) {
            return ret;
        }
        first_flag = 0;
    }

    // histos is the last item, no need to add ","
    ret = __snprintf(buffer, *maxLen, maxLen, "%s", "}");
    if (ret) {
        return IMDB_BUFFER_FULL;
    }

    return 0;
}

static int IMDB_BuildJsonMetrics(IMDB_DataBaseMgr *mgr, IMDB_Record *record, IMDB_Table *table,
                                 char **buffer, int *maxLen)
{
    int ret = 0;
    char first_flag = 1;

    ret = __snprintf(buffer, *maxLen, maxLen, "%s", "\"metrics\":{");
    if (ret) {
        return IMDB_BUFFER_FULL;
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

        if (strcmp(record->metrics[i]->type, "histogram") == 0) {
            // skip histogram type metrics
            continue;
        }

        if (first_flag) {
            ret = __snprintf(buffer, *maxLen, maxLen, "\"%s\":\"%s\"",
                            record->metrics[i]->name, record->metrics[i]->val);
        } else {
            ret = __snprintf(buffer, *maxLen, maxLen, ",\"%s\":\"%s\"",
                            record->metrics[i]->name, record->metrics[i]->val);
        }
        if (ret < 0) {
            return IMDB_BUFFER_FULL;
        }
        first_flag = 0;
    }

    ret = __snprintf(buffer, *maxLen, maxLen, "%s", "},");
    if (ret) {
        return IMDB_BUFFER_FULL;
    }

    return 0;
}

/*
 * output format like:
 *  {
 *    "timestamp": 15869605860,
 *    "entity_name": "tcp_link",
 *    "table_name": "tcp_tx_rx",
 *    "labels": {
 *        "machine_id":"2c1c455d-24a5-897c-ea11-bc08f2d510da-192.168.128.123",
 *        "tgid":1123,
 *        "role":"server",
 *        "server_ip": "192.136.123.1",
 *        "container_id": "2c1c455d-24a5-897c-ea11-bc08f2d510da",
 *        "pod_id": "xxxxx"
 *    },
 *    "metrics": {
 *      "rx_bytes":1,
 *      "tx_bytes":2
 *   },
 *   "histos": {
 *      "srtt": {
 *          "50":1,
 *          "100":1
 *      }
 *   }
 *  }
*/
static int IMDB_Rec2Json(IMDB_DataBaseMgr *mgr, IMDB_Record *record, IMDB_Table *table,
                         char *buffer, uint32_t maxLen)
{
    int ret = 0;
    char *curBuffer = buffer;
    int curMaxLen = (int)maxLen;
    const char *fmt = "{\"timestamp\":%lld,\"entity_name\":\"%s\",\"table_name\":\"%s\",\"labels\":{";

    time_t now;
    (void)time(&now);
    ret = __snprintf(&curBuffer, curMaxLen, &curMaxLen, fmt, now * THOUSAND, table->entity_name, table->name);
    if (ret < 0)  {
        return 0;
    }

    ret = IMDB_BuildLabels(mgr, record, table, curBuffer, curMaxLen, 1);
    if (ret < 0)  {
        return (ret == IMDB_BUFFER_FULL) ? 0 : IMDB_BUILD_ERR;
    }
    curMaxLen -= strlen(curBuffer);
    curBuffer += strlen(curBuffer);

    ret = __snprintf(&curBuffer, curMaxLen, &curMaxLen, "%s", "},");
    if (ret < 0)  {
        return 0;
    }

    ret = IMDB_BuildJsonMetrics(mgr, record, table, &curBuffer, &curMaxLen);
    if (ret < 0)  {
        return (ret == IMDB_BUFFER_FULL) ? 0 : IMDB_BUILD_ERR;
    }

    ret = IMDB_BuildJsonHistos(mgr, record, table, &curBuffer, &curMaxLen);
    if (ret < 0)  {
        return (ret == IMDB_BUFFER_FULL) ? 0 : IMDB_BUILD_ERR;
    }

    // last "}" and LF
    ret = __snprintf(&curBuffer, curMaxLen, &curMaxLen, "%s", "}\n");
    if (ret < 0)  {
        return 0;
    }

    return (int)(maxLen - curMaxLen);
}

static int IMDB_Tbl2Metrics(IMDB_DataBaseMgr *mgr, IMDB_Table *table, char *buffer, uint32_t maxLen)
{
    int ret = 0;
    int total = 0;
    IMDB_Record *record, *tmp;
    char *curBuffer = buffer;
    uint32_t curMaxLen = maxLen;
    uint32_t period_records = DEFAULT_PERIOD_RECORD_NUM;
    uint32_t index = 0;

#define __RESERVED_BUF_SIZE 2
    if (curMaxLen < __RESERVED_BUF_SIZE) {
        return 0;
    }
    curMaxLen -= __RESERVED_BUF_SIZE;

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

        if (mgr->writeLogsType == METRIC_LOG_JSON) {
            ret = IMDB_Rec2Json(mgr, record, table, curBuffer, curMaxLen);
        } else {
            ret = IMDB_Rec2Prometheus(mgr, record, table, curBuffer, curMaxLen);
        }

        if (ret < 0) {
            // if build label fail, we just delete record
            HASH_deleteRecord(table->records, record);
            IMDB_RecordDestroy(record);
            continue;
        }
        if (ret == 0) {
            curBuffer[0] = 0;
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

    if (total == 0) {   // no record written
        return 0;
    }

    if (mgr->writeLogsType == METRIC_LOG_JSON) {
        return total;
    }

    curMaxLen += __RESERVED_BUF_SIZE;
    ret = snprintf(curBuffer, curMaxLen, "\n");
    if (ret < 0 || ret >= curMaxLen) {
        ERROR("[IMDB] table(%s) add endsym fail, ret=%d.\n", table->name, ret);
        return -1;
    }
    curBuffer += 1;
    curMaxLen -= 1;
    total += 1;

    return total;
}

int IMDB_DataBase2Metrics(IMDB_DataBaseMgr *mgr, char *buffer, uint32_t maxLen, uint32_t *buf_len)
{
    pthread_rwlock_wrlock(&mgr->rwlock);

    int ret = 0;
    char *cursor = buffer;
    uint32_t curMaxLen = maxLen;

    for (int i = 0; i < mgr->tablesNum; i++) {
        ret = IMDB_Tbl2Metrics(mgr, mgr->tables[i], cursor, curMaxLen);
        if (ret < 0 || ret >= curMaxLen) {
            ERROR("[IMDB] Failed to transfer tables to prometheus, ret=%d.\n", ret);
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

int IMDB_Record2Json(const IMDB_DataBaseMgr *mgr, const IMDB_Table *table, const IMDB_Record *record,
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

    ret = snprintf(json_cursor, maxLen, "%s", "}");
    if (ret < 0) {
        return -1;
    }

    return 0;
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
