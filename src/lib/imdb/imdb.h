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
#ifndef __IMDB_H__
#define __IMDB_H__

#pragma once

#include <stdint.h>
#include <pthread.h>

#include "base.h"
#include "hash.h"
#include "ext_label.h"
#include "container_cache.h"

#define MAX_IMDB_DATABASEMGR_CAPACITY   256
// metric specification
#define MAX_IMDB_METRIC_DESC_LEN        1024
#define MAX_IMDB_METRIC_TYPE_LEN        32
#define MAX_IMDB_METRIC_NAME_LEN        32
#define MAX_IMDB_METRIC_VAL_LEN         128

// table specification
#define MAX_IMDB_TABLE_NAME_LEN         32

// database specification
#define MAX_IMDB_DATABASE_NAME_LEN      32

// MAX LENGTH FOR PROMETHEUS LABELS
#define MAX_LABELS_BUFFER_SIZE          1024

#define MAX_IMDB_SYSTEM_UUID_LEN        40
#define MAX_IMDB_HOSTNAME_LEN           64
#define MAX_IMDB_HOSTIP_LEN             64

#define METRIC_TYPE_LABEL "label"
#define METRIC_TYPE_KEY "key"

#define THOUSAND        1000

#define INVALID_METRIC_VALUE "(null)"

// NUMS OF RECORD TO STRING EVERY PERIOD
#define DEFAULT_PERIOD_RECORD_NUM       100

typedef enum {
    METRIC_LOG_NULL = 0,
    METRIC_LOG_PROM,
    METRIC_LOG_JSON,

    METRIC_LOG_MAX
} MetricLogType;

typedef struct {
    char systemUuid[MAX_IMDB_SYSTEM_UUID_LEN];
    char hostName[MAX_IMDB_HOSTNAME_LEN];
    char hostIP[MAX_IMDB_HOSTIP_LEN];
} IMDB_NodeInfo;

typedef struct {
    char description[MAX_IMDB_METRIC_DESC_LEN];
    // MetricType type;
    char type[MAX_IMDB_METRIC_TYPE_LEN];
    char name[MAX_IMDB_METRIC_NAME_LEN];
} IMDB_Metric;

typedef struct {
    char val[MAX_IMDB_METRIC_VAL_LEN];
} IMDB_MetricValue;

struct IMDB_Table_s;
typedef struct IMDB_Table_s IMDB_Table;
typedef struct {
    char *key;
    time_t updateTime;     // Unit: second
    IMDB_MetricValue **value;
    const IMDB_Table *table;     // table that this record belongs to
    UT_hash_handle hh;
} IMDB_Record;

typedef struct {
    uint32_t metricsCapacity;       // Capability for metrics count in one record
    IMDB_Metric **metrics;
} IMDB_Meta;

typedef struct IMDB_Table_s {
    char name[MAX_IMDB_TABLE_NAME_LEN];
    char entity_name[MAX_IMDB_TABLE_NAME_LEN];
    IMDB_Meta *meta;
    char weighting;                 // 0: Highest Level(Entitlement to priority); >0: Low priority
    char pad[3];                    // rsvd
    uint32_t recordsCapability;     // Capability for records count in one table
    uint32_t recordKeySize;
    IMDB_Record **records;
    struct ext_label_conf ext_label_conf;
} IMDB_Table;

typedef struct {
    char tgid[INT_LEN + 1];
    u64 startup_ts;
} TGID_RecordKey;

typedef struct {
    TGID_RecordKey key;
    char container_id[CONTAINER_ABBR_ID_LEN + 1];
    char comm[TASK_COMM_LEN + 1];
    char cmdline[PROC_CMDLINE_LEN];
    H_HANDLE;
} TGID_Record;

typedef struct {
    uint32_t tblsCapability;        // Capability for tables count in one database
    uint32_t tablesNum;

    IMDB_Table **tables;
    IMDB_NodeInfo nodeInfo;
    pthread_rwlock_t rwlock;
    MetricLogType writeLogsType;

    TGID_Record **tgids;
    struct container_cache *container_caches;
    struct pod_cache *pod_caches;

    pthread_t metrics_tid;
} IMDB_DataBaseMgr;

IMDB_Metric *IMDB_MetricCreate(char *name, char *description, char *type);
void IMDB_MetricDestroy(IMDB_Metric *metric);

IMDB_Meta *IMDB_MetaCreate(uint32_t capacity);
void IMDB_MetaDestroy(IMDB_Meta *meta);

IMDB_Record *IMDB_RecordCreateWithTable(const IMDB_Table *table);
int IMDB_RecordAppendKey(IMDB_Record *record, uint32_t keyIdx, char *val);
void IMDB_RecordUpdateTime(IMDB_Record *record, time_t seconds);
void IMDB_RecordDestroy(IMDB_Record *record);

IMDB_Record *HASH_findRecord(const IMDB_Record **records, const IMDB_Record *record);
void HASH_deleteRecord(IMDB_Record **records, IMDB_Record *record);
void HASH_deleteAndFreeRecords(IMDB_Record **records);
void HASH_addRecord(IMDB_Record **records, IMDB_Record *record);
uint32_t HASH_recordCount(const IMDB_Record **records);

IMDB_Table *IMDB_TableCreate(char *name, uint32_t capacity);
void IMDB_TableSetEntityName(IMDB_Table *table, char *entity_name);
void IMDB_TableSetMeta(IMDB_Table *table, IMDB_Meta *meta);
int IMDB_TableSetRecordKeySize(IMDB_Table *table, uint32_t keyNum);
int IMDB_TableAddRecord(IMDB_Table *table, IMDB_Record *record);
void IMDB_TableUpdateExtLabelConf(IMDB_Table *table, struct ext_label_conf *conf);
void IMDB_TableDestroy(IMDB_Table *table);

IMDB_DataBaseMgr *IMDB_DataBaseMgrCreate(uint32_t capacity);
void IMDB_DataBaseMgrSetRecordTimeout(uint32_t timeout);
void IMDB_DataBaseMgrDestroy(IMDB_DataBaseMgr *mgr);

int IMDB_DataBaseMgrAddTable(IMDB_DataBaseMgr *mgr, IMDB_Table* table);
IMDB_Table *IMDB_DataBaseMgrFindTable(IMDB_DataBaseMgr *mgr, const char *tableName);

IMDB_Record* IMDB_DataBaseMgrCreateRec(IMDB_DataBaseMgr *mgr, IMDB_Table *table, const char *content);
int IMDB_DataBase2Metrics(IMDB_DataBaseMgr *mgr, char *buffer, uint32_t maxLen, uint32_t *buf_len);
int IMDB_DataStr2Json(IMDB_DataBaseMgr *mgr, const char *recordStr, char *jsonStr, uint32_t jsonStrLen);
int IMDB_Record2Json(const IMDB_DataBaseMgr *mgr, const IMDB_Table *table, const IMDB_Record *record,
                     char *jsonStr, uint32_t jsonStrLen);

void WriteMetricsLogsMain(IMDB_DataBaseMgr *mgr);
int ReadMetricsLogs(char logs_file_name[]);
void RemoveMetricsLogs(char logs_file_name[]);

#endif

