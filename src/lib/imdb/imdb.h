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

#define MAX_IMDB_DATABASEMGR_CAPACITY   256
// metric specification
#define MAX_IMDB_METRIC_DESC_LEN        1024
#define MAX_IMDB_METRIC_TYPE_LEN        32
#define MAX_IMDB_METRIC_NAME_LEN        32
#define MAX_IMDB_METRIC_VAL_LEN         512

// table specification
#define MAX_IMDB_TABLE_NAME_LEN         32

// database specification
#define MAX_IMDB_DATABASE_NAME_LEN      32

// MAX LENGTH FOR PROMETHEUS LABELS
#define MAX_LABELS_BUFFER_SIZE 512

#define MAX_IMDB_SYSTEM_UUID_LEN        40
#define MAX_IMDB_HOSTNAME_LEN           64
#define MAX_IMDB_HOSTIP_LEN             64

#define METRIC_TYPE_LABEL "label"
#define METRIC_TYPE_KEY "key"

#define THOUSAND        1000

#define INVALID_METRIC_VALUE "(null)"

// NUMS OF RECORD TO STRING EVERY PERIOD
#define DEFAULT_PERIOD_RECORD_NUM       100

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
    char val[MAX_IMDB_METRIC_VAL_LEN];
} IMDB_Metric;

typedef struct {
    uint32_t keySize;
    char *key;
    time_t updateTime;     // Unit: second
    uint32_t metricsCapacity;       // Capability for metrics count in one record
    uint32_t metricsNum;
    IMDB_Metric **metrics;
    UT_hash_handle hh;
} IMDB_Record;

typedef struct {
    char name[MAX_IMDB_TABLE_NAME_LEN];
    char entity_name[MAX_IMDB_TABLE_NAME_LEN];
    IMDB_Record *meta;
    char weighting;                 // 0: Highest Level(Entitlement to priority); >0: Low priority
    char pad[3];                    // rsvd
    uint32_t recordsCapability;     // Capability for records count in one table
    uint32_t recordKeySize;
    IMDB_Record **records;
} IMDB_Table;

typedef struct {
    char tgid[INT_LEN + 1];
    int startup_ts;
} TGID_RecordKey;

typedef struct {
    TGID_RecordKey key;
    char container_id[CONTAINER_ABBR_ID_LEN + 1];
    char pod_id[POD_ID_LEN + 1];
    char comm[TASK_COMM_LEN + 1];
    H_HANDLE;
} TGID_Record;

typedef struct {
    uint32_t tblsCapability;        // Capability for tables count in one database
    uint32_t tablesNum;

    IMDB_Table **tables;
    IMDB_NodeInfo nodeInfo;
    pthread_rwlock_t rwlock;
    uint32_t writeLogsOn;

    TGID_Record **tgids;

    pthread_t metrics_tid;
} IMDB_DataBaseMgr;

IMDB_Metric *IMDB_MetricCreate(char *name, char *description, char *type);
int IMDB_MetricSetValue(IMDB_Metric *metric, char *val);
void IMDB_MetricDestroy(IMDB_Metric *metric);

IMDB_Record *IMDB_RecordCreate(uint32_t capacity);
IMDB_Record *IMDB_RecordCreateWithKey(uint32_t capacity, uint32_t keySize);
int IMDB_RecordAddMetric(IMDB_Record *record, IMDB_Metric *metric);
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
int IMDB_TableSetMeta(IMDB_Table *table, IMDB_Record *metaRecord);
int IMDB_TableSetRecordKeySize(IMDB_Table *table, uint32_t keyNum);
int IMDB_TableAddRecord(IMDB_Table *table, IMDB_Record *record);
void IMDB_TableDestroy(IMDB_Table *table);

IMDB_DataBaseMgr *IMDB_DataBaseMgrCreate(uint32_t capacity);
void IMDB_DataBaseMgrSetRecordTimeout(uint32_t timeout);
void IMDB_DataBaseMgrDestroy(IMDB_DataBaseMgr *mgr);

int IMDB_DataBaseMgrAddTable(IMDB_DataBaseMgr *mgr, IMDB_Table* table);
IMDB_Table *IMDB_DataBaseMgrFindTable(IMDB_DataBaseMgr *mgr, char *tableName);

int IMDB_DataBaseMgrAddRecord(IMDB_DataBaseMgr *mgr, char *recordStr);
IMDB_Record* IMDB_DataBaseMgrCreateRec(IMDB_DataBaseMgr *mgr, IMDB_Table *table, char *content);
int IMDB_DataBase2Prometheus(IMDB_DataBaseMgr *mgr, char *buffer, uint32_t maxLen, uint32_t *buf_len);
int IMDB_DataStr2Json(IMDB_DataBaseMgr *mgr, const char *recordStr, char *jsonStr, uint32_t jsonStrLen);
int IMDB_Rec2Json(IMDB_DataBaseMgr *mgr, IMDB_Table *table,
                        IMDB_Record* rec, const char *dataStr, char *jsonStr, uint32_t jsonStrLen);

void WriteMetricsLogsMain(IMDB_DataBaseMgr *mgr);
int ReadMetricsLogs(char logs_file_name[]);
void RemoveMetricsLogs(char logs_file_name[]);

#endif

