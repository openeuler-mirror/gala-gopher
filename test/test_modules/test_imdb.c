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
 * Create: 2021-04-26
 * Description: provide gala-gopher test
 ******************************************************************************/
#include <stdint.h>
#include <CUnit/Basic.h>

#include "imdb.h"
#include "test_imdb.h"

#if GALA_GOPHER_INFO("test cases")
static void TestIMDB_MetricCreate(void);
static void TestIMDB_MetricSetValue(void);
static void TestIMDB_RecordCreate(void);
static void TestIMDB_RecordCreateWithKey(void);
static void TestIMDB_RecordAddMetric(void);
static void TestIMDB_TableCreate(void);
static void TestIMDB_TableSetMeta(void);
static void TestIMDB_TableAddRecord(void);
static void TestIMDB_DataBaseMgrCreate(void);
static void TestIMDB_TableAddRecord(void);
static void TestIMDB_DataBaseMgrFindTable(void);
static void TestIMDB_DataBaseMgrAddRecord(void);
static void TestIMDB_DataBaseMgrData2String(void);
static void TestIMDB_RecordAppendKey(void);
static void TestHASH_addRecord(void);
static void TestHASH_deleteRecord(void);
static void TestIMDB_TableSetRecordKeySize(void);
#endif

static void TestIMDB_MetricCreate(void)
{
    IMDB_Metric *metric = IMDB_MetricCreate("aa", "bb", "cc");
    CU_ASSERT(metric != NULL);
    CU_ASSERT(strcmp(metric->name, "aa") == 0);
    CU_ASSERT(strcmp(metric->description, "bb") == 0);
    CU_ASSERT(strcmp(metric->type, "cc") == 0);

    IMDB_MetricDestroy(metric);
}

static void TestIMDB_MetricSetValue(void)
{
    int ret = 0;
    IMDB_Metric *metric = IMDB_MetricCreate("aa", "bb", "cc");
    CU_ASSERT(metric != NULL);

    ret = IMDB_MetricSetValue(metric, "dd");
    CU_ASSERT(ret == 0);
    CU_ASSERT(strcmp(metric->val, "dd") == 0);

    IMDB_MetricDestroy(metric);
}

static void TestIMDB_RecordCreate(void)
{
    IMDB_Record *record = IMDB_RecordCreate(1024);
    CU_ASSERT(record != NULL);
    CU_ASSERT(record->metrics != NULL);
    CU_ASSERT(record->metricsCapacity == 1024);
    CU_ASSERT(record->metricsNum == 0);
    CU_ASSERT(record->key == NULL);
    CU_ASSERT(record->keySize == 0);

    IMDB_RecordDestroy(record);
}

static void TestIMDB_RecordCreateWithKey(void)
{
    IMDB_Record *record = IMDB_RecordCreateWithKey(1024, MAX_IMDB_METRIC_VAL_LEN * 1);
    CU_ASSERT(record != NULL);
    CU_ASSERT(record->metrics != NULL);
    CU_ASSERT(record->metricsCapacity == 1024);
    CU_ASSERT(record->metricsNum == 0);
    CU_ASSERT(record->key != NULL);
    CU_ASSERT(record->keySize == MAX_IMDB_METRIC_VAL_LEN * 1);

    IMDB_RecordDestroy(record);
}

static void TestIMDB_RecordAddMetric(void)
{
    int ret = 0;
    IMDB_Record *record = IMDB_RecordCreate(1024);
    CU_ASSERT(record != NULL);

    IMDB_Metric *metric = IMDB_MetricCreate("aa", "bb", "cc");
    CU_ASSERT(metric != NULL);

    ret = IMDB_RecordAddMetric(record, metric);
    CU_ASSERT(ret == 0);
    CU_ASSERT(record->metricsNum == 1);
    CU_ASSERT(record->metrics[0] == metric);

    IMDB_RecordDestroy(record);
}

static void TestIMDB_TableCreate(void)
{
    IMDB_Table *table = IMDB_TableCreate("table1", 1024);
    CU_ASSERT(table != NULL);
    CU_ASSERT(table->records != NULL);
    CU_ASSERT(*table->records == NULL);
    CU_ASSERT(table->recordKeySize == 0);
    CU_ASSERT(table->recordsCapability == 1024);
    CU_ASSERT(strcmp(table->name, "table1") == 0);
    CU_ASSERT(table->meta == NULL);

    IMDB_TableDestroy(table);
}

static void TestIMDB_TableSetMeta(void)
{
    int ret = 0;
    IMDB_Table *table = IMDB_TableCreate("table1", 1024);
    CU_ASSERT(table != NULL);

    IMDB_Record *record = IMDB_RecordCreate(1024);
    CU_ASSERT(record != NULL);

    IMDB_Metric *metric = IMDB_MetricCreate("aa", "bb", "cc");
    CU_ASSERT(metric != NULL);

    ret = IMDB_RecordAddMetric(record, metric);
    CU_ASSERT(ret == 0);

    ret = IMDB_TableSetMeta(table, record);
    CU_ASSERT(ret == 0);
    CU_ASSERT(table->meta == record);

    IMDB_TableDestroy(table);
}

static void TestIMDB_TableAddRecord(void)
{
    int ret = 0;
    IMDB_Table *table = IMDB_TableCreate("table1", 1024);
    CU_ASSERT(table != NULL);

    IMDB_Record *record = IMDB_RecordCreateWithKey(1024, MAX_IMDB_METRIC_VAL_LEN * 1);
    CU_ASSERT(record != NULL);

    ret = IMDB_RecordAppendKey(record, 0, "record_key");
    CU_ASSERT(ret == 0);

    IMDB_Metric *metric = IMDB_MetricCreate("aa", "bb", "cc");
    CU_ASSERT(metric != NULL);

    ret = IMDB_RecordAddMetric(record, metric);
    CU_ASSERT(ret == 0);

    ret = IMDB_TableAddRecord(table, record);
    CU_ASSERT(ret == 0);
    CU_ASSERT(HASH_recordCount(table->records) == 1);
    CU_ASSERT(HASH_findRecord(table->records, record) == record);

    IMDB_TableDestroy(table);
}

static void TestIMDB_DataBaseMgrCreate(void)
{
    IMDB_DataBaseMgr *mgr = IMDB_DataBaseMgrCreate(1024);
    CU_ASSERT(mgr != NULL);
    CU_ASSERT(mgr->tables != NULL);
    CU_ASSERT(mgr->tblsCapability == 1024);
    CU_ASSERT(mgr->tablesNum == 0);

    IMDB_DataBaseMgrDestroy(mgr);
}

static void TestIMDB_DataBaseMgrAddTable(void)
{
    int ret = 0;
    IMDB_DataBaseMgr *mgr = IMDB_DataBaseMgrCreate(1024);
    CU_ASSERT(mgr != NULL);

    IMDB_Table *table = IMDB_TableCreate("table1", 1024);
    CU_ASSERT(table != NULL);

    ret = IMDB_DataBaseMgrAddTable(mgr, table);
    CU_ASSERT(ret == 0);
    CU_ASSERT(mgr->tablesNum == 1);
    CU_ASSERT(mgr->tables[0] == table);

    IMDB_DataBaseMgrDestroy(mgr);
}

static void TestIMDB_DataBaseMgrFindTable(void)
{
    int ret = 0;
    IMDB_DataBaseMgr *mgr = IMDB_DataBaseMgrCreate(1024);
    CU_ASSERT(mgr != NULL);

    IMDB_Table *table = IMDB_TableCreate("table1", 1024);
    CU_ASSERT(table != NULL);

    ret = IMDB_DataBaseMgrAddTable(mgr, table);
    CU_ASSERT(ret == 0);

    IMDB_Table *tmpTable = IMDB_DataBaseMgrFindTable(mgr, "table1");
    CU_ASSERT(tmpTable == table);

    IMDB_DataBaseMgrDestroy(mgr);
}

static void TestIMDB_DataBaseMgrAddRecord(void)
{
    int ret = 0;
    IMDB_DataBaseMgr *mgr = IMDB_DataBaseMgrCreate(1024);
    CU_ASSERT(mgr != NULL);

    IMDB_Table *table = IMDB_TableCreate("table1", 1024);
    CU_ASSERT(table != NULL);

    IMDB_Record *meta = IMDB_RecordCreate(1024);
    CU_ASSERT(meta != NULL);
    IMDB_Metric *metric1 = IMDB_MetricCreate("metric1", "desc1", "key");
    CU_ASSERT(metric1 != NULL);
    ret = IMDB_RecordAddMetric(meta, metric1);
    CU_ASSERT(ret == 0);
    IMDB_Metric *metric2 = IMDB_MetricCreate("metric2", "desc2", "key");
    CU_ASSERT(metric2 != NULL);
    ret = IMDB_RecordAddMetric(meta, metric2);
    CU_ASSERT(ret == 0);
    IMDB_Metric *metric3 = IMDB_MetricCreate("metric3", "desc3", "type3");
    CU_ASSERT(metric3 != NULL);
    ret = IMDB_RecordAddMetric(meta, metric3);
    CU_ASSERT(ret == 0);

    ret = IMDB_TableSetMeta(table, meta);
    CU_ASSERT(ret == 0);

    ret = IMDB_TableSetRecordKeySize(table, 2);
    CU_ASSERT(ret == 0);

    ret = IMDB_DataBaseMgrAddTable(mgr, table);
    CU_ASSERT(ret == 0);

    char recordStr[] = "|table1|value1|value2|value3|";
    ret = IMDB_DataBaseMgrAddRecord(mgr, recordStr);
    CU_ASSERT(ret == 0);
    CU_ASSERT(table->records[0]->metricsNum == 3);
    CU_ASSERT(strcmp(table->records[0]->metrics[0]->name, "metric1") == 0);
    CU_ASSERT(strcmp(table->records[0]->metrics[0]->description, "desc1") == 0);
    CU_ASSERT(strcmp(table->records[0]->metrics[0]->type, "key") == 0);
    CU_ASSERT(strcmp(table->records[0]->metrics[0]->val, "value1") == 0);

    CU_ASSERT(strcmp(table->records[0]->metrics[1]->name, "metric2") == 0);
    CU_ASSERT(strcmp(table->records[0]->metrics[1]->description, "desc2") == 0);
    CU_ASSERT(strcmp(table->records[0]->metrics[1]->type, "key") == 0);
    CU_ASSERT(strcmp(table->records[0]->metrics[1]->val, "value2") == 0);

    CU_ASSERT(strcmp(table->records[0]->metrics[2]->name, "metric3") == 0);
    CU_ASSERT(strcmp(table->records[0]->metrics[2]->description, "desc3") == 0);
    CU_ASSERT(strcmp(table->records[0]->metrics[2]->type, "type3") == 0);
    CU_ASSERT(strcmp(table->records[0]->metrics[2]->val, "value3") == 0);

    IMDB_DataBaseMgrDestroy(mgr);
}

static void TestIMDB_DataBaseMgrData2String(void)
{
    int ret = 0;
    IMDB_DataBaseMgr *mgr = IMDB_DataBaseMgrCreate(1024);
    CU_ASSERT(mgr != NULL);

    IMDB_Table *table = IMDB_TableCreate("table1", 1024);
    CU_ASSERT(table != NULL);

    IMDB_Record *meta = IMDB_RecordCreate(1024);
    CU_ASSERT(meta != NULL);
    IMDB_Metric *metric1 = IMDB_MetricCreate("metric1", "desc1", "key");
    CU_ASSERT(metric1 != NULL);
    ret = IMDB_RecordAddMetric(meta, metric1);
    CU_ASSERT(ret == 0);
    IMDB_Metric *metric2 = IMDB_MetricCreate("metric2", "desc2", "type2");
    CU_ASSERT(metric2 != NULL);
    ret = IMDB_RecordAddMetric(meta, metric2);
    CU_ASSERT(ret == 0);

    ret = IMDB_TableSetMeta(table, meta);
    CU_ASSERT(ret == 0);

    ret = IMDB_TableSetRecordKeySize(table, 1);
    CU_ASSERT(ret == 0);

    ret = IMDB_DataBaseMgrAddTable(mgr, table);
    CU_ASSERT(ret == 0);

    char recordStr[] = "|table1|value1|value2|\n";
    ret = IMDB_DataBaseMgrAddRecord(mgr, recordStr);
    CU_ASSERT(ret == 0);

    char buffer[2048] = {0};
    int buf_len;
    ret = IMDB_DataBase2Prometheus(mgr, buffer, 2048, &buf_len);
    CU_ASSERT(ret >= 0);
    printf("DatabaseMgr2String: \n");
    printf("%s", buffer);

    IMDB_DataBaseMgrDestroy(mgr);
}

static void TestIMDB_RecordAppendKey(void)
{
    int ret = 0;
    IMDB_Record *record = IMDB_RecordCreateWithKey(1024, MAX_IMDB_METRIC_VAL_LEN * 2);
    CU_ASSERT(record != NULL);

    char *key[] = {"key1", "key2", "key3"};
    ret = IMDB_RecordAppendKey(record, 0, key[0]);
    CU_ASSERT(ret == 0);
    CU_ASSERT(strcmp(record->key, key[0]) == 0);

    ret = IMDB_RecordAppendKey(record, 1, key[1]);
    CU_ASSERT(ret == 0);
    CU_ASSERT(strcmp(record->key + MAX_IMDB_METRIC_VAL_LEN, key[1]) == 0);

    ret = IMDB_RecordAppendKey(record, 2, key[2]);
    CU_ASSERT(ret != 0);

    IMDB_RecordDestroy(record);
}

static void TestHASH_addRecord(void)
{
    int ret = 0;
    IMDB_Record **records = (IMDB_Record **)malloc(sizeof(IMDB_Record *));
    CU_ASSERT(records != NULL);
    *records = NULL;
    IMDB_Record *record = IMDB_RecordCreateWithKey(1024, MAX_IMDB_METRIC_VAL_LEN * 1);
    CU_ASSERT(record != NULL);
    IMDB_Record *another_record = IMDB_RecordCreateWithKey(1024, MAX_IMDB_METRIC_VAL_LEN * 1);
    CU_ASSERT(another_record != NULL);

    ret = IMDB_RecordAppendKey(record, 0, "key");
    CU_ASSERT(ret == 0);

    ret = IMDB_RecordAppendKey(another_record, 0, "key");
    CU_ASSERT(ret == 0);

    HASH_addRecord(records, record);
    CU_ASSERT(HASH_recordCount(records) == 1);
    CU_ASSERT(HASH_findRecord(records, another_record) == record);

    IMDB_RecordDestroy(another_record);
    HASH_deleteAndFreeRecords(records);
    free(records);
}

static void TestHASH_deleteRecord(void)
{
    int ret = 0;
    IMDB_Record **records = (IMDB_Record **)malloc(sizeof(IMDB_Record *));
    CU_ASSERT(records != NULL);
    *records = NULL;
    IMDB_Record *record = IMDB_RecordCreateWithKey(1024, MAX_IMDB_METRIC_VAL_LEN * 1);
    CU_ASSERT(record != NULL);
    IMDB_Record *another_record = IMDB_RecordCreateWithKey(1024, MAX_IMDB_METRIC_VAL_LEN * 1);
    CU_ASSERT(another_record != NULL);

    ret = IMDB_RecordAppendKey(record, 0, "key1");
    CU_ASSERT(ret == 0);

    ret = IMDB_RecordAppendKey(another_record, 0, "key2");
    CU_ASSERT(ret == 0);

    HASH_addRecord(records, record);
    CU_ASSERT(HASH_recordCount(records) == 1);

    HASH_addRecord(records, another_record);
    CU_ASSERT(HASH_recordCount(records) == 2);

    HASH_deleteRecord(records, record);
    CU_ASSERT(HASH_recordCount(records) == 1);

    HASH_deleteRecord(records, another_record);
    CU_ASSERT(HASH_recordCount(records) == 0);

    IMDB_RecordDestroy(record);
    IMDB_RecordDestroy(another_record);
    free(records);
}

static void TestIMDB_TableSetRecordKeySize(void)
{
    int ret = 0;
    IMDB_Table *table = IMDB_TableCreate("table1", 1024);
    CU_ASSERT(table != NULL);

    ret = IMDB_TableSetRecordKeySize(table, 10);
    CU_ASSERT(ret == 0);
    CU_ASSERT(table->recordKeySize == 10 * MAX_IMDB_METRIC_VAL_LEN);

    IMDB_TableDestroy(table);
}

void TestIMDBMain(CU_pSuite suite)
{
    CU_ADD_TEST(suite, TestIMDB_MetricCreate);
    CU_ADD_TEST(suite, TestIMDB_MetricSetValue);
    CU_ADD_TEST(suite, TestIMDB_RecordCreate);
    CU_ADD_TEST(suite, TestIMDB_RecordCreateWithKey);
    CU_ADD_TEST(suite, TestIMDB_RecordAddMetric);
    CU_ADD_TEST(suite, TestIMDB_TableCreate);
    CU_ADD_TEST(suite, TestIMDB_TableSetMeta);
    CU_ADD_TEST(suite, TestIMDB_TableAddRecord);
    CU_ADD_TEST(suite, TestIMDB_DataBaseMgrCreate);
    CU_ADD_TEST(suite, TestIMDB_DataBaseMgrAddTable);
    CU_ADD_TEST(suite, TestIMDB_DataBaseMgrFindTable);
    CU_ADD_TEST(suite, TestIMDB_DataBaseMgrAddRecord);
    CU_ADD_TEST(suite, TestIMDB_DataBaseMgrData2String);
    CU_ADD_TEST(suite, TestIMDB_RecordAppendKey);
    CU_ADD_TEST(suite, TestHASH_addRecord);
    CU_ADD_TEST(suite, TestHASH_deleteRecord);
    CU_ADD_TEST(suite, TestIMDB_TableSetRecordKeySize);
}

