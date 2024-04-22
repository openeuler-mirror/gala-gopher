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
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <libconfig.h>
#include "logs.h"
#include "meta.h"

#if GALA_GOPHER_INFO("inner func")
static Measurement *MeasurementCreate(void);
static void MeasurementDestroy(Measurement *mm);
static int MeasurementMgrAdd(MeasurementMgr *mgr, Measurement *measurement);
static Measurement *MeasurementMgrGet(MeasurementMgr *mgr, const char *name);
#endif

static Measurement *MeasurementCreate(void)
{
    Measurement *mm = NULL;
    mm = (Measurement *)malloc(sizeof(Measurement));
    if (mm == NULL)
        return NULL;

    memset(mm, 0, sizeof(Measurement));
    return mm;
}

static void MeasurementDestroy(Measurement *mm)
{
    if (mm == NULL)
        return;

    free(mm);
    return;
}

MeasurementMgr *MeasurementMgrCreate(uint32_t measurementsCapability, uint32_t fields_num_max)
{
    MeasurementMgr *mgr = NULL;
    mgr = (MeasurementMgr *)malloc(sizeof(MeasurementMgr));
    if (mgr == NULL) {
        return NULL;
    }
    memset(mgr, 0, sizeof(MeasurementMgr));

    mgr->measurements = (Measurement **)malloc(sizeof(Measurement *) * measurementsCapability);
    if (mgr->measurements == NULL) {
        free(mgr);
        return NULL;
    }
    memset(mgr->measurements, 0, sizeof(Measurement *) * measurementsCapability);
    mgr->measurementsCapability = measurementsCapability;
    mgr->fields_num_max = fields_num_max < MAX_FIELDS_NUM ? fields_num_max : MAX_FIELDS_NUM;

    return mgr;
}

void MeasurementMgrDestroy(MeasurementMgr *mgr)
{
    if (mgr == NULL)
        return;

    for (int i = 0; i < mgr->measurementsNum; i++) {
        if (mgr->measurements[i] != NULL)
            MeasurementDestroy(mgr->measurements[i]);
    }

    free(mgr->measurements);
    free(mgr);
    return;
}

static int MeasurementMgrAdd(MeasurementMgr *mgr, Measurement *measurement)
{
    Measurement *mm = NULL;
    mm = MeasurementMgrGet(mgr, measurement->name);
    if (mm != NULL)
        return -1;

    if (mgr->measurementsNum == mgr->measurementsCapability) {
        return -1;
    }
    mgr->measurements[mgr->measurementsNum] = measurement;
    mgr->measurementsNum++;
    return 0;
}

static Measurement *MeasurementMgrGet(MeasurementMgr *mgr, const char *name)
{
    for (int i = 0; i < mgr->measurementsNum; i++) {
        if (strcmp(mgr->measurements[i]->name, name) == 0)
            return mgr->measurements[i];
    }

    return NULL;
}

static int FieldLoad(Field *field, config_setting_t *fieldConfig)
{
    int ret = 0;
    const char *token;

    memset(field, 0, sizeof(Field));
    ret = config_setting_lookup_string(fieldConfig, "description", &token);
    if (ret == 0) {
        ERROR("load field description failed.\n");
        return -1;
    }
    (void)strncpy(field->description, token, MAX_FIELD_DESCRIPTION_LEN - 1);

    ret = config_setting_lookup_string(fieldConfig, "type", &token);
    if (ret == 0) {
        ERROR("load field type failed.\n");
        return -1;
    }
    (void)strncpy(field->type, token, MAX_FIELD_TYPE_LEN - 1);

    ret = config_setting_lookup_string(fieldConfig, "name", &token);
    if (ret == 0) {
        ERROR("load field name failed.\n");
        return -1;
    }
    (void)strncpy(field->name, token, MAX_FIELD_NAME_LEN - 1);

    return 0;
}

static int MeasurementLoad(MeasurementMgr *mgr, Measurement *mm, config_setting_t *mmConfig)
{
    int ret = 0;
    const char *name;
    const char *entity;
    const char *field;
    ret = config_setting_lookup_string(mmConfig, "table_name", &name);
    if (ret == 0) {
        ERROR("load measurement name failed.\n");
        return -1;
    }
    (void)snprintf(mm->name, sizeof(mm->name), "%s", name);

    ret = config_setting_lookup_string(mmConfig, "entity_name", &entity);
    if (ret == 0) {
        ERROR("load measurement entity failed.\n");
        return -1;
    }
    (void)snprintf(mm->entity, sizeof(mm->entity), "%s", entity);

#if LIBCONFIG_VER_MAJOR == 1 && LIBCONFIG_VER_MINOR < 5
    config_setting_t *fields = config_lookup_from(mmConfig, "fields");
#else
    config_setting_t *fields = config_setting_lookup(mmConfig, "fields");
#endif
    int fieldsCount = config_setting_length(fields);
    if (fieldsCount > mgr->fields_num_max) {
        ERROR("Too many fields.\n");
        return -1;
    }

    for (int i = 0; i < fieldsCount; i++) {
        config_setting_t *fieldConfig = config_setting_get_elem(fields, i);

        ret = FieldLoad(&mm->fields[i], fieldConfig);
        if (ret != 0)
            ERROR("[META] load measurement field failed.\n");

        mm->fieldsNum++;
    }

    return 0;
}

int MeasurementMgrLoadSingleMeta(MeasurementMgr *mgr, const char *metaPath)
{
    int ret = 0;
    config_t cfg;
    config_setting_t *measurements = NULL;
    const char *version = NULL;

    char *name = NULL;
    char *field = NULL;

    INFO("[META] begin load meta: %s.\n", metaPath);

    config_init(&cfg);
    ret = config_read_file(&cfg, metaPath);
    if (ret == 0) {
        ERROR("[META] config read file %s failed.\n", metaPath);
        config_destroy(&cfg);
        return -1;
    }

    ret = config_lookup_string(&cfg, "version", &version);
    if (ret <= 0) {
        ERROR("[META] get version failed.\n");
        config_destroy(&cfg);
        return -1;
    }

    measurements = config_lookup(&cfg, "measurements");
    if (measurements == NULL) {
        ERROR("[META] get measurements failed.\n");
        config_destroy(&cfg);
        return -1;
    }

    int count = config_setting_length(measurements);
    for (int i = 0; i < count; i++) {
        config_setting_t *measurement = config_setting_get_elem(measurements, i);

        Measurement *mm = MeasurementCreate();
        if (mm == NULL) {
            ERROR("[META] malloc measurement failed.\n");
            config_destroy(&cfg);
            return -1;
        }
        (void)memset(mm->version, 0, MAX_META_VERSION_LEN);
        (void)strncpy(mm->version, version, MAX_META_VERSION_LEN - 1);

        ret = MeasurementLoad(mgr, mm, measurement);
        if (ret != 0) {
            ERROR("[META] load_measurement failed.\n");
            config_destroy(&cfg);
            MeasurementDestroy(mm);
            return -1;
        }

        ret = MeasurementMgrAdd(mgr, mm);
        if (ret != 0) {
            ERROR("[META] Add measurements failed.\n");
            config_destroy(&cfg);
            MeasurementDestroy(mm);
            return -1;
        }
    }

    config_destroy(&cfg);
    return 0;
}

int MeasurementMgrLoad(const MeasurementMgr *mgr, const char *metaDir)
{
    int ret = 0;
    DIR *d = NULL;
    char metaPath[MAX_META_PATH_LEN] = {0};

    d = opendir(metaDir);
    if (d == NULL) {
        ERROR("open meta directory failed.\n");
        return -1;
    }

    struct dirent *file = readdir(d);
    while (file != NULL) {
        // skip current dir, parent dir and hidden files
        if (strncmp(file->d_name, ".", 1) == 0) {
            file = readdir(d);
            continue;
        }

        memset(metaPath, 0, sizeof(metaPath));
        (void)snprintf(metaPath, MAX_META_PATH_LEN - 1, "%s/%s", metaDir, file->d_name);
        ret = MeasurementMgrLoadSingleMeta((MeasurementMgr *)mgr, metaPath);
        if (ret != 0) {
            ERROR("[META] load single meta file failed. meta file: %s\n", metaPath);
            closedir(d);
            return -1;
        }

        file = readdir(d);
    }

    closedir(d);
    return 0;
}

#if GALA_GOPHER_INFO("report_meta_to_kafka func")
static int metadata_build_timestamp(char *json_str, int max_len)
{
    char *str = json_str;
    int str_len = max_len;
    time_t now;
    const char *fmt = "{\"timestamp\": %lld";    // "timestamp": 1655211859000

    (void)time(&now);
    if (__snprintf(&str, str_len, &str_len, fmt, now * THOUSAND) < 0) {
        return -1;
    }
    return max_len > str_len ? (max_len - str_len) : -1;
}

static int metadata_build_metaname(const Measurement *mm, char *json_str, int max_len)
{
    char *str = json_str;
    int str_len = max_len;
    const char *fmt = ", \"meta_name\": \"%s\""; // "meta_name": "block",

    if (__snprintf(&str, str_len, &str_len, fmt, mm->name) < 0) {
        return -1;
    }
    return max_len > str_len ? (max_len - str_len) : -1;
}

static int metadata_build_entityname(const Measurement *mm, char *json_str, int max_len)
{
    char *str = json_str;
    int str_len = max_len;
    const char *fmt = ", \"entity_name\": \"%s\""; // "entity_name": "block",

    if (__snprintf(&str, str_len, &str_len, fmt, mm->entity) < 0) {
        return -1;
    }
    return max_len > str_len ? (max_len - str_len) : -1;
}

static int metadata_build_vrsion(const Measurement *mm, char *json_str, int max_len)
{
    char *str = json_str;
    int str_len = max_len;
    const char *fmt = ", \"version\": \"%s\""; // "version": "1.0.0",

    if (__snprintf(&str, str_len, &str_len, fmt, mm->version) < 0) {
        return -1;
    }
    return max_len > str_len ? (max_len - str_len) : -1;
}

/* "keys": ["machine_id", "tgid"] */
static int metadata_build_keys(const Measurement *mm, char *json_str, int max_len)
{
    int i, ret;
    char *str = json_str;
    int str_len = max_len;
    int total_len = 0;

    ret = snprintf(str, str_len, ", \"keys\": [\"%s\"", META_COMMON_KEY_HOST_ID);
    if (ret < 0 || ret >= str_len) {
        return -1;
    }
    str += ret;
    str_len -= ret;
    total_len += ret;

    for (i = 0; i < mm->fieldsNum; i++) {
        if (strcmp(mm->fields[i].type, META_FIELD_TYPE_KEY) == 0) {
            ret = snprintf(str, str_len, ", \"%s\"", mm->fields[i].name);
            if (ret < 0 || ret >= str_len) {
                return -1;
            }
            str += ret;
            str_len -= ret;
            total_len += ret;
        }
    }
    ret = snprintf(str, str_len, "]");
    if (ret < 0 || ret >= str_len) {
        return -1;
    }
    total_len += ret;

    return total_len;
}

static int is_proc_level(const Measurement *mm)
{
    int i;

    for (i = 0; i < mm->fieldsNum; i++) {
        if (strcmp(mm->fields[i].type, META_FIELD_TYPE_KEY) != 0 &&
            strcmp(mm->fields[i].type, META_FIELD_TYPE_LABEL) != 0) {
            continue;
        }
        if (strcasecmp(mm->fields[i].name, META_FIELD_NAME_PROC) == 0) {
            return 1;
        }
    }

    return 0;
}

/* "labels": ["hostname", "blk_type", "comm"] */
static int metadata_build_labels(const Measurement *mm, char *json_str, int max_len)
{
    int i, ret;
    char *str = json_str;
    int str_len = max_len;
    int total_len = 0;

    ret = snprintf(str, str_len, ", \"labels\": [\"%s\"", META_COMMON_LABEL_HOST_NAME);
    if (ret < 0 || ret >= str_len) {
        return -1;
    }
    str += ret;
    str_len -= ret;
    total_len += ret;

    for (i = 0; i < mm->fieldsNum; i++) {
        if (strcmp(mm->fields[i].type, META_FIELD_TYPE_LABEL) == 0) {
            ret = snprintf(str, str_len, ", \"%s\"", mm->fields[i].name);
            if (ret < 0 || ret >= str_len) {
                return -1;
            }
            str += ret;
            str_len -= ret;
            total_len += ret;
        }
    }

    if (is_proc_level(mm)) {
        ret = snprintf(str, str_len, ", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\"",
            META_COMMON_LABEL_PROC_COMM, META_COMMON_LABEL_CONTAINER_ID,
            META_COMMON_LABEL_CONTAINER_NAME, META_COMMON_LABEL_CONTAINER_IMAGE,
            META_COMMON_LABEL_POD_ID, META_COMMON_LABEL_POD_NAME, META_COMMON_LABEL_POD_NAMESPACE);
        if (ret < 0 || ret >= str_len) {
            return -1;
        }
        str += ret;
        str_len -= ret;
        total_len += ret;
    }

    if (is_entity_proc(mm->entity)) {
        ret = snprintf(str, str_len, ", \"%s\", \"%s\"",
            META_PROC_LABEL_CMDLINE, META_PROC_LABEL_START_TIME);
        if (ret < 0 || ret >= str_len) {
            return -1;
        }
        str += ret;
        str_len -= ret;
        total_len += ret;
    }

    if (is_entity_container(mm->entity)) {
        ret = snprintf(str, str_len, ", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\"",
            META_COMMON_LABEL_CONTAINER_NAME, META_COMMON_LABEL_CONTAINER_IMAGE,
            META_COMMON_LABEL_POD_ID, META_COMMON_LABEL_POD_NAME, META_COMMON_LABEL_POD_NAMESPACE);
        if (ret < 0 || ret >= str_len) {
            return -1;
        }
        str += ret;
        str_len -= ret;
        total_len += ret;
    }

    ret = snprintf(str, str_len, "]");
    if (ret < 0 || ret >= str_len) {
        return -1;
    }
    total_len += ret;

    return total_len;
}

static int is_filed_type_metric(char *field_type)
{
    int i;

    const char meta_fileld_type_metric[][MAX_FIELD_TYPE_LEN] = {
        "counter",
        "gauge"
    };
    size_t size = sizeof(meta_fileld_type_metric) / sizeof(meta_fileld_type_metric[0]);

    for (i = 0; i < size; i++) {
        if (strcmp(field_type, meta_fileld_type_metric[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

/* "metrics": ["rx_bytes", "tx_bytes"] */
static int metadata_build_metrics(const Measurement *mm, char *json_str, int max_len)
{
    int i, j, ret;
    char *str = json_str;
    int str_len = max_len;
    int total_len = 0;
    int first_metric = 1;

    ret = snprintf(str, str_len, ", \"metrics\": [");
    if (ret < 0 || ret >= str_len) {
        return -1;
    }
    str += ret;
    str_len -= ret;
    total_len += ret;

    for (i = 0; i < mm->fieldsNum; i++) {
        if (is_filed_type_metric((char *)mm->fields[i].type) == 0) {
            /* not metric, continue */
            continue;
        }
        if (first_metric == 1) {
            ret = snprintf(str, str_len, "\"%s\"", mm->fields[i].name);
            first_metric = 0;
        } else {
            ret = snprintf(str, str_len, ", \"%s\"", mm->fields[i].name);
        }
        if (ret < 0 || ret >= str_len) {
            return -1;
        }
        str += ret;
        str_len -= ret;
        total_len += ret;
    }

    ret = snprintf(str, str_len, "]}");
    if (ret < 0 || ret >= str_len) {
        return -1;
    }
    total_len += ret;

    return total_len;
}

static int metadata_to_json(const Measurement *mm, char *json_str, int max_json_len)
{
    int ret;
    char *str = json_str;
    int str_len = max_json_len;

    ret = metadata_build_timestamp(str, str_len);
    if (ret < 0) {
        return -1;
    }
    str += ret;
    str_len -= ret;

    ret = metadata_build_metaname(mm, str, str_len);
    if (ret < 0) {
        return -1;
    }
    str += ret;
    str_len -= ret;

    ret = metadata_build_entityname(mm, str, str_len);
    if (ret < 0) {
        return -1;
    }
    str += ret;
    str_len -= ret;

    ret = metadata_build_vrsion(mm, str, str_len);
    if (ret < 0) {
        return -1;
    }
    str += ret;
    str_len -= ret;

    ret = metadata_build_keys(mm, str, str_len);
    if (ret < 0) {
        return -1;
    }
    str += ret;
    str_len -= ret;

    ret = metadata_build_labels(mm, str, str_len);
    if (ret < 0) {
        return -1;
    }
    str += ret;
    str_len -= ret;

    ret = metadata_build_metrics(mm, str, str_len);
    if (ret < 0) {
        return -1;
    }
    str += ret;
    str_len -= ret;

    return 0;
}

static int report_one_metadata(const MeasurementMgr *mgr, const Measurement *mm)
{
    int ret;
    char *json_str = NULL;

    json_str = (char *)malloc(MAX_DATA_STR_LEN);
    if (json_str == NULL) {
        return -1;
    }
    json_str[0] = 0;

    ret = metadata_to_json(mm, json_str, MAX_DATA_STR_LEN);
    if (ret < 0) {
        ERROR("[META] metadata to json failed.\n");
        (void)free(json_str);
        return -1;
    }

#ifdef KAFKA_CHANNEL
    if (mgr->meta_out_channel == OUT_CHNL_KAFKA) {
        // Report meta to kafka
        KafkaMgr *meta_kafka = mgr->meta_kafkaMgr;
        if (meta_kafka == NULL) {
            ERROR("[META] kafka topic(metadata_topic) is NULL\n");
            (void)free(json_str);
            return -1;
        }
        (void)KafkaMsgProduce(meta_kafka, json_str, strlen(json_str));
        DEBUG("[META] kafka metadata_topic produce one data: %s\n", json_str);
    }
#endif

    if (mgr->meta_out_channel == OUT_CHNL_LOGS) {
        // Write meta to log
        wr_meta_logs(json_str);
        DEBUG("[META] write metadata to logs: %s\n", json_str);
        (void)free(json_str);
    }

    return 0;
}

static int ReportMeteData(const MeasurementMgr *mgr)
{
    Measurement *mm = NULL;
    int i, meta_num;

    if (mgr == NULL) {
        ERROR("[META] measurement mgr is NULL\n");
        return -1;
    }
    meta_num = mgr->measurementsNum;

    for (i = 0; i < meta_num; i++) {
        mm = mgr->measurements[i];
        if (report_one_metadata(mgr, mm) != 0) {
            ERROR("[META] report one metadata to kafka fail.\n");
            return -1;
        }
    }
    return 0;
}

#define TEM_MINUTES (10 * 60)
int ReportMetaDataMain(const MeasurementMgr *mgr)
{
    int ret;
    if (mgr->meta_out_channel == OUT_CHNL_NULL) {
        INFO("[META] metadata out channel is null, skip creating metadata report thread\n");
        return 0;
    }

    if (mgr->meta_out_channel != OUT_CHNL_LOGS && mgr->meta_out_channel != OUT_CHNL_KAFKA) {
        ERROR("[META] metadata out channel isn't logs or kafka, break.\n");
        return -1;
    }
#ifdef KAFKA_CHANNEL
    if (mgr->meta_out_channel == OUT_CHNL_KAFKA && mgr->meta_kafkaMgr == NULL) {
        ERROR("[META] metadata out channel is kafka but kafkaMgr is NULL, break.\n");
        return -1;
    }
#endif

    for (;;) {
        ret = ReportMeteData(mgr);
        if (ret < 0) {
            return -1;
        }
        sleep(TEM_MINUTES);
    }
}

int is_entity_proc(const char *entity_name)
{
    if (strcmp(entity_name, ENTITY_PROC) == 0) {
        return 1;
    }
    return 0;
}

int is_entity_container(const char *entity_name)
{
    if (strcmp(entity_name, ENTITY_CONTAINER) == 0) {
        return 1;
    }
    return 0;
}

#endif