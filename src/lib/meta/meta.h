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
#ifndef __META_H__
#define __META_H__

#pragma once

#include <stdint.h>
#include "base.h"
#ifdef KAFKA_CHANNEL
#include "kafka.h"
#include "probe_mng.h"
#endif

#define META_FIELD_TYPE_KEY                 "key"
#define META_FIELD_TYPE_LABEL               "label"

#define META_FIELD_NAME_PROC                "tgid"
#define META_FIELD_NAME_CONTAINER_ID        "container_id"

#define META_COMMON_KEY_HOST_ID             "machine_id"
#define META_COMMON_LABEL_HOST_NAME         "hostname"
#define META_COMMON_LABEL_PROC_COMM         "comm"
#define META_COMMON_LABEL_CONTAINER_ID      "container_id"
#define META_COMMON_LABEL_CONTAINER_NAME    "container_name"
#define META_COMMON_LABEL_CONTAINER_IMAGE   "container_image"
#define META_COMMON_LABEL_POD_ID            "pod_id"
#define META_COMMON_LABEL_POD_NAME          "pod"
#define META_COMMON_LABEL_POD_NAMESPACE     "pod_namespace"

#define ENTITY_PROC                         "proc"
#define META_PROC_LABEL_CMDLINE             "cmdline"
#define META_PROC_LABEL_START_TIME          "start_time"
#define ENTITY_CONTAINER                    "container"

typedef struct {
    char description[MAX_FIELD_DESCRIPTION_LEN];
    char type[MAX_FIELD_TYPE_LEN];
    char name[MAX_FIELD_NAME_LEN];
} Field;

typedef struct {
    char entity[MAX_MEASUREMENT_NAME_LEN];
    char name[MAX_MEASUREMENT_NAME_LEN];
    char version[MAX_META_VERSION_LEN];
    uint32_t fieldsNum;
    Field fields[MAX_FIELDS_NUM];
} Measurement;

typedef struct {
    uint32_t measurementsCapability;
    uint32_t measurementsNum;

    uint32_t fields_num_max;

    Measurement **measurements;

#ifdef KAFKA_CHANNEL
    KafkaMgr *meta_kafkaMgr;
#endif
    // metadata output
    OutChannelType meta_out_channel;

    pthread_t tid;

} MeasurementMgr;

MeasurementMgr *MeasurementMgrCreate(uint32_t measurementsCapability, uint32_t fields_num_max);
void MeasurementMgrDestroy(MeasurementMgr *mgr);

int MeasurementMgrLoad(const MeasurementMgr *mgr, const char *metaDir);
int MeasurementMgrLoadSingleMeta(MeasurementMgr *mgr, const char *metaPath);

int ReportMetaDataMain(const MeasurementMgr *mgr);
int is_entity_proc(const char *entity_name);
int is_entity_container(const char *entity_name);

#endif

