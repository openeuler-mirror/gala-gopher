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
#ifndef __KAFKA_H__
#define __KAFKA_H__

#include <stdint.h>
#include <rdkafka.h>
#include "base.h"
#include "config.h"

typedef struct {
    char kafkaBroker[MAX_KAFKA_BROKER_LEN];
    char kafkaTopic[MAX_KAFKA_TOPIC_LEN];
    uint32_t batchNumMessages;
    char compressionCodec[KAFKA_COMPRESSION_CODEC_LEN];
    uint32_t queueBufferingMaxMessages;
    uint32_t queueBufferingMaxKbytes;
    uint32_t queueBufferingMaxMs;

    rd_kafka_t *rk;
    rd_kafka_topic_t *rkt;
    rd_kafka_conf_t *conf;
} KafkaMgr;

KafkaMgr *KafkaMgrCreate(const ConfigMgr *configMgr, const char *topic);
void KafkaMgrDestroy(KafkaMgr *mgr);

int KafkaMsgProduce(const KafkaMgr *mgr, char *msg, const uint32_t msgLen);

#endif

