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
#include <stdlib.h>
#include <stdint.h>
#include <CUnit/Basic.h>

#include "kafka.h"
#include "test_kafka.h"

#define KAFKA_BROKER "localhost:9092"
#define KAFKA_TOPIC "gala_gopher"
#define KAFKA_COMP_CODEC "none"
#define KAFKA_BATCH_NUM_MESSAGES 10000
#define KAFKA_QUEUE_BUFFER_MESSAGES 100000
#define KAFKA_QUEUE_BUFFER_KBYTES 1048576
#define KAFKA_QUEUE_BUFFER_MS 5
#define KAFKA_ERR 1

static ConfigMgr *init_kafka_config(void)
{
    ConfigMgr *configMgr = ConfigMgrCreate();
    if (configMgr == NULL) {
        return NULL;
    }

    (void)snprintf(configMgr->kafkaConfig->broker, sizeof(configMgr->kafkaConfig->broker), "%s", KAFKA_BROKER);
    (void)snprintf(configMgr->metricOutConfig->kafka_topic, sizeof(configMgr->metricOutConfig->kafka_topic), "%s", KAFKA_TOPIC);
    (void)snprintf(configMgr->kafkaConfig->compressionCodec, sizeof(configMgr->kafkaConfig->compressionCodec), "%s", KAFKA_COMP_CODEC);
    configMgr->kafkaConfig->batchNumMessages = KAFKA_BATCH_NUM_MESSAGES;
    configMgr->kafkaConfig->queueBufferingMaxMessages = KAFKA_QUEUE_BUFFER_MESSAGES;
    configMgr->kafkaConfig->queueBufferingMaxKbytes = KAFKA_QUEUE_BUFFER_KBYTES;
    configMgr->kafkaConfig->queueBufferingMaxMs = KAFKA_QUEUE_BUFFER_MS;

    return configMgr;
}


static void TestKafkaMsgProduce(void)
{
    uint32_t ret = 0;
    char *msg = (char *)malloc(10);
    snprintf(msg, 10, "%s", "deadbeef");

    ConfigMgr *configMgr = init_kafka_config();
    CU_ASSERT(configMgr != NULL);

    KafkaMgr *mgr = KafkaMgrCreate(configMgr, "kafka_topic");
    CU_ASSERT(mgr != NULL);

    ret = KafkaMsgProduce(mgr, msg, strlen(msg));
    CU_ASSERT(ret == 0);

    KafkaMgrDestroy(mgr);
    ConfigMgrDestroy(configMgr);
}


void TestKafkaMain(CU_pSuite suite)
{
    CU_ADD_TEST(suite, TestKafkaMsgProduce);
}

