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

#include "kafka.h"
#include "test_kafka.h"

#define KAFKA_BROKER "localhost:9092"
#define KAFKA_TOPIC "gala_gopher"
#define KAFKA_BATCH_NUM_MESSAGES 10000
#define KAFKA_QUEUE_BUFFER_MESSAGES 100000
#define KAFKA_QUEUE_BUFFER_KBYTES 1048576
#define KAFKA_QUEUE_BUFFER_MS 5
#define KAFKA_ERR 1
ConfigMgr *configMgr = NULL;

static void TestKafkaMgrCreate(void)
{
    KafkaMgr *mgr = KafkaMgrCreate(configMgr, "kafka_topic");

    CU_ASSERT(mgr != NULL);
    CU_ASSERT(strcmp(mgr->kafkaBroker, KAFKA_BROKER) == 0);
    CU_ASSERT(strcmp(mgr->kafkaTopic, KAFKA_TOPIC) == 0);
}

static void TestKafkaMsgProduce(void)
{
    uint32_t ret = 0;
    char msg[] = "deadbeaf";
    KafkaMgr *mgr = KafkaMgrCreate(configMgr, "kafka_topic");
    CU_ASSERT(mgr != NULL);

    ret = KafkaMsgProduce(mgr, msg, strlen(msg));
    CU_ASSERT(ret == 0);
}

int init_config()
{
    configMgr = (ConfigMgr *)malloc(sizeof(ConfigMgr));
    if (configMgr == NULL) {
        return KAFKA_ERR;
    }
    configMgr->kafkaConfig = (KafkaConfig *)malloc(sizeof(KafkaConfig));
    if (configMgr->kafkaConfig == NULL) {
        return KAFKA_ERR;
    }

    (void)strncpy(configMgr->kafkaConfig->broker, KAFKA_BROKER, MAX_KAFKA_BROKER_LEN - 1);
    (void)strncpy(configMgr->metricOutConfig->kafka_topic, KAFKA_TOPIC, MAX_KAFKA_TOPIC_LEN - 1);
    configMgr->kafkaConfig->batchNumMessages = KAFKA_BATCH_NUM_MESSAGES;
    (void)strncpy(configMgr->kafkaConfig->compressionCodec, "none", KAFKA_COMPRESSION_CODEC_LEN - 1);
    configMgr->kafkaConfig->queueBufferingMaxMessages = KAFKA_QUEUE_BUFFER_MESSAGES;
    configMgr->kafkaConfig->queueBufferingMaxKbytes = KAFKA_QUEUE_BUFFER_KBYTES;
    configMgr->kafkaConfig->queueBufferingMaxMs = KAFKA_QUEUE_BUFFER_MS;

    return 0;
}

void delete_config()
{
    free(configMgr->kafkaConfig);
    free(configMgr);
}


void TestKafkaMain(CU_pSuite suite)
{
    if (init_config() != 0) {
        printf("test_kafka init_config failed.\n");
        return;
    }
    CU_ADD_TEST(suite, TestKafkaMgrCreate);
    CU_ADD_TEST(suite, TestKafkaMsgProduce);
    delete_config();
}

