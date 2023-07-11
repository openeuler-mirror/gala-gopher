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
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "kafka.h"

static void dr_msg_cb(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque)
{
    if (rkmessage->err) {
        ERROR("Message delivery failed: %s\n", rd_kafka_err2str(rkmessage->err));
    }/* rkmessage被librdkafka自动销毁 */
}

KafkaMgr *KafkaMgrCreate(const ConfigMgr *configMgr, const char *topic_type)
{
    rd_kafka_conf_res_t ret;
    KafkaMgr *mgr = NULL;
    char errstr[MAX_KAFKA_ERRSTR_SIZE];

    mgr = (KafkaMgr *)malloc(sizeof(KafkaMgr));
    if (mgr == NULL) {
        ERROR("malloc memory for egress_kafka_mgr failed.\n");
        return NULL;
    }
    memset(mgr, 0, sizeof(KafkaMgr));

    if (topic_type == NULL) {
        ERROR("input kafka topic_type NULL, please input valid topic type.\n");
        free(mgr);
        return NULL;
    }
    if (strcmp(topic_type, "kafka_topic") == 0) {
        /* metric topic */
        (void)snprintf(mgr->kafkaTopic, sizeof(mgr->kafkaTopic), "%s", configMgr->metricOutConfig->kafka_topic);
    } else if (strcmp(topic_type, "metadata_topic") == 0) {
        /* metadata topic */
        (void)snprintf(mgr->kafkaTopic, sizeof(mgr->kafkaTopic), "%s", configMgr->metaOutConfig->kafka_topic);
    } else if (strcmp(topic_type, "event_topic") == 0) {
        /* event topic */
        (void)snprintf(mgr->kafkaTopic, sizeof(mgr->kafkaTopic), "%s", configMgr->eventOutConfig->kafka_topic);
    } else {
        ERROR("input kafka topic_type(%s) error.\n", topic_type);
        free(mgr);
        return NULL;
    }

    (void)snprintf(mgr->kafkaBroker, sizeof(mgr->kafkaBroker), "%s", configMgr->kafkaConfig->broker);
    (void)snprintf(mgr->compressionCodec, sizeof(mgr->compressionCodec), "%s",
                   configMgr->kafkaConfig->compressionCodec);
    mgr->batchNumMessages = configMgr->kafkaConfig->batchNumMessages;
    mgr->queueBufferingMaxKbytes = configMgr->kafkaConfig->queueBufferingMaxKbytes;
    mgr->queueBufferingMaxMessages = configMgr->kafkaConfig->queueBufferingMaxMessages;
    mgr->queueBufferingMaxMs = configMgr->kafkaConfig->queueBufferingMaxMs;
    (void)snprintf(mgr->kafkaUsername, sizeof(mgr->kafkaUsername), "%s", configMgr->kafkaConfig->username);
    (void)snprintf(mgr->kafkaPassword, sizeof(mgr->kafkaPassword), "%s", configMgr->kafkaConfig->password);

    mgr->conf = rd_kafka_conf_new();
    ret = rd_kafka_conf_set(mgr->conf, "bootstrap.servers", mgr->kafkaBroker, errstr, sizeof(errstr));
    if (ret != RD_KAFKA_CONF_OK) {
        ERROR("set rdkafka bootstrap.servers failed(%s).\n", errstr);
        free(mgr);
        return NULL;
    }
    rd_kafka_conf_set_dr_msg_cb(mgr->conf, dr_msg_cb);

    char batchNumMessages[10] = {0};
    (void)snprintf(batchNumMessages, sizeof(batchNumMessages), "%u", mgr->batchNumMessages);
    ret = rd_kafka_conf_set(mgr->conf, "batch.num.messages", batchNumMessages, errstr, sizeof(errstr));
    if (ret != RD_KAFKA_CONF_OK) {
        ERROR("set rdkafka batch.num.messages failed(%s).\n", errstr);
        free(mgr);
        return NULL;
    }
    rd_kafka_conf_set_dr_msg_cb(mgr->conf, dr_msg_cb);

    ret = rd_kafka_conf_set(mgr->conf, "compression.codec", mgr->compressionCodec, errstr, sizeof(errstr));
    if (ret != RD_KAFKA_CONF_OK) {
        ERROR("set rdkafka compression.codec failed(%s).\n", errstr);
        free(mgr);
        return NULL;
    }
    rd_kafka_conf_set_dr_msg_cb(mgr->conf, dr_msg_cb);

    char queueBufferingMaxMessages[10] = {0};
    (void)snprintf(queueBufferingMaxMessages, sizeof(queueBufferingMaxMessages), "%u", mgr->queueBufferingMaxMessages);
    ret = rd_kafka_conf_set(mgr->conf, "queue.buffering.max.messages", queueBufferingMaxMessages, errstr, sizeof(errstr));
    if (ret != RD_KAFKA_CONF_OK) {
        ERROR("set rdkafka queue.buffering.max.messages failed(%s).\n", errstr);
        free(mgr);
        return NULL;
    }
    rd_kafka_conf_set_dr_msg_cb(mgr->conf, dr_msg_cb);

    char queueBufferingMaxKbytes[10] = {0};
    (void)snprintf(queueBufferingMaxKbytes, sizeof(queueBufferingMaxKbytes), "%u", mgr->queueBufferingMaxKbytes);
    ret = rd_kafka_conf_set(mgr->conf, "queue.buffering.max.kbytes", queueBufferingMaxKbytes, errstr, sizeof(errstr));
    if (ret != RD_KAFKA_CONF_OK) {
        ERROR("set rdkafka queue.buffering.max.kbytes failed(%s).\n", errstr);
        free(mgr);
        return NULL;
    }
    rd_kafka_conf_set_dr_msg_cb(mgr->conf, dr_msg_cb);

    char queueBufferingMaxMs[10] = {0};
    (void)snprintf(queueBufferingMaxMs, sizeof(queueBufferingMaxMs), "%u", mgr->queueBufferingMaxMs);
    ret = rd_kafka_conf_set(mgr->conf, "queue.buffering.max.ms", queueBufferingMaxMs, errstr, sizeof(errstr));
    if (ret != RD_KAFKA_CONF_OK) {
        ERROR("set rdkafka queue.buffering.max.ms failed(%s).\n", errstr);
        free(mgr);
        return NULL;
    }
    rd_kafka_conf_set_dr_msg_cb(mgr->conf, dr_msg_cb);

    if (mgr->kafkaUsername[0] != 0 && mgr->kafkaPassword[0] != 0) {
        ret = rd_kafka_conf_set(mgr->conf, "sasl.username", mgr->kafkaUsername, errstr, sizeof(errstr));
        if (ret != RD_KAFKA_CONF_OK) {
            ERROR("set rdkafka sasl.username failed(%s).\n", errstr);
            free(mgr);
            return NULL;
        }

        ret = rd_kafka_conf_set(mgr->conf, "sasl.password", mgr->kafkaPassword, errstr, sizeof(errstr));
        if (ret != RD_KAFKA_CONF_OK) {
            ERROR("set rdkafka sasl.password failed(%s).\n", errstr);
            free(mgr);
            return NULL;
        }

        ret = rd_kafka_conf_set(mgr->conf, "sasl.mechanism", "PLAIN", errstr, sizeof(errstr));
        if (ret != RD_KAFKA_CONF_OK) {
            ERROR("set rdkafka sasl.mechanism failed(%s).\n", errstr);
            free(mgr);
            return NULL;
        }

        ret = rd_kafka_conf_set(mgr->conf, "security.protocol", "SASL_PLAINTEXT", errstr, sizeof(errstr));
        if (ret != RD_KAFKA_CONF_OK) {
            ERROR("set rdkafka sasl.protocol failed(%s).\n", errstr);
            free(mgr);
            return NULL;
        }
    }

    mgr->rk = rd_kafka_new(RD_KAFKA_PRODUCER, mgr->conf, errstr, sizeof(errstr));
    if (mgr->rk == NULL) {
        ERROR("failed to create new kafka_producer, errstr(%s).\n", errstr);
        free(mgr);
        return NULL;
    }

    mgr->rkt = rd_kafka_topic_new(mgr->rk, mgr->kafkaTopic,  NULL);
    if (mgr->rkt == NULL) {
        ERROR("failed to create new kafka topic object.\n");
        rd_kafka_destroy(mgr->rk);
        free(mgr);
        return NULL;
    }

    return mgr;
}

void KafkaMgrDestroy(KafkaMgr *mgr)
{
    if (mgr == NULL)
        return;

    if (mgr->rkt != NULL)
        rd_kafka_topic_destroy(mgr->rkt);

    if (mgr->rk != NULL)
        rd_kafka_destroy(mgr->rk);

    free(mgr);
    return;
}

#define __RETRY_MAX 3
int KafkaMsgProduce(const KafkaMgr *mgr, char *msg, const uint32_t msgLen)
{
    int ret = 0;
    int retry_index = 0, retry_max = __RETRY_MAX;

retry:
    ret = rd_kafka_produce(mgr->rkt,
                           RD_KAFKA_PARTITION_UA,
                           RD_KAFKA_MSG_F_FREE,
                           (void *)msg, msgLen,
                           NULL, 0, NULL);
    if (ret == -1) {
        retry_index++;
        if ((retry_index < retry_max) && (rd_kafka_last_error() == RD_KAFKA_RESP_ERR__QUEUE_FULL)) {
            (void)rd_kafka_poll(mgr->rk, 10);
            goto retry;
        }
        ERROR("Failed to produce msg to topic %s: %s.\n", rd_kafka_topic_name(mgr->rkt),
                                                           rd_kafka_err2str(rd_kafka_last_error()));
        (void)free(msg);
        return -1;
    }
    (void)rd_kafka_poll(mgr->rk, 0);
    return 0;
}

