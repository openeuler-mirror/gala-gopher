/*******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: shiaigang
 * Create: 2023-06-07
 * Description:
 *
 ******************************************************************************/

#include <stddef.h>
#include <stdlib.h>
#include "common/protocol_common.h"
#include "kafka_msg_format.h"

const int KAFKA_API_KEY_LENGTH = 2;
const int KAFKA_API_VERSION_LENGTH = 2;
const int KAFKA_PAYLOAD_LENGTH = 4;
const int KAFKA_CORRELATION_ID_LENGTH = 4;
//KAFKA_MIN_REQ_FRAME_LENGTH = KAFKA_PAYLOAD_LENGTH + KAFKA_API_KEY_LENGTH + KAFKA_API_VERSION_LENGTH + KAFKA_CORRELATION_ID_LENGTH;
const int KAFKA_MIN_REQ_FRAME_LENGTH = 12;
//KAFKA_MIN_RESP_FRAME_LENGTH = KAFKA_PAYLOAD_LENGTH + KAFKA_CORRELATION_ID_LENGTH;
const int KAFKA_MIN_RESP_FRAME_LENGTH = 8;
const int KAFKA_MAX_MESSAGE_LEN = 1024 * 1024;

struct kafka_version_matcher_t kafka_version_map[68] = {
        KAFKA_VERSION_MATCHER_S(0, 9, 9),    //Produce = 0,
        KAFKA_VERSION_MATCHER_S(0, 12, 12),  //Fetch = 1,
        KAFKA_VERSION_MATCHER_S(0, 7, 6),    //ListOffsets = 2,
        KAFKA_VERSION_MATCHER_S(0, 12, 9),   //Metadata = 3,
        KAFKA_VERSION_MATCHER_S(0, 5, 4),    //LeaderAndIsr = 4,
        KAFKA_VERSION_MATCHER_S(0, 3, 2),    //StopReplica = 5,
        KAFKA_VERSION_MATCHER_S(0, 7, 6),    //UpdateMetadata = 6,
        KAFKA_VERSION_MATCHER_S(0, 3, 3),    //ControlledShutdown = 7,
        KAFKA_VERSION_MATCHER_S(0, 8, 8),    //OffsetCommit = 8,
        KAFKA_VERSION_MATCHER_S(0, 8, 6),    //OffsetFetch = 9,
        KAFKA_VERSION_MATCHER_S(0, 4, 3),    //FindCoordinator = 10,
        KAFKA_VERSION_MATCHER_S(0, 7, 6),    //JoinGroup = 11,
        KAFKA_VERSION_MATCHER_S(0, 4, 4),    //Heartbeat = 12,
        KAFKA_VERSION_MATCHER_S(0, 4, 4),    //LeaveGroup = 13,
        KAFKA_VERSION_MATCHER_S(0, 5, 4),    //SyncGroup = 14,
        KAFKA_VERSION_MATCHER_S(0, 5, 5),    //DescribeGroups = 15,
        KAFKA_VERSION_MATCHER_S(0, 4, 3),    //ListGroups = 16,
        KAFKA_VERSION_MATCHER_S(0, 1, 1),    //SaslHandshake = 17,
        KAFKA_VERSION_MATCHER_S(0, 3, 3),    //ApiVersions = 18,
        KAFKA_VERSION_MATCHER_S(0, 7, 5),    //CreateTopics = 19,
        KAFKA_VERSION_MATCHER_S(0, 6, 4),    //DeleteTopics = 20,
        KAFKA_VERSION_MATCHER_S(0, 2, 2),    //DeleteRecords = 21,
        KAFKA_VERSION_MATCHER_S(0, 4, 2),    //InitProducerId = 22,
        KAFKA_VERSION_MATCHER_S(0, 4, 4),    //OffsetForLeaderEpoch = 23,
        KAFKA_VERSION_MATCHER_S(0, 3, 3),    //AddPartitionsToTxn = 24,
        KAFKA_VERSION_MATCHER_S(0, 3, 3),    //AddOffsetsToTxn = 25,
        KAFKA_VERSION_MATCHER_S(0, 3, 3),    //EndTxn = 26,
        KAFKA_VERSION_MATCHER_S(0, 1, 1),    //WriteTxnMarkers = 27,
        KAFKA_VERSION_MATCHER_S(0, 3, 3),    //TxnOffsetCommit = 28,
        KAFKA_VERSION_MATCHER_S(0, 2, 2),    //DescribeAcls = 29,
        KAFKA_VERSION_MATCHER_S(0, 2, 2),    //CreateAcls = 30,
        KAFKA_VERSION_MATCHER_S(0, 2, 2),    //DeleteAcls = 31,
        KAFKA_VERSION_MATCHER_S(0, 4, 4),    //DescribeConfigs = 32,
        KAFKA_VERSION_MATCHER_S(0, 2, 2),    //AlterConfigs = 33,
        KAFKA_VERSION_MATCHER_S(0, 2, 2),    //AlterReplicaLogDirs = 34,
        KAFKA_VERSION_MATCHER_S(0, 2, 2),    //DescribeLogDirs = 35,
        KAFKA_VERSION_MATCHER_S(0, 2, 2),    //SaslAuthenticate = 36,
        KAFKA_VERSION_MATCHER_S(0, 3, 2),    //CreatePartitions = 37,
        KAFKA_VERSION_MATCHER_S(0, 2, 2),    //CreateDelegationToken = 38,
        KAFKA_VERSION_MATCHER_S(0, 2, 2),    //RenewDelegationToken = 39,
        KAFKA_VERSION_MATCHER_S(0, 2, 2),    //ExpireDelegationToken = 40,
        KAFKA_VERSION_MATCHER_S(0, 2, 2),    //DescribeDelegationToken = 41,
        KAFKA_VERSION_MATCHER_S(0, 5, 5),    //DeleteGroups = 42,
        KAFKA_VERSION_MATCHER_S(0, 2, 2),    //ElectLeaders = 43,
        KAFKA_VERSION_MATCHER_S(0, 1, 1),    //IncrementalAlterConfigs = 44,
        KAFKA_VERSION_MATCHER_S(0, 0, 0),    //AlterPartitionReassignments = 45,
        KAFKA_VERSION_MATCHER_S(0, 0, 0),    //ListPartitionReassignments = 46,
        KAFKA_VERSION_MATCHER_S(0, 0, 1),    //OffsetDelete = 47,
        KAFKA_VERSION_MATCHER_S(0, 1, 1),    //DescribeClientQuotas = 48,
        KAFKA_VERSION_MATCHER_S(0, 1, 1),    //AlterClientQuotas = 49,
        KAFKA_VERSION_MATCHER_S(0, 0, 0),    //DescribeUserScramCredentials = 50,
        KAFKA_VERSION_MATCHER_S(0, 0, 0),    //AlterUserScramCredentials = 51,
        KAFKA_VERSION_MATCHER_S(0, 0, 0),    //NULL
        KAFKA_VERSION_MATCHER_S(0, 0, 0),    //NULL
        KAFKA_VERSION_MATCHER_S(0, 0, 0),    //NULL
        KAFKA_VERSION_MATCHER_S(0, 0, 0),    //NULL
        KAFKA_VERSION_MATCHER_S(0, 0, 0),    //AlterIsr = 56,
        KAFKA_VERSION_MATCHER_S(0, 0, 0),    //UpdateFeatures = 57,
        KAFKA_VERSION_MATCHER_S(0, 0, 0),    //Envelope = 58,
        KAFKA_VERSION_MATCHER_S(0, 0, 0),    //NULL
        KAFKA_VERSION_MATCHER_S(0, 0, 0),    //DescribeCluster = 60,
        KAFKA_VERSION_MATCHER_S(0, 0, 0),    //DescribeProducers = 61,
        KAFKA_VERSION_MATCHER_S(0, 0, 0),    //NULL
        KAFKA_VERSION_MATCHER_S(0, 0, 0),    //NULL
        KAFKA_VERSION_MATCHER_S(0, 0, 0),    //UnregisterBroker = 64,
        KAFKA_VERSION_MATCHER_S(0, 0, 0),    //DescribeTransactions = 65,
        KAFKA_VERSION_MATCHER_S(0, 0, 0),    //ListTransactions = 66,
        KAFKA_VERSION_MATCHER_S(0, 0, 0)     //AllocateProducerIds = 67
};

const int kafka_version_map_len = sizeof(kafka_version_map) / sizeof(struct kafka_version_matcher_t);

// 通过api key和api version 判断是否支持flexible版本
bool is_flexible(enum kafka_api api, int16_t api_version)
{
    struct kafka_version_matcher_t *version_matcher = &kafka_version_map[api];

    if (version_matcher == NULL) {
        return false;
    }

    if (api_version != version_matcher->flexible_version) {
        if (version_matcher->flexible_version < 0) {
            return false;
        }
        return api_version >= version_matcher->flexible_version;
    }
    return false;
}

// 是否支持该api key
bool is_api_key_valid(int16_t api_key)
{
    if (api_key > kafka_version_map_len || api_key < 0) {
        ERROR("[KAFKA] Api key is invalid.\n");
        return false;
    }
    // 遍历enum kafka_api，判断api_key是否在其中
    for (int i = Produce; i < AllocateProducerIds; i++) {
        if (i == api_key) {
            return true;
        }
    }
    ERROR("[KAFKA] Api key is undefined.\n");
    return false;
}

// 是否是支持的api版本
bool is_api_version_support(enum kafka_api api_key, int16_t api_version)
{
    struct kafka_version_matcher_t *version_matcher = &kafka_version_map[api_key];

    if (version_matcher == NULL) {
        return false;
    }
    return api_version >= version_matcher->min_version &&
           api_version <= version_matcher->max_version;
}

void free_kafka_frame(struct kafka_frame_s *frame)
{
    if (frame == NULL) {
        return;
    }
    if (frame->msg != NULL) {
        free(frame->msg);
    }
    free(frame);
}

void free_kafka_req_record(struct kafka_request_s *request)
{
    if (request == NULL) {
        return;
    }
    if (request->msg != NULL) {
        free(request->msg);
    }
    if (request->client_id != NULL) {
        free(request->client_id);
    }
    free(request);
}

void free_kafka_resp_record(struct kafka_response_s *response)
{
    if (response == NULL) {
        return;
    }

    if (response->msg != NULL) {
        free(response->msg);
    }

    free(response);
}

void free_kafka_record(struct kafka_record_s *record)
{
    if (record == NULL) {
        return;
    }
    free(record);
}