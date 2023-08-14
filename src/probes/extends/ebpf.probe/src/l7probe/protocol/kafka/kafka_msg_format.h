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

#ifndef __KAFKA_MSG_FORMAT_H__
#define __KAFKA_MSG_FORMAT_H__
#pragma once

#include "hash.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include "../../include/data_stream.h"


// The following variable length unit is bytes
extern const int KAFKA_API_KEY_LENGTH;
extern const int KAFKA_API_VERSION_LENGTH;
extern const int KAFKA_PAYLOAD_LENGTH;
extern const int KAFKA_CORRELATION_ID_LENGTH;
extern const int KAFKA_MIN_REQ_FRAME_LENGTH;
extern const int KAFKA_MIN_RESP_FRAME_LENGTH;
extern const int KAFKA_MAX_MESSAGE_LEN;

// https://kafka.apache.org/protocol.html#protocol_api_keys
enum kafka_api {
    Produce = 0,
    Fetch = 1,
    ListOffsets = 2,
    Metadata = 3,
    LeaderAndIsr = 4,
    StopReplica = 5,
    UpdateMetadata = 6,
    ControlledShutdown = 7,
    OffsetCommit = 8,
    OffsetFetch = 9,
    FindCoordinator = 10,
    JoinGroup = 11,
    Heartbeat = 12,
    LeaveGroup = 13,
    SyncGroup = 14,
    DescribeGroups = 15,
    ListGroups = 16,
    SaslHandshake = 17,
    ApiVersions = 18,
    CreateTopics = 19,
    DeleteTopics = 20,
    DeleteRecords = 21,
    InitProducerId = 22,
    OffsetForLeaderEpoch = 23,
    AddPartitionsToTxn = 24,
    AddOffsetsToTxn = 25,
    EndTxn = 26,
    WriteTxnMarkers = 27,
    TxnOffsetCommit = 28,
    DescribeAcls = 29,
    CreateAcls = 30,
    DeleteAcls = 31,
    DescribeConfigs = 32,
    AlterConfigs = 33,
    AlterReplicaLogDirs = 34,
    DescribeLogDirs = 35,
    SaslAuthenticate = 36,
    CreatePartitions = 37,
    CreateDelegationToken = 38,
    RenewDelegationToken = 39,
    ExpireDelegationToken = 40,
    DescribeDelegationToken = 41,
    DeleteGroups = 42,
    ElectLeaders = 43,
    IncrementalAlterConfigs = 44,
    AlterPartitionReassignments = 45,
    ListPartitionReassignments = 46,
    OffsetDelete = 47,
    DescribeClientQuotas = 48,
    AlterClientQuotas = 49,
    DescribeUserScramCredentials = 50,
    AlterUserScramCredentials = 51,
    AlterIsr = 56,
    UpdateFeatures = 57,
    Envelope = 58,
    DescribeCluster = 60,
    DescribeProducers = 61,
    UnregisterBroker = 64,
    DescribeTransactions = 65,
    ListTransactions = 66,
    AllocateProducerIds = 67
};

// https://kafka.apache.org/protocol.html#protocol_error_codes
enum kafka_error_code {
    UnknownServerError = -1,
    None = 0,
    OffsetOutOfRange = 1,
    CorruptMessage = 2,
    UnknownTopicOrPartition = 3,
    InvalidFetchSize = 4,
    LeaderNotAvailable = 5,
    NotLeaderOrFollowee = 6,
    RequestTimedOut = 7,
    BrokerNotAvailable = 8,
    ReplicaNotAvailable = 9,
    MessageTooLarge = 10,
    StaleControllerEpoch = 11,
    OffsetMetadataTooLarge = 12,
    NetworkException = 13,
    CoordinatorLoadInProgress = 14,
    CoordinatorNotAvailable = 15,
    NotCoordinator = 16,
    InvalidTopicException = 17,
    RecordListTooLarge = 18,
    NotEnoughReplicas = 19,
    NotEnoughReplicasAfterAppend = 20,
    InvalidRequiredAcks = 21,
    IllegalGeneration = 22,
    InconsistentGroupProtocol = 23,
    InvalidGroupID = 24,
    UnknownMemberID = 25,
    InvalidSessionTimeout = 26,
    RebalanceInProgress = 27,
    InvalidCommitOffsetSize = 28,
    TopicAuthorizationFailed = 29,
    GroupAuthorizationFailed = 30,
    ClusterAuthorizationFailed = 31,
    InvalidTimestamp = 32,
    UnsupportedSaslMechanism = 33,
    IllegalSaslState = 34,
    UnsupportedVersion = 35,
    TopicAlreadyExists = 36,
    InvalidPartitions = 37,
    InvalidReplicationFactor = 38,
    InvalidReplicaAssignment = 39,
    InvalidConfig = 40,
    NotController = 41,
    InvalidRequest = 42,
    UnsupportedForMessageFormat = 43,
    PolicyViolation = 44,
    OutOfOrderSequenceNumber = 45,
    DuplicateSequenceNumber = 46,
    InvalidProducerEpoch = 47,
    InvalidTxnState = 48,
    InvalidProducerIDMapping = 49,
    InvalidTransactionTimeout = 50,
    ConcurrentTransactions = 51,
    TransactionCoordinatorFenced = 52,
    TransactionalIDAuthorizationFailed = 53,
    SecurityDisabled = 54,
    OperationNotAttempted = 55,
    KafkaStorageError = 56,
    LogDirNotFound = 57,
    SaslAuthenticationFailed = 58,
    UnknownProducerID = 59,
    ReassignmentInProgress = 60,
    DelegationTokenAuthDisabled = 61,
    DelegationTokenNotFound = 62,
    DelegationTokenOwnerMismatch = 63,
    DelegationTokenRequestNotAllowed = 64,
    DelegationTokenAuthorizationFailed = 65,
    DelegationTokenExpired = 66,
    InvalidPrincipalType = 67,
    NonEmptyGroup = 68,
    GroupIDNotFound = 69,
    FetchSessionIDNotFound = 70,
    InvalidFetchSessionEpoch = 71,
    ListenerNotFound = 72,
    TopicDeletionDisabled = 73,
    FencedLeaderEpoch = 74,
    UnknownLeaderEpoch = 75,
    UnsupportedCompressionType = 76,
    StaleBrokerEpoch = 77,
    OffsetNotAvailable = 78,
    MemberIDRequired = 79,
    PreferredLeaderNotAvailable = 80,
    GroupMaxSizeReached = 81,
    FencedInstanceID = 82,
    EligibleLeadersNotAvailable = 83,
    ElectionNotNeeded = 84,
    NoReassignmentInProgress = 85,
    GroupSubscribedToTopic = 86,
    InvalidRecord = 87,
    UnstableOffsetCommit = 88,
    ThrottlingQuotaExceeded = 89,
    ProducerFenced = 90,
    ResourceNotFound = 91,
    DuplicateResource = 92,
    UnacceptableCredential = 93,
    InconsistentVoterSet = 94,
    InvalidUpdateVersion = 95,
    FeatureUpdateFailed = 96,
    PrincipalDeserializationFailure = 97,
    SnapshotNotFound = 98,
    PositionOutOfRange = 99,
    UnknownTopicID = 100,
    DuplicateBrokerRegistration = 101,
    BrokerIDNotRegistered = 102,
    InconsistentTopicID = 103,
    InconsistentClusterID = 104,
    TransactionalIdNotFound = 105,
    FetchSessionTopicIdError = 106,
    IneligibleReplica = 107,
    NewLeaderElected = 108
};

struct kafka_version_matcher_t {
    int16_t min_version;
    int16_t max_version;
    int16_t flexible_version;
};

extern struct kafka_version_matcher_t kafka_version_map[68];
extern const int kafka_version_map_len;

#define KAFKA_VERSION_MATCHER_S(x, y, z) {x, y, z}

// 通过api key和api version 判断是否支持flexible版本
bool is_flexible(enum kafka_api api, int16_t api_version);

// 是否支持该api key
bool is_api_key_valid(int16_t api_key);

// 是否是支持的api版本
bool is_api_version_support(enum kafka_api api_key, int16_t api_version);


struct kafka_frame_s {
    int32_t correlation_id;
    struct raw_data_s *msg;
    size_t msg_len;
    bool consumed;
    uint64_t timestamp_ns;
};

struct kafka_request_s {
    enum kafka_api api;
    int16_t api_version;
    char *client_id;
    char *msg;
    uint64_t timestamp_ns;
};

struct kafka_response_s {
    char *msg;
    uint64_t timestamp_ns;
};

struct kafka_record_s {
    struct kafka_request_s *req;
    struct kafka_response_s *resp;
};

void free_kafka_frame(struct kafka_frame_s *frame);

void free_kafka_record(struct kafka_record_s *record);

void free_kafka_req_record(struct kafka_request_s *request);

void free_kafka_resp_record(struct kafka_response_s *response);

#endif