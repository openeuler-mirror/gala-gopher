/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangshuyuan
 * Create: 2024-10-08
 * Description:
 ******************************************************************************/
#ifndef __MYSQL_MSG_FORMAT_H__
#define __MYSQL_MSG_FORMAT_H__

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <utlist.h>
#include "hash.h"
#include "../../include/data_stream.h"

/**
 * The MySQL parsing structure has 3 different levels of abstraction. From low to high level:
 * 1. MySQL Packet (Output of MySQL Parser). The content of it is not parsed.
 *    https://dev.mysql.com/doc/internals/en/mysql-packet.html
 * 2. MySQL Message, a Request or Response, consisting of one or more MySQL Packets. It contains
 * parsed out fields based on the type of request/response.
 * 3. MySQL Event, containing a request and response pair.
 */

// Command Types
// https://dev.mysql.com/doc/internals/en/command-phase.html
#define kMaxPacketLength (1 << 24) - 1
#define kPacketHeaderLength 4

#define kRespHeaderEOF 0xfe
#define kRespHeaderErr 0xff
#define kRespHeaderOK 0x00

// 定义 NumberRange 结构体
typedef struct {
    int min;
    int max;
} NumberRange;

//-----------------------------------------------------------------------------
// Packet Level Definitions
//-----------------------------------------------------------------------------

// Command Types
// https://dev.mysql.com/doc/internals/en/command-phase.html
typedef enum {
    kSleep = 0x00,
    kQuit = 0x01,
    kInitDB = 0x02,
    kQuery = 0x03,
    kFieldList = 0x04,
    kCreateDB = 0x05,
    kDropDB = 0x06,
    kRefresh = 0x07,
    kShutdown = 0x08,
    kStatistics = 0x09,
    kProcessInfo = 0x0a,
    kConnect = 0x0b,
    kProcessKill = 0x0c,
    kDebug = 0x0d,
    kPing = 0x0e,
    kTime = 0x0f,
    kDelayedInsert = 0x10,
    kChangeUser = 0x11,
    kBinlogDump = 0x12,
    kTableDump = 0x13,
    kConnectOut = 0x14,
    kRegisterSlave = 0x15,
    kStmtPrepare = 0x16,
    kStmtExecute = 0x17,
    kStmtSendLongData = 0x18,
    kStmtClose = 0x19,
    kStmtReset = 0x1a,
    kSetOption = 0x1b,
    kStmtFetch = 0x1c,
    kDaemon = 0x1d,
    kBinlogDumpGTID = 0x1e,
    kResetConnection = 0x1f,
} Command;

// 定义最大命令值
#define kMaxCommandValue 0x1f

struct mysql_packet_msg_s {
    // current_pos有效值：[0, data_len - 1]，current_pos = data_len时，证明已解析完当前data[]
    size_t current_pos;
    u64 timestamp_ns;
    u8 sequence_id;
    u8 command_t;
    u64 data_len;
    char *msg;
    bool consumed;
};

struct mysql_packet_msg_s *init_mysql_msg_s(void);

void free_mysql_packet_msg_s(struct mysql_packet_msg_s *msg);

struct mysql_command_req_resp_s {
    struct mysql_packet_msg_s *req;
    struct mysql_packet_msg_s *rsp;
};

struct mysql_command_req_resp_s *init_mysql_command_req_resp_s(void);

void free_mysql_command_req_resp_s(struct mysql_command_req_resp_s *req_rsp);  // mysql_record

void free_mysql_record(struct mysql_command_req_resp_s *record);

#endif
