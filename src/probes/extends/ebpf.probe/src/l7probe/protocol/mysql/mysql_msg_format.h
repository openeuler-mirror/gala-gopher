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

#define MAX_PACKET_LENGTH (1 << 24) - 1
#define PACKET_HEADER_LENGTH 4

#define RESP_HEADER_EOF 0xfe
#define RESP_HEADER_ERR 0xff
#define RESP_HEADER_OK 0x00

// 定义 NumberRange 结构体
typedef struct {
    int min;
    int max;
} NumberRange;

typedef enum {
    CMD_SLEEP = 0x00,
    CMD_QUIT = 0x01,
    CMD_INITDB = 0x02,
    CMD_QUERY = 0x03,
    CMD_FIELDLIST = 0x04,
    CMD_CREATDB = 0x05,
    CMD_DROPDB = 0x06,
    CMD_REFRESH = 0x07,
    CMD_SHUTDOWN = 0x08,
    CMD_STATISTICS = 0x09,
    CMD_PROCESS_INFO = 0x0a,
    CMD_CONNECT = 0x0b,
    CMD_PROCESS_KILL = 0x0c,
    CMD_DEBUG = 0x0d,
    CMD_PING = 0x0e,
    CMD_TIME = 0x0f,
    CMD_DELAYED_INSERT = 0x10,
    CMD_CHANGE_USER = 0x11,
    CMD_BINLOG_DUMP = 0x12,
    CMD_TABLE_DUMP = 0x13,
    CMD_CONNECT_OUT = 0x14,
    CMD_REGISTER_SLAVE = 0x15,
    CMD_STMT_PREPARE = 0x16,
    CMD_STMT_EXECUTE = 0x17,
    CMD_STMT_SEND_LONG_DATA = 0x18,
    CMD_STMT_CLOSE = 0x19,
    CMD_STMT_RESET = 0x1a,
    CMD_SET_OPTION = 0x1b,
    CMD_STMT_FETCH = 0x1c,
    CMD_DAEMON = 0x1d,
    CMD_BINLOG_DUMP_GTID = 0x1e,
    CMD_RESET_CONNECTION = 0x1f,
    CMD_BROKEN_DATA = 0x20,
} MySQLCommand;

// 定义最大命令值
#define MAX_COMMAND_VALUE 0x1f

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
