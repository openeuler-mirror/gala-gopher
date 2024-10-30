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
#ifndef MYSQL_MATCHER_WRAPPER_H
#define MYSQL_MATCHER_WRAPPER_H

#pragma once

#include <stdbool.h>
#include <string.h>
#include "common.h"
#include "mysql_msg_format.h"
#include "mysql_parser.h"

#define CTX_DCHECK(cond)                        \
    if (!(cond)) {                              \
        DEBUG("Assertion failed: %s\n", #cond); \
        return (DequeView){ NULL, 0, 0 };       \
    }

#define PX_ASSIGN_OR_RETURN(lhs, rexpr) \
    {                                   \
        StatusOrInt64 __s__ = (rexpr);  \
        if (__s__.error_code != 0) {    \
            return STATE_INVALID;       \
        }                               \
        (lhs) = __s__.value;            \
    }

#define PX_RETURN_IF_NOT_SUCCESS(stmt) \
    {                                  \
        parse_state_t s = (stmt);      \
        if (s != STATE_SUCCESS) {      \
            return s;                  \
        }                              \
    }

#define PX_UNUSED(x) (void)(x)

// If it is < 0xfb, treat it as a 1-byte integer.
// If it is 0xfc, it is followed by a 2-byte integer.
// If it is 0xfd, it is followed by a 3-byte integer.
// If it is 0xfe, it is followed by a 8-byte integer.
#define K_LENC_INT_PREFIX_2B 0xfc
#define K_LENC_INT_PREFIX_3B 0xfd
#define K_LENC_INT_PREFIX_8B 0xfe

#define RETURN_NEEDS_MORE_DATA_IF_EMPTY(resp_packets)           \
    if (((resp_packets)->count - (resp_packets)->start) == 0) { \
        return STATE_NEEDS_MORE_DATA;                           \
    }

typedef struct {
    struct frame_data_s **packets;
    int start;
    int count;
} DequeView;

typedef struct {
    int64_t value;
    int error_code;
} StatusOrInt64;

/**
 * Returns a read-only view of packets that correspond to the request packet at the head of
 * the request packets, which can then be sent for further processing as a contained bundle.
 *
 * The creation of the response packet bundle is done using timestamps and sequence numbers.
 * Any request with a timestamp that occurs after the timestamp of the 2nd request is not included.
 * Sequence numbers are also checked to be contiguous. Any gap results in sealing the bundle.
 *
 *
 * @param req_index
 * @param req_frames Deque of all received request packets (some may be missing).
 * @param rsp_frames Dequeue of all received response packets (some may be missing).
 * @return View into the "bundle" of response packets that correspond to the first request packet.
 */
DequeView GetRespView(size_t req_index, struct frame_buf_s *req_frames, struct frame_buf_s *rsp_frames);

/**
 * Implement the function for checking whether StatusOrInt64 is OK.
 *
 *
 * @param status
 * @return
 */
int IsStatusOk(StatusOrInt64 status);

/**
 * This dissector is helper functions that parse out a parameter from a packet's raw contents.
 * The offset identifies where to begin the parsing, and the offset is updated to reflect where
 * the parsing ends.
 * @param data
 * @param msg_size
 * @param offset the position at which to parse the length-encoded int.
 * The offset will be updated to point to the end position on a successful parse.
 * On an unsuccessful parse, the offset will be in an undefined state.
 * @param size
 * @return
 */
StatusOrInt64 DissectInt(const char *data, size_t msg_size, size_t *offset, size_t size);

/**
 * Converts a length encoded int from string to int.
 * https://dev.mysql.com/doc/internals/en/integer.html#packet-Protocol::LengthEncodedInteger
 *
 * @param data
 * @param data_len
 * @param offset the position at which to parse the length-encoded int.
 * The offset will be updated to point to the end position on a successful parse.
 * On an unsuccessful parse, the offset will be in an undefined state.
 *
 * @return
 */
StatusOrInt64 ProcessLengthEncodedInt(const char *data, u64 data_len, size_t *offset);

/**
 * The following functions check whether a Packet is of a certain type.
 * https://dev.mysql.com/doc/internals/en/packet-EOF_Packet.html
 * https://dev.mysql.com/doc/internals/en/packet-ERR_Packet.html
 * https://dev.mysql.com/doc/internals/en/packet-OK_Packet.html
 * https://dev.mysql.com/doc/internals/en/com-stmt-prepare-response.html#packet-COM_STMT_PREPARE_OK
 * @param rsp_msg
 * @return
 */
bool IsEOFPacket(struct mysql_packet_msg_s *rsp_msg);
bool IsErrPacket(struct mysql_packet_msg_s *rsp_msg);
bool IsOKPacket(struct mysql_packet_msg_s *rsp_msg);
bool IsStmtPrepareOKPacket(struct mysql_packet_msg_s *rsp_msg);

/**
 * This function looks for unsynchronized req/resp packet queues.
 * This could happen for a number of reasons:
 *  - lost events
 *  - previous unhandled case resulting in a bad state.
 * Currently handles the case where an apparently missing request has left dangling responses,
 * in which case those requests are popped off.
 * @param req_msg
 * @param rsp_frames
 * @return
 */
void SyncRespQueue(struct mysql_packet_msg_s *req_msg, struct frame_buf_s *rsp_frames);

/**
 * These dissectors are helper functions that parse out a parameter from a packet's raw contents.
 * The offset identifies where to begin the parsing, and the offset is updated to reflect where
 * the parsing ends.
 * @param rsp_msg
 * @param param_offset
 * @param param
 * @return
 */
bool DissectStringParam(struct mysql_packet_msg_s *rsp_msg, size_t *param_offset, char **param);

/**
 * This function processes columns packet.
 * @param rsp_msg
 * @return
 */
parse_state_t ProcessColumnDefPacket(struct mysql_packet_msg_s *rsp_msg);

/**
 * Handlers are helper functions that transform MySQL Packets into request/response object.
 * MySQL Response can have one or more packets, so the functions pop off packets from the
 * deque as it parses the first packet.
 * https://dev.mysql.com/doc/internals/en/packet-OK_Packet.html
 * https://dev.mysql.com/doc/internals/en/packet-ERR_Packet.html
 * @param rsp_msg
 * @param req_rsp
 * @return
 */
parse_state_t HandleOKMessage(struct mysql_packet_msg_s *rsp_msg, u64 *rsp_timestamp);
parse_state_t HandleErrMessage(struct mysql_packet_msg_s *rsp_msg, u64 *rsp_timestamp, struct record_buf_s *record_buf);

/**
 * A Resultset can either be a binary resultset(returned by StmtExecute), or a text
 * resultset(returned by Query).
 */
parse_state_t HandleResultsetResponse(DequeView *resp_packets, u64 *rsp_timestamp, bool binary_resultset,
    bool multi_resultset, struct record_buf_s *record_buf);
parse_state_t HandleStmtPrepareOKResponse(DequeView *resp_packets, u64 *rsp_timestamp);

#endif  // MYSQL_MATCHER_WRAPPER_H
