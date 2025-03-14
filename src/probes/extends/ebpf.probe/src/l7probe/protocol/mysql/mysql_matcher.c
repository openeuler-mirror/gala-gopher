/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan
 * PSL v2. You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 * KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE. See the
 * Mulan PSL v2 for more details. Author: wangshuyuan Create: 2024-10-08
 * Description:
 * **************************************************************************** */
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include "mysql_matcher_wrapper.h"
#include "mysql_msg_format.h"

// Process a simple request and response pair, and populate details into a
// record entry. This is for MySQL commands that have only a single OK, ERR or
// EOF response.
// TODO(wangshuyuan): Currently any of OK, ERR or EOF are accepted, but could
// specialize to expect a subset, since some responses are invalid for certain
// commands. For example, a COM_INIT_DB command should never receive an EOF
// response. All we would do is print a warning, though, so this is low
// priority.
static parse_state_t ProcessRequestWithBasicResponse(struct mysql_packet_msg_s *req, DequeView *resp_packets,
    u64 *rsp_timestamp, struct record_buf_s *record_buf)
{
    if (resp_packets->count == 0) {
        return STATE_NEEDS_MORE_DATA;
    }
    if (resp_packets->count > 1) {
        DEBUG("Did not expect more than one response packet [cmd=0x%x, "
            "num_extra_packets=%d].\n",
            req->command_t, resp_packets->count - 1);
    }
    struct mysql_packet_msg_s *rsp_msg;
    rsp_msg = (struct mysql_packet_msg_s *)resp_packets->packets[0]->frame;
    if (IsOKPacket(rsp_msg) || IsEOFPacket(rsp_msg)) {
        *rsp_timestamp = rsp_msg->timestamp_ns;
        ++resp_packets->start;
        return STATE_SUCCESS;
    }
    if (IsErrPacket(rsp_msg)) {
        PX_RETURN_IF_NOT_SUCCESS(HandleErrMessage(rsp_msg, rsp_timestamp, record_buf));
        ++resp_packets->start;
        return STATE_SUCCESS;
    }
    return STATE_INVALID;
}
// Process a  request and incomplete response.
static parse_state_t ProcessDataIncomplete(struct mysql_packet_msg_s *req, DequeView *resp_packets,
    u64 *rsp_timestamp, struct record_buf_s *record_buf)
{
    if (resp_packets->count == 0) {
        return STATE_NEEDS_MORE_DATA;
    }
    struct mysql_packet_msg_s *rsp_msg;
    rsp_msg = (struct mysql_packet_msg_s *)resp_packets->packets[0]->frame;
    *rsp_timestamp = rsp_msg->timestamp_ns;
    ++resp_packets->start;

    return STATE_SUCCESS;
}

// Process a COM_STMT_RESET request and response, and populate details into a record entry. MySQL documentation:
// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_reset.html
static parse_state_t ProcessStmtReset(struct mysql_packet_msg_s *req, DequeView *resp_packets, u64 *rsp_timestamp,
    struct record_buf_s *record_buf)
{
    // Defer to basic response for now.
    return ProcessRequestWithBasicResponse(req, /* string_req */ resp_packets, rsp_timestamp, record_buf);
}

// Process a COM_STMT_SEND_LONG_DATA request and response, and populate details into a record entry. MySQL
// documentation: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_send_long_data.html
static parse_state_t ProcessStmtSendLongData(struct mysql_packet_msg_s *req, DequeView *resp_packets, u64 *rsp_timestamp,
    struct record_buf_s *record_buf)
{
    return STATE_INVALID;
}

// Process a COM_STMT_CLOSE request and response, and populate details into a record entry. MySQL documentation:
// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_close.html
static parse_state_t ProcessStmtClose(struct mysql_packet_msg_s *req, DequeView *resp_packets, u64 *rsp_timestamp,
    struct record_buf_s *record_buf)
{
    return STATE_INVALID;
}

// Process a COM_QUIT request and response, and populate details into a record entry. MySQL documentation:
// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_quit.html
static parse_state_t ProcessQuit(struct mysql_packet_msg_s *req, DequeView *resp_packets, u64 *rsp_timestamp,
    struct record_buf_s *record_buf)
{
    if (resp_packets->count == 0) {
        return STATE_INVALID;
    }
    struct mysql_packet_msg_s *rsp_msg;
    rsp_msg = (struct mysql_packet_msg_s *)resp_packets->packets[0]->frame;
    if (rsp_msg->timestamp_ns < req->timestamp_ns) {
        return STATE_INVALID;
    }
    if (IsOKPacket(rsp_msg)) {
        *rsp_timestamp = rsp_msg->timestamp_ns;
        ++resp_packets->start;
        return STATE_SUCCESS;
    }
    return STATE_INVALID;
}

// Process a COM_STMT_PREPARE request and response, and populate details into a record entry. MySQL documentation:
// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_prepare.html
static parse_state_t ProcessStmtPrepare(struct mysql_packet_msg_s *req, DequeView *resp_packets, u64 *rsp_timestamp,
    struct record_buf_s *record_buf)
{
    if (resp_packets->count == 0) {
        return STATE_NEEDS_MORE_DATA;
    }
    // struct frame_data_s* rsp_frame;
    struct mysql_packet_msg_s *rsp_msg;
    rsp_msg = (struct mysql_packet_msg_s *)resp_packets->packets[0]->frame;
    if (rsp_msg->timestamp_ns < req->timestamp_ns) {
        return STATE_INVALID;
    }
    if (IsErrPacket(rsp_msg)) {
        PX_RETURN_IF_NOT_SUCCESS(HandleErrMessage(rsp_msg, rsp_timestamp, record_buf));
        ++resp_packets->start;
        return STATE_SUCCESS;
    }
    return HandleStmtPrepareOKResponse(resp_packets, rsp_timestamp);
}

// Process a COM_STMT_EXECUTE request and response, and populate details into a record entry. MySQL documentation:
// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_execute.html
static parse_state_t ProcessStmtExecute(struct mysql_packet_msg_s *req, DequeView *resp_packets, u64 *rsp_timestamp,
    struct record_buf_s *record_buf)
{
    if (resp_packets->count == 0) {
        return STATE_NEEDS_MORE_DATA;
    }
    struct mysql_packet_msg_s *rsp_msg;
    rsp_msg = (struct mysql_packet_msg_s *)resp_packets->packets[0]->frame;
    if (rsp_msg->timestamp_ns < req->timestamp_ns) {
        return STATE_INVALID;
    }
    if (IsOKPacket(rsp_msg)) {
        if (resp_packets->count > 1) {
            return STATE_INVALID;
        }
        *rsp_timestamp = rsp_msg->timestamp_ns;
        ++resp_packets->start;
        return STATE_SUCCESS;
    }
    if (IsErrPacket(rsp_msg)) {
        PX_RETURN_IF_NOT_SUCCESS(HandleErrMessage(rsp_msg, rsp_timestamp, record_buf));
        ++resp_packets->start;
        return STATE_SUCCESS;
    }
    return HandleResultsetResponse(resp_packets, rsp_timestamp,
        /* binaryresultset */ true,
        /* multiresultset */ false, record_buf);
}

// Process a COM_QUERY request and response, and populate details into a record entry. MySQL documentation:
// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query.html
static parse_state_t ProcessQuery(struct mysql_packet_msg_s *req, DequeView *resp_packets, u64 *rsp_timestamp,
    struct record_buf_s *record_buf)
{
    if (resp_packets->count == 0) {
        return STATE_NEEDS_MORE_DATA;
    }
    struct mysql_packet_msg_s *rsp_msg;
    rsp_msg = (struct mysql_packet_msg_s *)resp_packets->packets[0]->frame;
    if (rsp_msg->timestamp_ns < req->timestamp_ns) {
        return STATE_INVALID;
    }
    if (IsErrPacket(rsp_msg)) {
        PX_RETURN_IF_NOT_SUCCESS(HandleErrMessage(rsp_msg, rsp_timestamp, record_buf));
        ++resp_packets->start;
        return STATE_SUCCESS;
    }
    if (IsOKPacket(rsp_msg)) {
        if (resp_packets->count > 1) {
            return STATE_INVALID;
        }
        PX_RETURN_IF_NOT_SUCCESS(HandleOKMessage(rsp_msg, rsp_timestamp));
        ++resp_packets->start;
        return STATE_SUCCESS;
    }
    return HandleResultsetResponse(resp_packets, rsp_timestamp,
        /* binaryresultset */ false,
        /* multiresultset */ false, record_buf);
}

// Process a COM_FIELD_LIST request and response, and populate details into a record entry. MySQL documentation:
// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_field_list.html
static parse_state_t ProcessFieldList(struct mysql_packet_msg_s *req, DequeView *resp_packets, u64 *rsp_timestamp,
    struct record_buf_s *record_buf)
{
    return STATE_INVALID;
}

// Process a COM_STMT_FETCH request and response, and populate details into a record entry. MySQL documentation:
// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_fetch.html
static parse_state_t ProcessStmtFetch(struct mysql_packet_msg_s *req, DequeView *resp_packets, u64 *rsp_timestamp,
    struct record_buf_s *record_buf)
{
    // TODO(wangshuyuan) add handle COM_STMT_FETCH packet
    return STATE_INVALID;
}

static void mysql_matcher_add_record(struct mysql_packet_msg_s *req, u64 rsp_timestamp_ns,
    struct record_buf_s *record_buf)
{
    struct mysql_packet_msg_s *rsp;
    struct mysql_command_req_resp_s *mysql_record;
    struct record_data_s *record_data;
    if (record_buf->record_buf_size >= RECORD_BUF_SIZE) {
        WARN("[MYSQL MATCHER] The record buffer is full.\n");
        ++record_buf->err_count;
        return;
    }
    req->consumed = true;
    rsp = init_mysql_msg_s();
    rsp->timestamp_ns = rsp_timestamp_ns;
    mysql_record = (struct mysql_command_req_resp_s *)calloc(1, sizeof(struct mysql_command_req_resp_s));
    if (mysql_record == NULL) {
        ERROR("[MySQL MATCHER] Failed to malloc mysql_record_s for mysql_record.\n");
        free_mysql_packet_msg_s(rsp);
        return;
    }
    // mysql_record = init_mysql_command_req_resp_s();
    mysql_record->req = req;
    mysql_record->rsp = rsp;
    record_data = (struct record_data_s *)calloc(1, sizeof(struct record_data_s));
    if (record_data == NULL) {
        ERROR("[MySQL MATCHER] Failed to malloc mysql_record_s for mysql_record.\n");
        free_mysql_record(mysql_record);
        return;
    }
    record_data->record = mysql_record;
    record_data->latency = rsp_timestamp_ns - req->timestamp_ns;
    record_buf->records[record_buf->record_buf_size] = record_data;
    ++record_buf->record_buf_size;
}

static int ProcessPackets(size_t req_index, struct mysql_packet_msg_s *req, struct frame_buf_s *req_frames,
    struct frame_buf_s *rsp_frames, struct record_buf_s *record_buf, DequeView *resp_packets_view)
{
    parse_state_t parse_state;
    u64 rsp_timestamp;
    switch (req->command_t) {
        // Internal commands with response: ERR_Packet.
        case kConnect:
        case kConnectOut:
        case kTime:
        case kDelayedInsert:
        case kDaemon:
        case kInitDB:
        case kCreateDB:
        case kDropDB:
        // Basic Commands with response: OK_Packet or ERR_Packet
        case kSleep:
        case kRegisterSlave:
        case kResetConnection:
        case kProcessKill:
        case kRefresh: // Deprecated.
        case kPing:    // COM_PING can't actually send ERR_Packet.
        // Basic Commands with response: EOF_Packet or ERR_Packet.
        case kShutdown: // Deprecated.
        case kSetOption:
        case kDebug:
            parse_state = ProcessRequestWithBasicResponse(req, resp_packets_view, &rsp_timestamp, record_buf);
            break;
        case kBrokenData:
            parse_state = ProcessDataIncomplete(req, resp_packets_view, &rsp_timestamp, record_buf);
            break;
        case kQuit: // Response: OK_Packet or a connection close.
            parse_state = ProcessQuit(req, resp_packets_view, &rsp_timestamp, record_buf);
            break;
        // COM_FIELD_LIST has its own COM_FIELD_LIST meta response (ERR_Packet or one
        // or more Column Definition packets and a closing EOF_Packet).
        case kFieldList: // Deprecated.
            parse_state = ProcessFieldList(req, resp_packets_view, &rsp_timestamp, record_buf);
            break;
        // COM_QUERY has its own COM_QUERY meta response (ERR_Packet, OK_Packet,
        // Protocol::LOCAL_INFILE_Request, or ProtocolText::Resultset).
        case kQuery:
            parse_state = ProcessQuery(req, resp_packets_view, &rsp_timestamp, record_buf);
            break;
        // COM_STMT_PREPARE returns COM_STMT_PREPARE_OK on success, ERR_Packet
        // otherwise.
        case kStmtPrepare:
            parse_state = ProcessStmtPrepare(req, resp_packets_view, &rsp_timestamp, record_buf);
            break;
        // COM_STMT_SEND_LONG_DATA has no response.
        case kStmtSendLongData:
            parse_state = ProcessStmtSendLongData(req, resp_packets_view, &rsp_timestamp, record_buf);
            break;
        // COM_STMT_EXECUTE has its own COM_STMT_EXECUTE meta response (OK_Packet,
        // ERR_Packet or a resultset: Binary Protocol Resultset).
        case kStmtExecute:
            parse_state = ProcessStmtExecute(req, resp_packets_view, &rsp_timestamp, record_buf);
            break;
        // COM_CLOSE has no response.
        case kStmtClose:
            parse_state = ProcessStmtClose(req, resp_packets_view, &rsp_timestamp, record_buf);
            break;
        // COM_STMT_RESET response is OK_Packet if the statement could be reset,
        // ERR_Packet if not.
        case kStmtReset:
            parse_state = ProcessStmtReset(req, resp_packets_view, &rsp_timestamp, record_buf);
            break;
        // COM_STMT_FETCH has a meta response (multi-resultset, or ERR_Packet).
        case kStmtFetch:
            parse_state = ProcessStmtFetch(req, resp_packets_view, &rsp_timestamp, record_buf);
            break;
        case kProcessInfo: // a ProtocolText::Resultset or ERR_Packet
        case kChangeUser:  // Authentication Method Switch Request Packet or
        // ERR_Packet
        case kBinlogDumpGTID: // binlog network stream, ERR_Packet or EOF_Packet
        case kBinlogDump:     // binlog network stream, ERR_Packet or EOF_Packet
        case kTableDump:      // a table dump or ERR_Packet
        case kStatistics:     // string.EOF
            // Rely on recovery to re-sync responses based on timestamps.
            parse_state = STATE_INVALID;
            break;
        default:
            parse_state = STATE_INVALID;
            break;
    }
    if (parse_state == STATE_INVALID) {
        DEBUG("[MYSQL MATCHER] An error occurred while handing command\n");
        req->consumed = true;
        return 0;
    }
    if (parse_state == STATE_NEEDS_MORE_DATA) {
        if (req_index == req_frames->frame_buf_size - 1 && rsp_frames->current_pos >= rsp_frames->frame_buf_size - 1) {
            return 0;
        } else {
            req->consumed = true;
            return 0;
        }
    }
    mysql_matcher_add_record(req, rsp_timestamp, record_buf);
    return resp_packets_view->start;
}

void mysql_match_frames(struct frame_buf_s *req_frames, struct frame_buf_s *rsp_frames, struct record_buf_s *record_buf)
{
    int handle_result;
    size_t req_index;
    if (req_frames->frame_buf_size == 0 || rsp_frames->frame_buf_size == 0) {
        return;
    }
    req_index = req_frames->current_pos;
    while (req_index < req_frames->frame_buf_size && rsp_frames->current_pos < rsp_frames->frame_buf_size) {
        struct frame_data_s *req_frame = req_frames->frames[req_index];
        if (req_frame == NULL) {
            break;
        }
        struct mysql_packet_msg_s *req_msg = (struct mysql_packet_msg_s *)req_frame->frame;
        if (req_msg == NULL) {
            break;
        }
        // For safety, make sure we have no stale response packets.
        SyncRespQueue(req_msg, rsp_frames);
        DequeView resp_packets_view = GetRespView(req_index, req_frames, rsp_frames);
        handle_result = ProcessPackets(req_index, req_msg, req_frames, rsp_frames, record_buf, &resp_packets_view);
        rsp_frames->current_pos -= resp_packets_view.count - handle_result;
        ++req_index;
    }
    int pos = req_frames->current_pos;
    for (; pos < req_frames->frame_buf_size; ++pos) {
        struct frame_data_s *req_frame = req_frames->frames[pos];
        if (req_frame == NULL) {
            break;
        }
        struct mysql_packet_msg_s *req_msg = (struct mysql_packet_msg_s *)req_frame->frame;
        if (!req_msg->consumed) {
            break;
        }
    }
    req_frames->current_pos = pos;
    record_buf->req_count = req_frames->current_pos;
    record_buf->resp_count = rsp_frames->current_pos;
    DEBUG("[MYSQL MATCHER] Finished matching, records size: %d, req current "
        "position: %d, resp current position: %d\n",
        record_buf->record_buf_size, req_frames->current_pos, rsp_frames->current_pos);
}
