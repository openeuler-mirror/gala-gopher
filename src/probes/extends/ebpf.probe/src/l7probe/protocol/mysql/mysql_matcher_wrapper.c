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
#include <stdio.h>
#include <string.h>
#include <protocol/utils/binary_decoder.h>
#include "common.h"
#include "mysql_msg_format.h"
#include "mysql_matcher_wrapper.h"

int IsStatusOk(StatusOrInt64 status)
{
    return status.error_code == 0;
}

void SyncRespQueue(struct mysql_packet_msg_s* req_msg, struct frame_buf_s* rsp_frames)
{
    // This handles the case where there are responses that pre-date a request.
    while (rsp_frames->current_pos < rsp_frames->frame_buf_size) {
        struct frame_data_s *rsp_frame;
        struct mysql_packet_msg_s *resp_packet;
        rsp_frame = rsp_frames->frames[rsp_frames->current_pos];
        resp_packet = (struct mysql_packet_msg_s*)rsp_frame->frame;
        if (resp_packet->timestamp_ns < req_msg->timestamp_ns) {
            ++rsp_frames->current_pos;
            DEBUG("Dropping response packet that pre-dates request. Size=%zu [OK=%d "
                  "ERR=%d EOF=%d]\n",
                  resp_packet->data_len, IsOKPacket(resp_packet), IsErrPacket(resp_packet), IsEOFPacket(resp_packet));
            continue;
        }
        break;
    }
}

DequeView GetRespView(size_t req_index, struct frame_buf_s* req_frames, struct frame_buf_s* rsp_frames)
{
    CTX_DCHECK(req_frames->frame_buf_size > 0);
    int count = 0;
    for (; rsp_frames->current_pos < rsp_frames->frame_buf_size; ++rsp_frames->current_pos) {
        struct frame_data_s *rsp_frame;
        struct mysql_packet_msg_s *resp_packet;
        rsp_frame = rsp_frames->frames[rsp_frames->current_pos];
        resp_packet = (struct mysql_packet_msg_s*)rsp_frame->frame;
        if (req_index + 1 < req_frames->frame_buf_size) {
            struct frame_data_s *req_frame;
            struct mysql_packet_msg_s *req_packet;
            req_frame = req_frames->frames[req_index + 1];
            req_packet = (struct mysql_packet_msg_s*)req_frame->frame;

            if (resp_packet->timestamp_ns > req_packet->timestamp_ns) {
                break;
            }
        }

        u8 expected_seq_id = count + 1;
        if (resp_packet->sequence_id != expected_seq_id) {
            DEBUG("Found packet with unexpected sequence ID [expected=%d actual=%d]\n", expected_seq_id,
                  resp_packet->sequence_id);
            break;
        }

        ++count;
    }

    return (DequeView) {
        &rsp_frames->frames[rsp_frames->current_pos - count], 0, count
    };
}

StatusOrInt64 DissectInt(const char* data, size_t msg_size, size_t* offset, size_t size)
{
    if (msg_size < *offset + size) {
        DEBUG("Not enough bytes to dissect int param.\n");
        return (StatusOrInt64) {
            .error_code = -1
        };
    }
    u64 result = 0;
    for (size_t i = 0; i < size; i++) {
        result |= (u8)(data[*offset + size - 1 - i]) << (i * 8);
    }
    *offset += size;
    return (StatusOrInt64) {
        result, 0
    };
}

StatusOrInt64 ProcessLengthEncodedInt(const char* data, u64 data_len, size_t* offset)
{
    if (data == NULL || offset == NULL) {
        return (StatusOrInt64) {
            .error_code = -1
        };
    }
    if (*offset >= data_len) {
        return (StatusOrInt64) {
            .error_code = -1
        };
    }

    u8 first_byte = data[*offset];
    (*offset)++;

#define CHECK_LENGTH(offset, len, data_len)   \
    if (((*(offset)) + (len)) > (data_len)) { \
        return (StatusOrInt64){               \
            .error_code = -1                  \
        };                                    \
    }
    StatusOrInt64 result;
    switch (first_byte) {
    case K_LENC_INT_PREFIX_2B:
        CHECK_LENGTH(offset, 2, data_len);
        result = DissectInt(data, data_len, offset, 2);
        break;
    case K_LENC_INT_PREFIX_3B:
        CHECK_LENGTH(offset, 3, data_len);
        result = DissectInt(data, data_len, offset, 3);
        break;
    case K_LENC_INT_PREFIX_8B:
        CHECK_LENGTH(offset, 8, data_len);
        result = DissectInt(data, data_len, offset, 8);
        break;
    default:
        result = (StatusOrInt64) {
            first_byte, 0
        };
        break;
    }
#undef CHECK_LENGTH
    return result;
}

bool DissectStringParam(struct mysql_packet_msg_s* rsp_msg, size_t* param_offset, char** param)
{
    StatusOrInt64 result = ProcessLengthEncodedInt(rsp_msg->msg, rsp_msg->data_len, param_offset);
    if (!IsStatusOk(result)) {
        return false;
    }
    u64 param_length = result.value;

    if (rsp_msg->data_len < *param_offset + param_length) {
        return false;
    }
    // 分配内存给param指向的字符串
    *param = (char*)malloc(param_length + 1);
    if (*param == NULL) {
        return false;
    }
    memcpy(*param, rsp_msg->msg + *param_offset, param_length);
    (*param)[param_length] = '\0'; // 添加终止字符
    *param_offset += param_length;
    return true;
}

bool DissectNonStringParam(struct mysql_packet_msg_s* rsp_msg, size_t* param_offset)
{
    StatusOrInt64 result = ProcessLengthEncodedInt(rsp_msg->msg, rsp_msg->data_len, param_offset);
    if (!IsStatusOk(result)) {
        return false;
    }
    u64 param_length = result.value;

    if (rsp_msg->data_len < *param_offset + param_length) {
        return false;
    }
    *param_offset += param_length;
    return true;
}

/**
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_eof_packet.html
 */
bool IsEOFPacket(struct mysql_packet_msg_s* rsp_msg)
{
    return ((rsp_msg->command_t == kRespHeaderEOF) && rsp_msg->data_len == 5);
}

/**
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_err_packet.html
 */
bool IsErrPacket(struct mysql_packet_msg_s* rsp_msg)
{
    return ((rsp_msg->command_t == kRespHeaderErr) && rsp_msg->data_len > 3);
}

/**
 * Assume CLIENT_PROTOCOL_41 is set.
 * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_ok_packet.html
 */
bool IsOKPacket(struct mysql_packet_msg_s* rsp_msg)
{
    u8 header = rsp_msg->command_t;

    if (header == kRespHeaderOK && rsp_msg->data_len >= 7) {
        return true;
    }
    if (header == kRespHeaderEOF && rsp_msg->data_len < 9 && !IsEOFPacket(rsp_msg)) {
        return true;
    }
    return false;
}

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_prepare.html#sect_protocol_com_stmt_prepare_response_ok
bool IsStmtPrepareOKPacket(struct mysql_packet_msg_s* rsp_msg)
{
    return (rsp_msg->data_len == 12 && rsp_msg->msg[0] == 0 && rsp_msg->msg[9] == 0);
}

parse_state_t HandleOKMessage(struct mysql_packet_msg_s* rsp_msg, u64* rsp_timestamp)
{
    // Format of OK packet:
    // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_ok_packet.html
    const int kMinOKPacketSize = 7;
    if (rsp_msg->data_len < kMinOKPacketSize) {
        return STATE_INVALID;
    }
    *rsp_timestamp = rsp_msg->timestamp_ns;
    return STATE_SUCCESS;
}

parse_state_t HandleErrMessage(struct mysql_packet_msg_s* rsp_msg, u64* rsp_timestamp, struct record_buf_s* record_buf)
{
    // Format of ERR packet:
    //   1  header: 0xff
    //   2  error_code
    //   1  sql_state_marker
    //   5  sql_state
    //   x  error_message
    // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_err_packet.html
    const int kMinErrPacketSize = 9;

    if (rsp_msg->data_len < kMinErrPacketSize) {
        return STATE_INVALID;
    }
    *rsp_timestamp = rsp_msg->timestamp_ns;
    // TODO error count +1
    ++record_buf->err_count;
    return STATE_SUCCESS;
}

parse_state_t HandleStmtPrepareOKResponse(DequeView* resp_packets, u64* rsp_timestamp)
{
    RETURN_NEEDS_MORE_DATA_IF_EMPTY(resp_packets);
    const u8 kPrepareOKPacketColOffset = 5;
    StatusOrInt64 result;
    struct mysql_packet_msg_s *first_resp_packet;
    first_resp_packet = (struct mysql_packet_msg_s*)resp_packets->packets[resp_packets->start]->frame;
    ++resp_packets->start;
    if (!IsStmtPrepareOKPacket(first_resp_packet)) {
        return STATE_INVALID;
    }
    // Parse num_col.
    size_t offset = kPrepareOKPacketColOffset;
    result = DissectInt(first_resp_packet->msg, first_resp_packet->data_len, &offset, 2);
    if (!IsStatusOk(result)) {
        return STATE_INVALID;
    }
    u16 num_col = result.value;
    // Parse num_param.
    result = DissectInt(first_resp_packet->msg, first_resp_packet->data_len, &offset, 2);
    if (!IsStatusOk(result)) {
        return STATE_INVALID;
    }
    u16 num_param = result.value;

    // TODO(chengruizhe): Handle missing packets more robustly. Assuming no
    // missing packet. If num_col or num_param is non-zero, they might be followed
    // by EOF. Reference:
    // https://dev.mysql.com/doc/internals/en/com-stmt-prepare-response.html.
    u16 min_expected_packets = num_col + num_param;
    if (min_expected_packets > resp_packets->count) {
        return STATE_NEEDS_MORE_DATA;
    }
    *rsp_timestamp = first_resp_packet->timestamp_ns;
    for (int i = 0; i < num_param; ++i) {
        RETURN_NEEDS_MORE_DATA_IF_EMPTY(resp_packets);
        struct mysql_packet_msg_s *param_def_packet =
            (struct mysql_packet_msg_s*)resp_packets->packets[resp_packets->start]->frame;
        ++resp_packets->start;
        parse_state_t parse_state = ProcessColumnDefPacket(param_def_packet);
        if (parse_state != STATE_SUCCESS) {
            return parse_state;
        }
        *rsp_timestamp = param_def_packet->timestamp_ns;
    }
    if (num_param != 0) {
        // Optional EOF packet, based on CLIENT_DEPRECATE_EOF. But difficult to
        // infer CLIENT_DEPRECATE_EOF because num_param can be zero.
        if (resp_packets->count - resp_packets->start > 0) {
            struct mysql_packet_msg_s *eof_packet =
                (struct mysql_packet_msg_s*)resp_packets->packets[resp_packets->start]->frame;
            if (IsEOFPacket(eof_packet)) {
                ++resp_packets->start;
                *rsp_timestamp = eof_packet->timestamp_ns;
            }
        }
    }
    for (int i = 0; i < num_col; ++i) {
        RETURN_NEEDS_MORE_DATA_IF_EMPTY(resp_packets);
        struct mysql_packet_msg_s *col_def_packet =
            (struct mysql_packet_msg_s*)resp_packets->packets[resp_packets->start]->frame;
        ++resp_packets->start;
        parse_state_t parse_state = ProcessColumnDefPacket(col_def_packet);
        if (parse_state != STATE_SUCCESS) {
            return parse_state;
        }
        *rsp_timestamp = col_def_packet->timestamp_ns;
    }
    if (num_col != 0) {
        // Optional EOF packet, based on CLIENT_DEPRECATE_EOF. But difficult to
        // infer CLIENT_DEPRECATE_EOF because num_param can be zero.
        if (resp_packets->count - resp_packets->start > 0) {
            struct mysql_packet_msg_s *eof_packet =
                (struct mysql_packet_msg_s*)resp_packets->packets[resp_packets->start]->frame;
            if (IsEOFPacket(eof_packet)) {
                ++resp_packets->start;
                *rsp_timestamp = eof_packet->timestamp_ns;
            }
        }
    }
    if (resp_packets->count - resp_packets->start > 0) {
        ERROR("Extra packets\n");
    }
    return STATE_SUCCESS;
}

parse_state_t HandleResultsetResponse(DequeView* resp_packets, u64* rsp_timestamp, bool binary_resultset,
                                      bool multi_resultset, struct record_buf_s* record_buf)
{
    RETURN_NEEDS_MORE_DATA_IF_EMPTY(resp_packets);
    struct mysql_packet_msg_s *first_resp_packet;
    size_t param_offset = 0;
    first_resp_packet = (struct mysql_packet_msg_s*)resp_packets->packets[resp_packets->start]->frame;
    ++resp_packets->start;
    // The last resultset of a multi-resultset is just an OK packet.
    if (multi_resultset && IsOKPacket(first_resp_packet)) {
        *rsp_timestamp = first_resp_packet->timestamp_ns;
        ++resp_packets->start;
        return STATE_SUCCESS;
    }
    StatusOrInt64 param_res =
        ProcessLengthEncodedInt(first_resp_packet->msg, first_resp_packet->data_len, &param_offset);
    if (!IsStatusOk(param_res)) {
        return STATE_INVALID;
    }
    u64 num_col = param_res.value;
    if (param_offset != first_resp_packet->data_len) {
        return STATE_INVALID;
    }
    if (num_col == 0) {
        return STATE_INVALID;
    }

    // A resultset has:
    //  1             column_count packet (*already accounted for*)
    //  column_count  column definition packets
    //  0 or 1        EOF packet (if CLIENT_DEPRECATE_EOF is false)
    //  0+            ResultsetRow packets (Spec says 1+, but have seen 0 in
    //  practice). 1             OK or EOF packet
    // Must have at least the minimum number of remaining packets in a response.
    if (resp_packets->count - resp_packets->start < num_col + 1) {
        return STATE_NEEDS_MORE_DATA;
    }
    for (int i = 0; i < num_col; ++i) {
        RETURN_NEEDS_MORE_DATA_IF_EMPTY(resp_packets);
        struct mysql_packet_msg_s *packet =
            (struct mysql_packet_msg_s*)resp_packets->packets[resp_packets->start]->frame;
        ++resp_packets->start;
        parse_state_t parse_state = ProcessColumnDefPacket(packet);
        if (parse_state != STATE_SUCCESS) {
            return parse_state;
        }
    }
    if (IsEOFPacket((struct mysql_packet_msg_s*)resp_packets->packets[resp_packets->start]->frame)) {
        ++resp_packets->start;
    }
    while (resp_packets->start < resp_packets->count) {
        struct mysql_packet_msg_s *packet =
            (struct mysql_packet_msg_s*)resp_packets->packets[resp_packets->start]->frame;
        // TODO(wangshuyuan): Get actual results from the resultset row packets if
        // needed.
        // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response_text_resultset.html
        if (binary_resultset) {
            if (packet->command_t == 0x00) {
                ++resp_packets->start;
                continue;
            } else if (IsOKPacket(packet) || IsEOFPacket(packet) || IsErrPacket(packet)) {
                break;
            } else {
                return STATE_INVALID;
            }
        } else {
            if (IsEOFPacket(packet) || IsErrPacket(packet) || IsOKPacket(packet)) {
                break;
            }
            ++resp_packets->start;
        }
    }
    if (resp_packets->start >= resp_packets->count) {
        return STATE_NEEDS_MORE_DATA;
    }
    struct mysql_packet_msg_s *last_packet =
        (struct mysql_packet_msg_s*)resp_packets->packets[resp_packets->start]->frame;
    if (IsOKPacket(last_packet) || IsEOFPacket(last_packet)) {
        *rsp_timestamp = last_packet->timestamp_ns;
        ++resp_packets->start;
        return STATE_SUCCESS;
    }
    if (IsErrPacket(last_packet)) {
        PX_RETURN_IF_NOT_SUCCESS(HandleErrMessage(last_packet, rsp_timestamp, record_buf));
        ++resp_packets->start;
        return STATE_SUCCESS;
    }
    return STATE_INVALID;
}

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response_text_resultset_column_definition.html
parse_state_t ProcessColumnDefPacket(struct mysql_packet_msg_s* rsp_msg)
{
    size_t offset = 0;
    // catalog
    char *catalog = NULL;
    if (!DissectStringParam(rsp_msg, &offset, &catalog)) {
        return STATE_INVALID;
    }
    if (strcmp(catalog, "def") != 0) {
        free(catalog);
        return STATE_INVALID;
    }
    if (catalog != NULL) {
        free(catalog);
    }

    return STATE_SUCCESS;
}