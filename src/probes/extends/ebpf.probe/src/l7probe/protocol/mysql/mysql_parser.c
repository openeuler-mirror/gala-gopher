/* *****************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangshuyuan
 * Create: 2024-10-08
 * Description:
 * **************************************************************************** */
#include <string.h>
#include <stdint.h>
#include "../utils/binary_decoder.h"
#include "mysql_parser.h"
#include "data_stream.h"
#include "mysql_msg_format.h"

static bool is_first_packet = true;

static NumberRange cmd_length_ranges[32] = {
    [CMD_SLEEP] = {1, 1},
    [CMD_QUIT] = {1, 1},
    [CMD_INITDB] = {1, MAX_PACKET_LENGTH},
    [CMD_QUERY] = {1, MAX_PACKET_LENGTH},
    [CMD_FIELDLIST] = {2, MAX_PACKET_LENGTH},
    [CMD_CREATDB] = {1, MAX_PACKET_LENGTH},
    [CMD_DROPDB] = {1, MAX_PACKET_LENGTH},
    [CMD_REFRESH] = {2, 2},
    [CMD_SHUTDOWN] = {1, 2},
    [CMD_STATISTICS] = {1, 1},
    [CMD_PROCESS_INFO] = {1, 1},
    [CMD_CONNECT] = {1, 1},
    [CMD_PROCESS_KILL] = {1, 5},
    [CMD_DEBUG] = {1, 1},
    [CMD_PING] = {1, 1},
    [CMD_TIME] = {1, 1},
    [CMD_DELAYED_INSERT] = {1, 1},
    [CMD_CHANGE_USER] = {4, MAX_PACKET_LENGTH},
    [CMD_BINLOG_DUMP] = {11, MAX_PACKET_LENGTH},
    [CMD_TABLE_DUMP] = {3, MAX_PACKET_LENGTH},
    [CMD_CONNECT_OUT] = {1, 1},
    [CMD_REGISTER_SLAVE] = {18, MAX_PACKET_LENGTH},
    [CMD_STMT_PREPARE] = {1, MAX_PACKET_LENGTH},
    [CMD_STMT_EXECUTE] = {10, MAX_PACKET_LENGTH},
    [CMD_STMT_SEND_LONG_DATA] = {7, MAX_PACKET_LENGTH},
    [CMD_STMT_CLOSE] = {5, 5},
    [CMD_STMT_RESET] = {5, 5},
    [CMD_SET_OPTION] = {3, 3},
    [CMD_STMT_FETCH] = {9, 9},
    [CMD_DAEMON] = {1, 1},
    [CMD_BINLOG_DUMP_GTID] = {19, 19},
    [CMD_RESET_CONNECTION] = {1, 1}
};

static bool IsValidCommand(uint8_t command_byte)
{
    if (command_byte > MAX_COMMAND_VALUE) {
        return false;
    }
    // The following are internal commands, and should not be sent on the connection.
    // In some sense, they are a valid part of the protocol, as the server will properly respond with
    // error. But for the sake of identifying mis-classified MySQL connections, it helps to call these
    // out as invalid commands.
    switch (command_byte) {
        case CMD_SLEEP:
        case CMD_TIME:
        case CMD_DELAYED_INSERT:
        case CMD_CONNECT_OUT:
        case CMD_DAEMON:
            return false;
        default:
            return true;
    }
}

parse_state_t mysql_parse_packet_msg(struct raw_data_s *raw_data, struct mysql_packet_msg_s *msg)
{
    parse_state_t parse_state;
    int32_t header;
    msg->timestamp_ns = raw_data->timestamp_ns;
    if (!is_first_packet) {
        parse_state = decoder_extract_int32_t(raw_data, &header);
        if (parse_state != STATE_SUCCESS) {
            return parse_state;
        }
    } else {
        is_first_packet = false;
    }
    parse_state = decoder_extract_string(raw_data, &msg->msg, msg->data_len);
    if (parse_state != STATE_SUCCESS) {
        return parse_state;
    }
    return STATE_SUCCESS;
}

parse_state_t mysql_parse_frame(enum message_type_t msg_type, struct raw_data_s *raw_data,
    struct frame_data_s **frame_data)
{
    u32 packet_length;
    u8 sequence_id;
    u8 command;
    if (msg_type != MESSAGE_REQUEST && msg_type != MESSAGE_RESPONSE) {
        return STATE_INVALID;
    }

    if (raw_data->data_len <= PACKET_HEADER_LENGTH) {
        return STATE_NEEDS_MORE_DATA;
    }

    if (is_first_packet) {
        // TODO(wangshuyuan) If the length of the first request packet is greater than 8191, the method of supplementing
        // the header is incorrect.
        packet_length = raw_data->data_len;
        sequence_id = 0;
        command = raw_data->data[raw_data->current_pos];
    } else {
        packet_length = (u8)raw_data->data[raw_data->current_pos] |
            ((u8)raw_data->data[raw_data->current_pos + 1] << 8) |
            ((u8)raw_data->data[raw_data->current_pos + 2] << 16);
        sequence_id = raw_data->data[raw_data->current_pos + 3];
        command = raw_data->data[raw_data->current_pos + PACKET_HEADER_LENGTH];
        if (raw_data->isBrokeData) {
            packet_length = raw_data->data_len - raw_data->current_pos - PACKET_HEADER_LENGTH;
        }
        if ((raw_data->data_len < raw_data->current_pos + PACKET_HEADER_LENGTH + packet_length) && (raw_data->isBrokeData == 0)) {
            return STATE_NEEDS_MORE_DATA;
        }
    }

    // Better fit for matcher (when analyzing structure of packet bodies).
    if (msg_type == MESSAGE_REQUEST) {
        if (!IsValidCommand(command)) {
            return STATE_INVALID;
        }
        // We can constrain the expected lengths, by command type.
        NumberRange length_range = cmd_length_ranges[command];

        if (packet_length < length_range.min || packet_length > length_range.max) {
            return STATE_INVALID;
        }
    }
    *frame_data = (struct frame_data_s *)calloc(1, sizeof(struct frame_data_s));
    if ((*frame_data) == NULL) {
        return STATE_INVALID;
    }
    struct mysql_packet_msg_s *packet_msg;
    packet_msg = init_mysql_msg_s();
    if (packet_msg == NULL) {
        free(*frame_data);
        return STATE_INVALID;
    }
    packet_msg->timestamp_ns = raw_data->timestamp_ns;

    packet_msg->data_len = packet_length;
    packet_msg->sequence_id = sequence_id;
    if (raw_data->isBrokeData == 1) {
        command = (u8)CMD_BROKEN_DATA;
    }
    packet_msg->command_t = command;

    (*frame_data)->frame = packet_msg;
    parse_state_t parse_msg_state;
    parse_msg_state = mysql_parse_packet_msg(raw_data, packet_msg);

    return parse_msg_state;
}

size_t mysql_find_frame_boundary(enum message_type_t msg_type, struct raw_data_s *raw_data)
{
    if (is_first_packet) {
        // the first packet.
        return raw_data->current_pos;
    }
    if (raw_data->data_len < PACKET_HEADER_LENGTH) {
        return PARSER_INVALID_BOUNDARY_INDEX;
    }
    if (msg_type == MESSAGE_RESPONSE) {
        // No real search implemented for responses.
        return raw_data->current_pos;
    }
    if (raw_data->data_len == PACKET_HEADER_LENGTH) {
        return 0;
    }

    // Need at least PACKET_HEADER_LENGTH bytes + 1 command byte in buf.
    size_t i = raw_data->current_pos;
    u32 packet_length = (u8)raw_data->data[i] | ((u8)raw_data->data[i + 1] << 8) | ((u8)raw_data->data[i + 2] << 16);
    u8 sequence_id = raw_data->data[i + 3];
    u8 command = raw_data->data[i + PACKET_HEADER_LENGTH];

    // Requests must have sequence id of 0.
    if (sequence_id != 0) {
        return PARSER_INVALID_BOUNDARY_INDEX;
    }

    // If the command byte isn't a valid command, then this can't a message boundary.
    if (command < 0 || command > MAX_COMMAND_VALUE) {
        return PARSER_INVALID_BOUNDARY_INDEX;
    }

    // We can constrain the expected lengths, by command type.
    NumberRange length_range = cmd_length_ranges[command];
    if (packet_length < length_range.min || packet_length > length_range.max) {
        return PARSER_INVALID_BOUNDARY_INDEX;
    }
    return i;
}