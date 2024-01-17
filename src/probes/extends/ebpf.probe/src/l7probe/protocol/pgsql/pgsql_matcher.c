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
 * Author: zhaoguolin
 * Create: 2023-04-04
 * Description:
 ******************************************************************************/

#include <stdbool.h>
#include <string.h>
#include "common.h"
#include "pgsql_matcher.h"
#include "pgsql_parser.h"

parse_state_t pgsql_handle_query(struct pgsql_regular_msg_s *msg, struct frame_buf_s *req_frames,
                                 struct frame_buf_s *rsp_frames, struct pgsql_query_req_resp_s *req_rsp)
{
    bool found_rsp = false;
    size_t rsp_index = rsp_frames->current_pos;

    if (req_rsp->req == NULL) {
        WARN("[PGSQL MATCHER] Handling query, but req_rsp->req is null.\n");
        return STATE_INVALID;
    }

    // msg.payload中的信息不做保存
    req_rsp->req->timestamp_ns = msg->timestamp_ns;
    for (; rsp_index < rsp_frames->frame_buf_size; ++rsp_index) {
        struct frame_data_s *rsp_frame;
        struct pgsql_regular_msg_s *rsp_msg;
        rsp_frame = rsp_frames->frames[rsp_index];
        rsp_msg = (struct pgsql_regular_msg_s *) rsp_frame->frame;
        if (req_rsp->resp == NULL) {
            WARN("[PGSQL MATCHER] Handling query, but req_rsp->resp is null.\n");
            return STATE_INVALID;
        }
        if (rsp_msg->tag == PGSQL_EMPTY_QUERY_RESP) {
            found_rsp = true;
            req_rsp->resp->timestamp_ns = rsp_msg->timestamp_ns;
            rsp_msg->consumed = true;
            break;
        }
        if (rsp_msg->tag == PGSQL_CMD_COMPLETE) {
            parse_state_t parse_cmd_cmpl;
            found_rsp = true;
            req_rsp->resp->timestamp_ns = rsp_msg->timestamp_ns;
            parse_cmd_cmpl = pgsql_parse_cmd_complete(rsp_msg, req_rsp->resp->cmd_cmpl);
            if (parse_cmd_cmpl != STATE_SUCCESS) {
                return parse_cmd_cmpl;
            }
            rsp_msg->consumed = true;
            break;
        }
        if (rsp_msg->tag == PGSQL_ERR_RETURN) {
            parse_state_t parse_err_ret;
            found_rsp = true;
            req_rsp->resp->timestamp_ns = rsp_msg->timestamp_ns;
            parse_err_ret = pgsql_parse_err_resp(rsp_msg, req_rsp->resp->err_resp);
            if (parse_err_ret != STATE_SUCCESS) {
                return parse_err_ret;
            }
            rsp_msg->consumed = true;
            break;
        }

        // 对SELECT查询(或其他返回行集的查询，如EXPLAIN或SHOW)的响应
        // 通常由RowDescription、零条或多条DataRow消息以及CommandComplete组成
        // 因此，解析到RowDescription和DataRow消息后，不应跳出for循环
        if (rsp_msg->tag == PGSQL_ROW_DESCRIPTION) {
            // req_rsp->resp->row_desc内容不做解析，后续有需要可调用pgsql_parse_row_desc()
            found_rsp = true;
            req_rsp->resp->timestamp_ns = rsp_msg->timestamp_ns;
            rsp_msg->consumed = true;
        }
        if (rsp_msg->tag == PGSQL_DATA_ROW) {
            // data_row内容不做解析，后续有需要可调用pgsql_parse_data_row()
            found_rsp = true;
            req_rsp->resp->timestamp_ns = rsp_msg->timestamp_ns;
            rsp_msg->consumed = true;
        }
    }
    rsp_frames->current_pos = rsp_index;

    if (rsp_frames->current_pos != rsp_frames->frame_buf_size) {
        ++rsp_frames->current_pos;
    }
    if (!found_rsp) {
        DEBUG("[PGSQL MATCHER] Query response not found.\n");
        return STATE_INVALID;
    }
    return STATE_SUCCESS;
}

parse_state_t pgsql_fill_query_resp(struct frame_buf_s *rsp_frames, struct pgsql_query_resp_s *query_rsp)
{
    bool found_row_desc = false;
    bool found_cmd_complete = false;
    bool found_err_rsp = false;
    bool found_empty_rsp = false;
    size_t rsp_index = rsp_frames->current_pos;
    for (; rsp_index < rsp_frames->frame_buf_size; ++rsp_index) {
        struct frame_data_s *rsp_frame;
        struct pgsql_regular_msg_s *rsp_msg;
        rsp_frame = rsp_frames->frames[rsp_index];
        rsp_msg = (struct pgsql_regular_msg_s *) rsp_frame->frame;
        if (rsp_msg->tag == PGSQL_CMD_COMPLETE) {
            parse_state_t parse_cmd_cmpl;
            found_cmd_complete = true;
            query_rsp->timestamp_ns = rsp_msg->timestamp_ns;
            parse_cmd_cmpl = pgsql_parse_cmd_complete(rsp_msg, query_rsp->cmd_cmpl);
            if (parse_cmd_cmpl != STATE_SUCCESS) {
                return parse_cmd_cmpl;
            }
            rsp_msg->consumed = true;
            break;
        }
        if (rsp_msg->tag == PGSQL_ERR_RETURN) {
            parse_state_t parse_err_ret;
            found_err_rsp = true;
            query_rsp->timestamp_ns = rsp_msg->timestamp_ns;
            parse_err_ret = pgsql_parse_err_resp(rsp_msg, query_rsp->err_resp);
            if (parse_err_ret != STATE_SUCCESS) {
                return parse_err_ret;
            }
            rsp_msg->consumed = true;
            break;
        }
        if (rsp_msg->tag == PGSQL_EMPTY_QUERY_RESP) {
            found_empty_rsp = true;
            query_rsp->timestamp_ns = rsp_msg->timestamp_ns;
            rsp_msg->consumed = true;
            break;
        }
        if (rsp_msg->tag == PGSQL_ROW_DESCRIPTION) {
            // req_rsp->resp->row_desc内容不做解析，后续有需要可调用pgsql_parse_row_desc()
            found_row_desc = true;
            query_rsp->timestamp_ns = rsp_msg->timestamp_ns;
            rsp_msg->consumed = true;
        }
        if (rsp_msg->tag == PGSQL_DATA_ROW) {
            // data_row内容不做解析，后续有需要可调用pgsql_parse_data_row()
            rsp_msg->consumed = true;
        }
    }
    rsp_frames->current_pos = rsp_index;

    if (rsp_frames->current_pos != rsp_frames->frame_buf_size) {
        ++rsp_frames->current_pos;
    }
    if (!found_row_desc && !(found_cmd_complete || found_err_rsp || found_empty_rsp)) {
        DEBUG("[PGSQL MATCHER] Did not find one of row description, error return, empty response or cmd complete.\n");
        return STATE_INVALID;
    }
    return STATE_SUCCESS;
}

const char *pgsql_parse_complete_text = "PARSE COMPLETE";

parse_state_t set_cmd_cmpl_msg(void *req_rsp, enum pgsql_tag_t req_rsp_type, const char *cmpl_text)
{
    struct pgsql_cmd_complete_s *cmd_cmpl_msg;
    struct pgsql_bind_req_resp_s *convert_req_rsp;

    convert_req_rsp = (struct pgsql_bind_req_resp_s *) req_rsp;
    if (convert_req_rsp->resp == NULL) {
        WARN("[PGSQL MATCHER] Set cmd complete message, but convert_req_rsp->resp is null.\n");
        return STATE_INVALID;
    }

    cmd_cmpl_msg = init_pgsql_cmd_complete();
    if (cmd_cmpl_msg == NULL) {
        return STATE_INVALID;
    }

    cmd_cmpl_msg->cmd_tag = malloc(strlen(cmpl_text) + 1);
    if (cmd_cmpl_msg->cmd_tag == NULL) {
        free(cmd_cmpl_msg);
        return STATE_INVALID;
    }
    strcpy(cmd_cmpl_msg->cmd_tag, cmpl_text);

    if (req_rsp_type == PGSQL_PARSE_COMPLETE) {
        convert_req_rsp->resp->msg_type = CMD_CMPL_MSG;
        cmd_cmpl_msg->timestamp_ns = convert_req_rsp->resp->timestamp_ns;
        convert_req_rsp->resp->cmd_cmpl_msg = cmd_cmpl_msg;
        return STATE_SUCCESS;
    }

    if (req_rsp_type == PGSQL_BIND_COMPLETE) {
        convert_req_rsp->resp->msg_type = CMD_CMPL_MSG;
        cmd_cmpl_msg->timestamp_ns = convert_req_rsp->resp->timestamp_ns;
        convert_req_rsp->resp->cmd_cmpl_msg = cmd_cmpl_msg;
        return STATE_SUCCESS;
    }

    // 无法处理的类型，释放内存
    free(cmd_cmpl_msg->cmd_tag);
    free(cmd_cmpl_msg);
    return STATE_INVALID;
}

parse_state_t set_error_msg(void *req_rsp, enum pgsql_tag_t req_rsp_type, struct pgsql_regular_msg_s *rsp_msg)
{
    struct pgsql_err_resp_s *err_rsp;
    parse_state_t parse_err_ret;
    err_rsp = init_pgsql_err_resp();
    if (err_rsp == NULL) {
        return STATE_INVALID;
    }
    parse_err_ret = pgsql_parse_err_resp(rsp_msg, err_rsp);
    if (parse_err_ret != STATE_SUCCESS) {
        return parse_err_ret;
    }

    if (req_rsp_type == PGSQL_PARSE_COMPLETE) {
        struct pgsql_parse_req_resp_s *convert_req_rsp = (struct pgsql_parse_req_resp_s *) req_rsp;
        if (convert_req_rsp->resp == NULL) {
            WARN("[PGSQL MATCHER] Set error message, but convert_req_rsp->resp is null.\n");
            return STATE_INVALID;
        }
        convert_req_rsp->resp->msg_type = ERR_RESP_MSG;
        convert_req_rsp->resp->err_resp_msg = err_rsp;
        return STATE_SUCCESS;
    }
    if (req_rsp_type == PGSQL_BIND_COMPLETE) {
        struct pgsql_bind_req_resp_s *convert_req_rsp = (struct pgsql_bind_req_resp_s *) req_rsp;
        if (convert_req_rsp->resp == NULL) {
            WARN("[PGSQL MATCHER] Set error message, but convert_req_rsp->resp is null.\n");
            return STATE_INVALID;
        }
        convert_req_rsp->resp->msg_type = ERR_RESP_MSG;
        convert_req_rsp->resp->err_resp_msg = err_rsp;
        return STATE_SUCCESS;
    }

    // 无法处理的类型，释放内存
    free(err_rsp);
    return STATE_INVALID;
}

struct pgsql_regular_msg_s *pgsql_get_frame_from_buf(struct frame_buf_s *frame_buf, int frame_index)
{
    struct frame_data_s *rsp_frame = frame_buf->frames[frame_index];
    return (struct pgsql_regular_msg_s *) rsp_frame->frame;
}

size_t pgsql_find_first_tag(struct frame_buf_s *frame_buf, const enum pgsql_tag_t tags[], int tag_len)
{
    size_t rsp_index = frame_buf->current_pos;
    for (; rsp_index < frame_buf->frame_buf_size; ++rsp_index) {
        struct frame_data_s *rsp_frame;
        struct pgsql_regular_msg_s *rsp_msg;
        rsp_frame = frame_buf->frames[rsp_index];
        rsp_msg = (struct pgsql_regular_msg_s *) rsp_frame->frame;
        for (int i = 0; i < tag_len; ++i) {
            if (rsp_msg->tag == tags[i]) {
                return rsp_index;
            }
        }
    }

    // 未找到，可按需添加异常标识
    return rsp_index;
}

parse_state_t pgsql_handle_parse(struct pgsql_regular_msg_s *msg, struct frame_buf_s *req_frames,
                                 struct frame_buf_s *rsp_frames, struct pgsql_parse_req_resp_s *req_rsp)
{
    struct pgsql_parse_req_s *parse;
    parse_state_t parse_state;
    size_t rsp_index;
    struct pgsql_regular_msg_s *parse_rsp;
    enum pgsql_tag_t tags[] = {PGSQL_PARSE_COMPLETE, PGSQL_ERR_RETURN};

    parse = init_pgsql_parse_req();
    if (parse == NULL) {
        return STATE_INVALID;
    }
    parse_state = pgsql_parse_parse_msg(msg, parse);
    if (parse_state != STATE_SUCCESS) {
        free_pgsql_parse_req(parse);
        return parse_state;
    }

    rsp_index = pgsql_find_first_tag(rsp_frames, tags, sizeof(tags) / sizeof(enum pgsql_tag_t));
    if (rsp_index == rsp_frames->frame_buf_size) {
        ERROR("[PGSQL MATCHER] Did not find parse complete or error response message.\n");
        free_pgsql_parse_req(parse);
        return STATE_NOT_FOUND;
    }
    parse_rsp = pgsql_get_frame_from_buf(rsp_frames, rsp_index);

    // 刷新rsp_frames当前位置
    rsp_frames->current_pos = rsp_index + 1;

    req_rsp->req = parse;
    if (req_rsp->resp == NULL) {
        WARN("[PGSQL MATCHER] Handling parse, but req_rsp->resp is null.\n");
        return STATE_INVALID;
    }
    req_rsp->resp->timestamp_ns = parse_rsp->timestamp_ns;
    if (parse_rsp->tag == PGSQL_PARSE_COMPLETE) {
        // parse消息中携带的sql预处理查询语句当前不做解析，后续可按需保存至pgsql_state_s进行上下文传递
        parse_state_t set_cmd_cmpl_msg_state = set_cmd_cmpl_msg(req_rsp, PGSQL_PARSE_COMPLETE,
                                                                pgsql_parse_complete_text);
        if (set_cmd_cmpl_msg_state != STATE_SUCCESS) {
            return set_cmd_cmpl_msg_state;
        }
    }
    if (parse_rsp->tag == PGSQL_ERR_RETURN) {
        parse_state_t set_error_msg_state = set_error_msg(req_rsp, PGSQL_PARSE_COMPLETE, parse_rsp);
        if (set_error_msg_state != STATE_SUCCESS) {
            return set_error_msg_state;
        }
    }
    parse_rsp->consumed = true;
    return STATE_SUCCESS;
}

parse_state_t pgsql_fill_stmt_desc_resp(struct frame_buf_s *rsp_frames, struct pgsql_describe_resp_s *desc_rsp)
{
    size_t rsp_index;
    struct pgsql_regular_msg_s *param_desc_rsp;
    parse_state_t parse_param_desc;
    struct pgsql_regular_msg_s *row_desc;
    enum pgsql_tag_t tags[] = {PGSQL_ROW_DESCRIPTION, PGSQL_NO_DATA, PGSQL_ERR_RETURN};
    rsp_index = pgsql_find_first_tag(rsp_frames, tags, sizeof(tags) / sizeof(enum pgsql_tag_t));
    if (rsp_index == rsp_frames->frame_buf_size) {
        ERROR("[PGSQL MATCHER] Did not find row description for statement or error response message.\n");
        return STATE_NOT_FOUND;
    }
    param_desc_rsp = pgsql_get_frame_from_buf(rsp_frames, rsp_index);

    // 刷新rsp_frames当前位置
    rsp_frames->current_pos = rsp_index + 1;

    desc_rsp->timestamp_ns = param_desc_rsp->timestamp_ns;
    if (param_desc_rsp->tag == PGSQL_NO_DATA) {
        desc_rsp->is_no_data = true;
        param_desc_rsp->consumed = true;
        return STATE_SUCCESS;
    }

    if (param_desc_rsp->tag == PGSQL_ERR_RETURN) {
        parse_state_t parse_state;
        desc_rsp->is_err_resp = true;
        parse_state = pgsql_parse_err_resp(param_desc_rsp, desc_rsp->err_resp);
        if (parse_state != STATE_SUCCESS) {
            return parse_state;
        }
        param_desc_rsp->consumed = true;
        return STATE_SUCCESS;
    }

    parse_param_desc = pgsql_parse_param_desc(param_desc_rsp, desc_rsp->param_desc);
    if (parse_param_desc != STATE_SUCCESS) {
        return parse_param_desc;
    }
    if (++rsp_index == rsp_frames->frame_buf_size) {
        WARN("[PGSQL MATCHER] The buffer after parameter description msg is empty.\n");
        return STATE_INVALID;
    }

    rsp_frames->current_pos = rsp_index + 1;
    row_desc = pgsql_get_frame_from_buf(rsp_frames, rsp_index);
    if (row_desc->tag == PGSQL_ROW_DESCRIPTION) {
        parse_state_t parse_row_desc = pgsql_parse_row_desc(row_desc, desc_rsp->row_desc);
        if (parse_row_desc == STATE_SUCCESS) {
            row_desc->consumed = true;
        }
        return parse_row_desc;
    }
    if (row_desc->tag == PGSQL_NO_DATA) {
        desc_rsp->is_no_data = true;
        row_desc->consumed = true;
        return STATE_SUCCESS;
    }

    WARN("[PGSQL MATCHER] Row description or no data msg can not be found after parameter description msg.\n");
    return STATE_INVALID;
}

parse_state_t pgsql_fill_portal_desc_resp(struct frame_buf_s *rsp_frames, struct pgsql_describe_resp_s *desc_rsp)
{
    size_t rsp_index;
    struct pgsql_regular_msg_s *param_desc_rsp;
    enum pgsql_tag_t tags[] = {PGSQL_ROW_DESCRIPTION, PGSQL_NO_DATA, PGSQL_ERR_RETURN};
    rsp_index = pgsql_find_first_tag(rsp_frames, tags, sizeof(tags) / sizeof(enum pgsql_tag_t));
    if (rsp_index == rsp_frames->frame_buf_size) {
        ERROR("[PGSQL MATCHER] Did not find row description for portal or error response message.\n");
        return STATE_NOT_FOUND;
    }
    param_desc_rsp = pgsql_get_frame_from_buf(rsp_frames, rsp_index);

    // 刷新rsp_frames当前位置
    rsp_frames->current_pos = rsp_index + 1;
    desc_rsp->timestamp_ns = param_desc_rsp->timestamp_ns;
    if (param_desc_rsp->tag == PGSQL_NO_DATA) {
        desc_rsp->is_no_data = true;
        param_desc_rsp->consumed = true;
        return STATE_SUCCESS;
    }

    if (param_desc_rsp->tag == PGSQL_ERR_RETURN) {
        desc_rsp->is_err_resp = true;
        return pgsql_parse_err_resp(param_desc_rsp, desc_rsp->err_resp);
    }
    return pgsql_parse_row_desc(param_desc_rsp, desc_rsp->row_desc);
}

parse_state_t pgsql_handle_describe(struct pgsql_regular_msg_s *msg, struct frame_buf_s *req_frames,
                                    struct frame_buf_s *rsp_frames, struct pgsql_describe_req_resp_s *req_rsp)
{
    parse_state_t parse_parse_desc = pgsql_parse_describe(msg, req_rsp->req);
    if (parse_parse_desc != STATE_SUCCESS) {
        return parse_parse_desc;
    }
    if (req_rsp->req != NULL && req_rsp->req->desc_type == PGSQL_DESCRIBE_TYPE_STATEMENT) {
        return pgsql_fill_stmt_desc_resp(rsp_frames, req_rsp->resp);
    }
    if (req_rsp->resp != NULL && req_rsp->req->desc_type == PGSQL_DESCRIBE_TYPE_PORTAL) {
        return pgsql_fill_portal_desc_resp(rsp_frames, req_rsp->resp);
    }
    WARN("[PGSQL MATCHER] Invalid describe target type: %c.\n", req_rsp->req->desc_type);
    return STATE_INVALID;
}

const char *pgsql_bind_complete_text = "BIND COMPLETE";

parse_state_t pgsql_handle_bind(struct pgsql_regular_msg_s *msg, struct frame_buf_s *req_frames,
                                struct frame_buf_s *rsp_frames, struct pgsql_bind_req_resp_s *req_rsp)
{
    struct pgsql_bind_req_s *bind_req;
    parse_state_t parse_state;
    size_t rsp_index;
    struct pgsql_regular_msg_s *bind_rsp;
    enum pgsql_tag_t tags[] = {PGSQL_BIND_COMPLETE, PGSQL_ERR_RETURN};

    bind_req = init_pgsql_bind_req();
    if (bind_req == NULL) {
        WARN("[PGSQL MATCHER] Failed to malloc bind_req.\n");
        return STATE_INVALID;
    }
    parse_state = pgsql_parse_bind_req(msg, bind_req);
    if (parse_state != STATE_SUCCESS) {
        free_pgsql_bind_req(bind_req);
        return parse_state;
    }

    rsp_index = pgsql_find_first_tag(rsp_frames, tags, sizeof(tags) / sizeof(enum pgsql_tag_t));
    if (rsp_index == rsp_frames->frame_buf_size) {
        DEBUG("[PGSQL MATCHER] Did not find bind complete or error response message.\n");
        return STATE_NOT_FOUND;
    }
    bind_rsp = pgsql_get_frame_from_buf(rsp_frames, rsp_index);

    // 刷新rsp_frames当前位置
    rsp_frames->current_pos = rsp_index + 1;

    req_rsp->req = bind_req;
    if (req_rsp->resp == NULL) {
        WARN("[PGSQL MATCHER] Handling bind message, req_rsp->resp is null.\n");
        return STATE_INVALID;
    }

    req_rsp->resp->timestamp_ns = bind_rsp->timestamp_ns;
    if (bind_rsp->tag == PGSQL_BIND_COMPLETE) {
        // 可按需扩展校验绑定的sql预处理语句
        parse_state_t set_cmd_cmpl_msg_state = set_cmd_cmpl_msg(req_rsp, PGSQL_BIND_COMPLETE, pgsql_bind_complete_text);
        if (set_cmd_cmpl_msg_state != STATE_SUCCESS) {
            return set_cmd_cmpl_msg_state;
        }
    }
    if (bind_rsp->tag == PGSQL_ERR_RETURN) {
        parse_state_t set_error_msg_state = set_error_msg(req_rsp, PGSQL_BIND_COMPLETE, bind_rsp);
        if (set_error_msg_state != STATE_SUCCESS) {
            return set_error_msg_state;
        }
    }

    bind_rsp->consumed = true;
    return STATE_SUCCESS;
}

parse_state_t pgsql_handle_execute(struct pgsql_regular_msg_s *msg, struct frame_buf_s *req_frames,
                                   struct frame_buf_s *rsp_frames, struct pgsql_execute_req_resp_s *req_rsp)
{
    if (req_rsp->req == NULL) {
        WARN("[PGSQL MATCHER] Handling execute message, req_rsp.req is null.\n");
        return STATE_INVALID;
    }

    // msg.payload中的信息不做保存
    req_rsp->req->timestamp_ns = msg->timestamp_ns;
    return pgsql_fill_query_resp(rsp_frames, req_rsp->resp);
}

void pgsql_matcher_add_record(struct pgsql_regular_msg_s *req, uint64_t resp_timestamp_ns,
                              struct record_buf_s *record_buf)
{
    struct pgsql_regular_msg_s *resp;
    struct pgsql_record_s *pgsql_record;
    struct record_data_s *record_data;
    if (record_buf->record_buf_size >= RECORD_BUF_SIZE) {
        WARN("[PGSQL MATCHER] The record buffer is full.\n");
        ++record_buf->err_count;
        return;
    }

    // req、resp的payload字段均为作保存
    req->consumed = true;
    resp = (struct pgsql_regular_msg_s *) malloc(sizeof(struct pgsql_regular_msg_s));
    if (resp == NULL) {
        ERROR("[PGSQL MATCHER] Failed to malloc pgsql_regular_msg_s for resp_msg.\n");
        return;
    }
    memset(resp, 0, sizeof(struct pgsql_regular_msg_s));

    resp->timestamp_ns = resp_timestamp_ns;
    pgsql_record = (struct pgsql_record_s *) malloc(sizeof(struct pgsql_record_s));
    if (pgsql_record == NULL) {
        ERROR("[PGSQL MATCHER] Failed to malloc pgsql_record_s for pgsql_record.\n");
        free_pgsql_regular_msg(resp);
        return;
    }
    memset(pgsql_record, 0, sizeof(struct pgsql_record_s));

    pgsql_record->req_msg = req;
    pgsql_record->resp_msg = resp;
    record_data = (struct record_data_s *) malloc(sizeof(struct record_data_s));
    if (record_data == NULL) {
        ERROR("[PGSQL MATCHER] Failed to malloc record_data_s for record_data.\n");
        free_pgsql_regular_msg(resp);
        free_pgsql_record(pgsql_record);
        return;
    }
    memset(record_data, 0, sizeof(struct record_data_s));
    record_data->record = pgsql_record;
    record_data->latency = resp_timestamp_ns - req->timestamp_ns;
    record_buf->records[record_buf->record_buf_size] = record_data;
    ++record_buf->record_buf_size;
}

void handle_simple_query(struct pgsql_regular_msg_s *req, struct frame_buf_s *req_frames,
                         struct frame_buf_s *rsp_frames, struct record_buf_s *record_buf)
{
    struct pgsql_query_req_resp_s *req_rsp;
    parse_state_t parse_query_state;
    req_rsp = init_pgsql_query_req_resp();
    if (req_rsp == NULL) {
        return;
    }
    parse_query_state = pgsql_handle_query(req, req_frames, rsp_frames, req_rsp);
    if (parse_query_state != STATE_SUCCESS) {
        DEBUG("[PGSQL MATCHER] An error occurred while processing a simple query, state: %d.\n", parse_query_state);
        ++record_buf->err_count;
        free_pgsql_query_req_resp(req_rsp);
        return;
    }
    pgsql_matcher_add_record(req, req_rsp->resp->timestamp_ns, record_buf);
    free_pgsql_query_req_resp(req_rsp);
}

void handle_parse_req(struct pgsql_regular_msg_s *req, struct frame_buf_s *req_frames, struct frame_buf_s *rsp_frames,
                      struct record_buf_s *record_buf)
{
    struct pgsql_parse_req_resp_s *req_rsp;
    parse_state_t parse_parse_state;
    req_rsp = init_pgsql_parse_req_resp();
    if (req_rsp == NULL) {
        return;
    }
    parse_parse_state = pgsql_handle_parse(req, req_frames, rsp_frames, req_rsp);
    if (parse_parse_state != STATE_SUCCESS) {
        WARN("[PGSQL MATCHER] An error occurred while processing a parse request, state: %d.\n", parse_parse_state);
        ++record_buf->err_count;
        free_pgsql_parse_req_resp(req_rsp);
        return;
    }
    pgsql_matcher_add_record(req, req_rsp->resp->timestamp_ns, record_buf);
    free_pgsql_parse_req_resp(req_rsp);
}

void handle_bind_req(struct pgsql_regular_msg_s *req, struct frame_buf_s *req_frames, struct frame_buf_s *rsp_frames,
                     struct record_buf_s *record_buf)
{
    struct pgsql_bind_req_resp_s *req_rsp;
    parse_state_t parse_bind_state;
    req_rsp = init_pgsql_bind_req_resp();
    if (req_rsp == NULL) {
        DEBUG("[PGSQL MATCHER] Handling bind req message, but req_rsp is null.\n");
        return;
    }
    parse_bind_state = pgsql_handle_bind(req, req_frames, rsp_frames, req_rsp);
    if (parse_bind_state != STATE_SUCCESS) {
        DEBUG("[PGSQL MATCHER] An error occurred while processing a bind request, state: %d.\n", parse_bind_state);
        ++record_buf->err_count;
        free_pgsql_bind_req_resp(req_rsp);
        return;
    }
    if (req_rsp->resp == NULL) {
        WARN("[PGSQL MATCHER] Handling bind req message, but req_rsp->resp is null.\n");
        free_pgsql_bind_req_resp(req_rsp);
        return;
    }
    pgsql_matcher_add_record(req, req_rsp->resp->timestamp_ns, record_buf);
    free_pgsql_bind_req_resp(req_rsp);
}

void handle_describe_req(struct pgsql_regular_msg_s *req, struct frame_buf_s *req_frames,
                         struct frame_buf_s *rsp_frames, struct record_buf_s *record_buf)
{
    struct pgsql_describe_req_resp_s *req_rsp;
    parse_state_t parse_desc_state;
    req_rsp = init_pgsql_describe_req_resp();
    if (req_rsp == NULL) {
        return;
    }
    parse_desc_state = pgsql_handle_describe(req, req_frames, rsp_frames, req_rsp);
    if (parse_desc_state != STATE_SUCCESS) {
        WARN("[PGSQL MATCHER] An error occurred while processing a describe request, state: %d.\n", parse_desc_state);
        ++record_buf->err_count;
        free_pgsql_describe_req_resp(req_rsp);
        return;
    }
    pgsql_matcher_add_record(req, req_rsp->resp->timestamp_ns, record_buf);
    free_pgsql_describe_req_resp(req_rsp);
}

void handle_execute_req(struct pgsql_regular_msg_s *req, struct frame_buf_s *req_frames, struct frame_buf_s *rsp_frames,
                        struct record_buf_s *record_buf)
{
    struct pgsql_execute_req_resp_s *req_rsp;
    parse_state_t parse_exe_state;
    req_rsp = init_pgsql_execute_req_resp();
    if (req_rsp == NULL) {
        return;
    }
    parse_exe_state = pgsql_handle_execute(req, req_frames, rsp_frames, req_rsp);
    if (parse_exe_state != STATE_SUCCESS) {
        DEBUG("[PGSQL MATCHER] An error occurred while processing a execute request, state: %d.\n", parse_exe_state);
        ++record_buf->err_count;
        free_pgsql_execute_req_resp(req_rsp);
        return;
    }
    pgsql_matcher_add_record(req, req_rsp->resp->timestamp_ns, record_buf);
    free_pgsql_execute_req_resp(req_rsp);
}

void pgsql_match_frames(struct frame_buf_s *req_frames, struct frame_buf_s *rsp_frames,
                        struct record_buf_s *record_buf)
{
    DEBUG("[PGSQL MATCHER] Req frames size: %d, resp frames size: %d\n", req_frames->frame_buf_size, rsp_frames->frame_buf_size);
    size_t req_index, resp_index;
    size_t unconsumed_index;
    req_index = req_frames->current_pos;
    resp_index = rsp_frames->current_pos;
    while (req_index < req_frames->frame_buf_size && resp_index < rsp_frames->frame_buf_size) {
        struct frame_data_s *req_frame;
        struct pgsql_regular_msg_s *req_msg;
        req_frame = req_frames->frames[req_index];
        if (req_frame == NULL) {
            break;
        }
        req_msg = (struct pgsql_regular_msg_s *) req_frame->frame;
        ++req_index;
        if (req_msg == NULL) {
            break;
        }
        switch (req_msg->tag) {
            case PGSQL_READY_FOR_QUERY:
            case PGSQL_SYNC:
            case PGSQL_COPY_FAIL:
            case PGSQL_CLOSE:
            case PGSQL_PASSWD:
                req_msg->consumed = true;
                DEBUG("[PGSQL MATCHER] Ignore tag: %c.\n", req_msg->tag);
                break;
            case PGSQL_SIMPLE_QUERY:
                handle_simple_query(req_msg, req_frames, rsp_frames, record_buf);
                break;
            case PGSQL_EXTENDED_QUERY_PARSE:
                handle_parse_req(req_msg, req_frames, rsp_frames, record_buf);
                break;
            case PGSQL_EXTENDED_QUERY_BIND:
                handle_bind_req(req_msg, req_frames, rsp_frames, record_buf);
                break;
            case PGSQL_EXTENDED_QUERY_DESCRIBE:
                handle_describe_req(req_msg, req_frames, rsp_frames, record_buf);
                break;
            case PGSQL_EXTENDED_QUERY_EXECUTE:
                handle_execute_req(req_msg, req_frames, rsp_frames, record_buf);
                break;
            default:
                req_msg->consumed = true;
                DEBUG("[PGSQL MATCHER] Unresolvable or invalid tag: %c.\n", req_msg->tag);
                break;
        }
    }

    // pgsql协议为有序协议，删除已匹配的请求和所有的响应
    unconsumed_index = req_frames->current_pos;
    while (unconsumed_index != req_frames->frame_buf_size) {
        struct frame_data_s *req_frame;
        struct pgsql_regular_msg_s *req_msg;
        req_frame = req_frames->frames[unconsumed_index];
        if (req_frame == NULL) {
            break;
        }
        req_msg = (struct pgsql_regular_msg_s *) req_frame->frame;

        // 终结帧: req(X)无响应报文，直接当作consumed处理
        if (!req_msg->consumed && req_msg->tag != PGSQL_TERMINATE) {
            break;
        }
        unconsumed_index++;
    }
    if (unconsumed_index != req_frames->current_pos) {
        req_frames->current_pos = unconsumed_index;
        rsp_frames->current_pos = rsp_frames->frame_buf_size;
        record_buf->req_count = req_frames->current_pos;
        record_buf->resp_count = rsp_frames->current_pos;
    }
    DEBUG("[PGSQL MATCHER] Finished matching, records size: %d, req current position: %d, resp current position: %d\n",
          record_buf->record_buf_size, req_frames->current_pos, rsp_frames->current_pos);
}
