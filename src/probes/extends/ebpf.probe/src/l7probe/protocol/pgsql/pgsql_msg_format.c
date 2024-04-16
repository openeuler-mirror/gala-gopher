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
 * Create: 2023-04-27
 * Description:
 ******************************************************************************/

#include <stdlib.h>
#include <string.h>
#include "pgsql_msg_format.h"

struct pgsql_tag_enum_value_s pgsql_tag_enum_values[] = {
    PGSQL_TAG_ENUM_VALUE(true, PGSQL_COPY_DATA),
    PGSQL_TAG_ENUM_VALUE(true, PGSQL_COPY_DONE),
    PGSQL_TAG_ENUM_VALUE(true, PGSQL_SIMPLE_QUERY),
    PGSQL_TAG_ENUM_VALUE(true, PGSQL_EXTENDED_QUERY_PARSE),
    PGSQL_TAG_ENUM_VALUE(true, PGSQL_EXTENDED_QUERY_BIND),
    PGSQL_TAG_ENUM_VALUE(true, PGSQL_EXTENDED_QUERY_EXECUTE),
    PGSQL_TAG_ENUM_VALUE(true, PGSQL_FASTCALL_FUNCTION_CALL),
    PGSQL_TAG_ENUM_VALUE(true, PGSQL_CLOSE),
    PGSQL_TAG_ENUM_VALUE(true, PGSQL_EXTENDED_QUERY_DESCRIBE),
    PGSQL_TAG_ENUM_VALUE(true, PGSQL_SYNC),
    PGSQL_TAG_ENUM_VALUE(true, PGSQL_FLUSH),
    PGSQL_TAG_ENUM_VALUE(true, PGSQL_TERMINATE),
    PGSQL_TAG_ENUM_VALUE(true, PGSQL_COPY_FAIL),
    PGSQL_TAG_ENUM_VALUE(false, PGSQL_COPY_DATA),
    PGSQL_TAG_ENUM_VALUE(false, PGSQL_COPY_DONE),
    PGSQL_TAG_ENUM_VALUE(false, PGSQL_CMD_COMPLETE),
    PGSQL_TAG_ENUM_VALUE(false, PGSQL_ERR_RETURN),
    PGSQL_TAG_ENUM_VALUE(false, PGSQL_READY_FOR_QUERY),
    PGSQL_TAG_ENUM_VALUE(false, PGSQL_EMPTY_QUERY_RESP),
    PGSQL_TAG_ENUM_VALUE(false, PGSQL_PARSE_COMPLETE),
    PGSQL_TAG_ENUM_VALUE(false, PGSQL_BIND_COMPLETE),
    PGSQL_TAG_ENUM_VALUE(false, PGSQL_CLOSE_COMPLETE),
    PGSQL_TAG_ENUM_VALUE(false, PGSQL_PARAMETER_STATUS),
    PGSQL_TAG_ENUM_VALUE(false, PGSQL_SECRET_KEY),
    PGSQL_TAG_ENUM_VALUE(false, PGSQL_ROW_DESCRIPTION),
    PGSQL_TAG_ENUM_VALUE(false, PGSQL_NO_DATA),
    PGSQL_TAG_ENUM_VALUE(false, PGSQL_PARAMETER_DESCRIPTION),
    PGSQL_TAG_ENUM_VALUE(false, PGSQL_DATA_ROW),
    PGSQL_TAG_ENUM_VALUE(false, PGSQL_START_COPY_IN),
    PGSQL_TAG_ENUM_VALUE(false, PGSQL_START_COPY_OUT),
    PGSQL_TAG_ENUM_VALUE(false, PGSQL_START_COPY_BOTH),
    PGSQL_TAG_ENUM_VALUE(false, PGSQL_AUTH)
};

const int pgsql_tag_enum_values_count = sizeof(pgsql_tag_enum_values) / sizeof(struct pgsql_tag_enum_value_s);

bool contains_pgsql_tag(char tag)
{
    for (int i = 0; i < pgsql_tag_enum_values_count; ++i) {
        if (pgsql_tag_enum_values[i].value == tag) {
            return true;
        }
    }
    return false;
}

struct pgsql_regular_msg_s *init_pgsql_regular_msg(void)
{
    struct pgsql_regular_msg_s *msg = (struct pgsql_regular_msg_s *) malloc(sizeof(struct pgsql_regular_msg_s));
    if (msg == NULL) {
        return NULL;
    }
    memset(msg, 0, sizeof(struct pgsql_regular_msg_s));
    return msg;
}

void free_pgsql_regular_msg(struct pgsql_regular_msg_s *msg)
{
    if (msg == NULL) {
        return;
    }
    if (msg->payload_data != NULL) {
        free(msg->payload_data);
        msg->payload_data = NULL;
    }
    free(msg);
}


struct pgsql_row_desc_field_s *init_pgsql_row_desc_field(void)
{
    struct pgsql_row_desc_field_s *field = (struct pgsql_row_desc_field_s *) malloc(
        sizeof(struct pgsql_row_desc_field_s));
    if (field == NULL) {
        return NULL;
    }
    memset(field, 0, sizeof(struct pgsql_row_desc_field_s));
    return field;
}

void free_pgsql_row_desc_field(struct pgsql_row_desc_field_s *field)
{
    if (field == NULL) {
        return;
    }
    if (field->name != NULL) {
        free(field->name);
        field->name = NULL;
    }
    free(field);
}

struct pgsql_startup_msg_s *init_pgsql_startup_msg(void)
{
    struct pgsql_startup_msg_s *msg = (struct pgsql_startup_msg_s *)malloc(sizeof(struct pgsql_startup_msg_s));
    if (msg == NULL) {
        return NULL;
    }
    memset(msg, 0, sizeof(struct pgsql_startup_msg_s));
    return msg;
}

void free_pgsql_startup_msg(struct pgsql_startup_msg_s *msg)
{
    if (msg == NULL) {
        return;
    }
    free(msg);
}

struct pgsql_parse_req_s *init_pgsql_parse_req(void)
{
    struct pgsql_parse_req_s *req = (struct pgsql_parse_req_s *) malloc(sizeof(struct pgsql_parse_req_s));
    if (req == NULL) {
        return NULL;
    }
    memset(req, 0, sizeof(struct pgsql_parse_req_s));
    return req;
}

void free_pgsql_parse_req(struct pgsql_parse_req_s *parse_req)
{
    if (parse_req == NULL) {
        return;
    }
    if (parse_req->stmt_name != NULL) {
        free(parse_req->stmt_name);
        parse_req->stmt_name = NULL;
    }
    if (parse_req->query != NULL) {
        free(parse_req->query);
        parse_req->query = NULL;
    }
    free(parse_req);
}

struct pgsql_combo_resp_s *init_pgsql_combo_resp(void)
{
    struct pgsql_combo_resp_s *rsp = (struct pgsql_combo_resp_s *) malloc(sizeof(struct pgsql_combo_resp_s));
    if (rsp == NULL) {
        return NULL;
    }
    memset(rsp, 0, sizeof(struct pgsql_combo_resp_s));
    return rsp;
}

void free_pgsql_combo_resp(struct pgsql_combo_resp_s *combo_resp)
{
    if (combo_resp == NULL) {
        return;
    }

    if (combo_resp->msg_type == CMD_CMPL_MSG && combo_resp->cmd_cmpl_msg) {
        free_pgsql_cmd_complete(combo_resp->cmd_cmpl_msg);
    }

    if (combo_resp->msg_type == ERR_RESP_MSG && combo_resp->err_resp_msg) {
        free_pgsql_err_resp(combo_resp->err_resp_msg);
    }
    free(combo_resp);
}

struct pgsql_parse_req_resp_s *init_pgsql_parse_req_resp(void)
{
    struct pgsql_parse_req_resp_s *req_rsp = (struct pgsql_parse_req_resp_s *) malloc(
        sizeof(struct pgsql_parse_req_resp_s));
    if (req_rsp == NULL) {
        return NULL;
    }
    memset(req_rsp, 0, sizeof(struct pgsql_parse_req_resp_s));

    req_rsp->req = init_pgsql_parse_req();
    if (req_rsp->req == NULL) {
        goto err;
    }
    req_rsp->resp = init_pgsql_combo_resp();
    if (req_rsp->resp == NULL) {
        goto err;
    }
    return req_rsp;

err:
    free_pgsql_parse_req_resp(req_rsp);
    return NULL;
}

void free_pgsql_parse_req_resp(struct pgsql_parse_req_resp_s *parse_req_resp)
{
    if (parse_req_resp == NULL) {
        return;
    }
    if (parse_req_resp->req != NULL) {
        free_pgsql_parse_req(parse_req_resp->req);
    }
    if (parse_req_resp->resp != NULL) {
        free_pgsql_combo_resp(parse_req_resp->resp);
    }
    free(parse_req_resp);
}


struct pgsql_bind_req_s *init_pgsql_bind_req(void)
{
    struct pgsql_bind_req_s *req = (struct pgsql_bind_req_s *) malloc(sizeof(struct pgsql_bind_req_s));
    if (req == NULL) {
        return NULL;
    }
    memset(req, 0, sizeof(struct pgsql_bind_req_s));
    return req;
}

void free_pgsql_bind_req(struct pgsql_bind_req_s *bind_req)
{
    if (bind_req == NULL) {
        return;
    }
    if (bind_req->dest_portal_name != NULL) {
        free(bind_req->dest_portal_name);
    }
    if (bind_req->src_prepared_stat_name != NULL) {
        free(bind_req->src_prepared_stat_name);
    }
    free(bind_req);
}

struct pgsql_bind_req_resp_s *init_pgsql_bind_req_resp(void)
{
    struct pgsql_bind_req_resp_s *req_rsp = (struct pgsql_bind_req_resp_s *) malloc(
        sizeof(struct pgsql_bind_req_resp_s));
    if (req_rsp == NULL) {
        return NULL;
    }
    memset(req_rsp, 0, sizeof(struct pgsql_bind_req_resp_s));

    req_rsp->req = init_pgsql_bind_req();
    if (req_rsp->req == NULL) {
        goto err;
    }
    req_rsp->resp = init_pgsql_combo_resp();
    if (req_rsp->resp == NULL) {
        goto err;
    }
    return req_rsp;

err:
    free_pgsql_bind_req_resp(req_rsp);
    return NULL;
}

void free_pgsql_bind_req_resp(struct pgsql_bind_req_resp_s *bind_req_rsp)
{
    if (bind_req_rsp == NULL) {
        return;
    }
    if (bind_req_rsp->req != NULL) {
        free_pgsql_bind_req(bind_req_rsp->req);
        bind_req_rsp->req = NULL;
    }
    if (bind_req_rsp->resp != NULL) {
        free_pgsql_combo_resp(bind_req_rsp->resp);
        bind_req_rsp->resp = NULL;
    }
    free(bind_req_rsp);
}

struct pgsql_describe_req_s *init_pgsql_describe_req(void)
{
    struct pgsql_describe_req_s *req = (struct pgsql_describe_req_s *) malloc(sizeof(struct pgsql_describe_req_s));
    if (req == NULL) {
        return NULL;
    }
    memset(req, 0, sizeof(struct pgsql_describe_req_s));
    return req;
}

void free_pgsql_describe_req(struct pgsql_describe_req_s *desc_req)
{
    if (desc_req == NULL) {
        return;
    }
    if (desc_req->name != NULL) {
        free(desc_req->name);
        desc_req->name = NULL;
    }
    free(desc_req);
}

struct pgsql_param_description_s *init_pgsql_param_description(void)
{
    struct pgsql_param_description_s *param_desc = (struct pgsql_param_description_s *) malloc(
        sizeof(struct pgsql_param_description_s));
    if (param_desc == NULL) {
        return NULL;
    }
    memset(param_desc, 0, sizeof(struct pgsql_param_description_s));
    return param_desc;
}

void free_pgsql_param_description(struct pgsql_param_description_s *param_desc)
{
    if (param_desc == NULL) {
        return;
    }
    free(param_desc);
}


struct pgsql_row_description_s *init_pgsql_row_description(void)
{
    struct pgsql_row_description_s *row_desc = (struct pgsql_row_description_s *) malloc(
        sizeof(struct pgsql_row_description_s));
    if (row_desc == NULL) {
        return NULL;
    }
    memset(row_desc, 0, sizeof(struct pgsql_row_description_s));
    return row_desc;
}

void free_pgsql_row_description(struct pgsql_row_description_s *row_desc)
{
    if (row_desc == NULL) {
        return;
    }

    for (int i = 0; i < row_desc->row_desc_field_size; i++) {
        free_pgsql_row_desc_field(row_desc->row_desc_fields[i]);
        row_desc->row_desc_fields[i] = NULL;
    }
    free(row_desc);
}


struct pgsql_err_resp_s *init_pgsql_err_resp(void)
{
    struct pgsql_err_resp_s *err_rsp = (struct pgsql_err_resp_s *) malloc(sizeof(struct pgsql_err_resp_s));
    if (err_rsp == NULL) {
        return NULL;
    }
    memset(err_rsp, 0, sizeof(struct pgsql_err_resp_s));
    return err_rsp;
}

void free_pgsql_err_resp(struct pgsql_err_resp_s *err_rsp)
{
    if (err_rsp == NULL) {
        return;
    }
    if (err_rsp->pgsql_err_code != NULL) {
        free(err_rsp->pgsql_err_code);
        err_rsp->pgsql_err_code = NULL;
    }
    free(err_rsp);
}

struct pgsql_describe_resp_s *init_pgsql_describe_resp(void)
{
    struct pgsql_describe_resp_s *rsp = (struct pgsql_describe_resp_s *) malloc(sizeof(struct pgsql_describe_resp_s));
    if (rsp == NULL) {
        return NULL;
    }
    memset(rsp, 0, sizeof(struct pgsql_describe_resp_s));

    rsp->param_desc = init_pgsql_param_description();
    if (rsp->param_desc == NULL) {
        goto err;
    }
    rsp->row_desc = init_pgsql_row_description();
    if (rsp->row_desc == NULL) {
        goto err;
    }
    rsp->err_resp = init_pgsql_err_resp();
    if (rsp->err_resp == NULL) {
        goto err;
    }
    return rsp;

err:
    free_pgsql_describe_resp(rsp);
    return NULL;
}

void free_pgsql_describe_resp(struct pgsql_describe_resp_s *desc_rsp)
{
    if (desc_rsp == NULL) {
        return;
    }
    if (desc_rsp->param_desc != NULL) {
        free_pgsql_param_description(desc_rsp->param_desc);
        desc_rsp->param_desc = NULL;
    }
    if (desc_rsp->row_desc != NULL) {
        free_pgsql_row_description(desc_rsp->row_desc);
        desc_rsp->row_desc = NULL;
    }
    if (desc_rsp->err_resp != NULL) {
        free_pgsql_err_resp(desc_rsp->err_resp);
        desc_rsp->err_resp = NULL;
    }
    free(desc_rsp);
}

struct pgsql_describe_req_resp_s *init_pgsql_describe_req_resp(void)
{
    struct pgsql_describe_req_resp_s *desc_req_rsp = (struct pgsql_describe_req_resp_s *) malloc(
        sizeof(struct pgsql_describe_req_resp_s));
    if (desc_req_rsp == NULL) {
        return NULL;
    }
    memset(desc_req_rsp, 0, sizeof(struct pgsql_describe_req_resp_s));

    desc_req_rsp->req = init_pgsql_describe_req();
    if (desc_req_rsp->req == NULL) {
        goto err;
    }
    desc_req_rsp->resp = init_pgsql_describe_resp();
    if (desc_req_rsp->resp == NULL) {
        goto err;
    }
    return desc_req_rsp;

err:
    free_pgsql_describe_req_resp(desc_req_rsp);
    return NULL;
}

void free_pgsql_describe_req_resp(struct pgsql_describe_req_resp_s *desc_req_rsp)
{
    if (desc_req_rsp == NULL) {
        return;
    }
    if (desc_req_rsp->req != NULL) {
        free_pgsql_describe_req(desc_req_rsp->req);
        desc_req_rsp->req = NULL;
    }
    if (desc_req_rsp->resp != NULL) {
        free_pgsql_describe_resp(desc_req_rsp->resp);
        desc_req_rsp->resp = NULL;
    }
    free(desc_req_rsp);
}

struct pgsql_execute_req_s *init_pgsql_execute_req(void)
{
    struct pgsql_execute_req_s *exec_req = (struct pgsql_execute_req_s *) malloc(sizeof(struct pgsql_execute_req_s));
    if (exec_req == NULL) {
        return NULL;
    }
    memset(exec_req, 0, sizeof(struct pgsql_execute_req_s));
    return exec_req;
}

void free_pgsql_execute_req_s(struct pgsql_execute_req_s *exec_req)
{
    if (exec_req == NULL) {
        return;
    }
    if (exec_req->query != NULL) {
        free(exec_req->query);
        exec_req->query = NULL;
    }
    free(exec_req);
}

struct pgsql_cmd_complete_s *init_pgsql_cmd_complete(void)
{
    struct pgsql_cmd_complete_s *cmd_cmpl = (struct pgsql_cmd_complete_s *) malloc(sizeof(struct pgsql_cmd_complete_s));
    if (cmd_cmpl == NULL) {
        return NULL;
    }
    memset(cmd_cmpl, 0, sizeof(struct pgsql_cmd_complete_s));
    return cmd_cmpl;
}

void free_pgsql_cmd_complete(struct pgsql_cmd_complete_s *cmd_cmpl)
{
    if (cmd_cmpl == NULL) {
        return;
    }
    if (cmd_cmpl->cmd_tag != NULL) {
        free(cmd_cmpl->cmd_tag);
        cmd_cmpl->cmd_tag = NULL;
    }
    free(cmd_cmpl);
}

struct pgsql_query_resp_s *init_pgsql_query_resp(void)
{
    struct pgsql_query_resp_s *rsp = (struct pgsql_query_resp_s *) malloc(sizeof(struct pgsql_query_resp_s));
    if (rsp == NULL) {
        return NULL;
    }
    memset(rsp, 0, sizeof(struct pgsql_query_resp_s));

    rsp->row_desc = init_pgsql_row_description();
    if (rsp->row_desc == NULL) {
        goto err;
    }
    rsp->cmd_cmpl = init_pgsql_cmd_complete();
    if (rsp->cmd_cmpl == NULL) {
        goto err;
    }
    rsp->err_resp = init_pgsql_err_resp();
    if (rsp->err_resp == NULL) {
        goto err;
    }
    return rsp;

err:
    free_pgsql_query_resp(rsp);
    return NULL;
}

void free_pgsql_query_resp(struct pgsql_query_resp_s *query_rsp)
{
    if (query_rsp == NULL) {
        return;
    }
    if (query_rsp->row_desc != NULL) {
        free_pgsql_row_description(query_rsp->row_desc);
        query_rsp->row_desc = NULL;
    }
    if (query_rsp->cmd_cmpl != NULL) {
        free_pgsql_cmd_complete(query_rsp->cmd_cmpl);
        query_rsp->cmd_cmpl = NULL;
    }
    if (query_rsp->err_resp != NULL) {
        free_pgsql_err_resp(query_rsp->err_resp);
        query_rsp->err_resp = NULL;
    }
    free(query_rsp);
}

struct pgsql_execute_req_resp_s *init_pgsql_execute_req_resp(void)
{
    struct pgsql_execute_req_resp_s *exec_req_rsp = (struct pgsql_execute_req_resp_s *) malloc(
        sizeof(struct pgsql_execute_req_resp_s));
    if (exec_req_rsp == NULL) {
        return NULL;
    }
    memset(exec_req_rsp, 0, sizeof(struct pgsql_execute_req_resp_s));
    exec_req_rsp->req = init_pgsql_execute_req();
    if (exec_req_rsp->req == NULL) {
        goto err;
    }
    exec_req_rsp->resp = init_pgsql_query_resp();
    if (exec_req_rsp->resp == NULL) {
        goto err;
    }
    return exec_req_rsp;

err:
    free_pgsql_execute_req_resp(exec_req_rsp);
    return NULL;
}

void free_pgsql_execute_req_resp(struct pgsql_execute_req_resp_s *exec_req_rsp)
{
    if (exec_req_rsp == NULL) {
        return;
    }
    if (exec_req_rsp->req != NULL) {
        free_pgsql_execute_req_s(exec_req_rsp->req);
        exec_req_rsp->req = NULL;
    }
    if (exec_req_rsp->resp != NULL) {
        free_pgsql_query_resp(exec_req_rsp->resp);
        exec_req_rsp->resp = NULL;
    }
    free(exec_req_rsp);
}


struct pgsql_query_req_s *init_pgsql_query_req(void)
{
    struct pgsql_query_req_s *req = (struct pgsql_query_req_s *) malloc(sizeof(struct pgsql_query_req_s));
    if (req == NULL) {
        return NULL;
    }
    memset(req, 0, sizeof(struct pgsql_query_req_s));
    return req;
}

void free_pgsql_query_req(struct pgsql_query_req_s *query_req)
{
    if (query_req == NULL) {
        return;
    }
    if (query_req->query != NULL) {
        free(query_req->query);
        query_req->query = NULL;
    }
    free(query_req);
}

struct pgsql_query_req_resp_s *init_pgsql_query_req_resp(void)
{
    struct pgsql_query_req_resp_s *req_rsp = (struct pgsql_query_req_resp_s *) malloc(
        sizeof(struct pgsql_query_req_resp_s));
    if (req_rsp == NULL) {
        return NULL;
    }
    memset(req_rsp, 0, sizeof(struct pgsql_query_req_resp_s));
    req_rsp->req = init_pgsql_query_req();
    if (req_rsp->req == NULL) {
        goto err;
    }
    req_rsp->resp = init_pgsql_query_resp();
    if (req_rsp->resp == NULL) {
        goto err;
    }
    return req_rsp;

err:
    free_pgsql_query_req_resp(req_rsp);
    return NULL;
}

void free_pgsql_query_req_resp(struct pgsql_query_req_resp_s *query_req_rsp)
{
    if (query_req_rsp == NULL) {
        return;
    }
    if (query_req_rsp->req != NULL) {
        free_pgsql_query_req(query_req_rsp->req);
        query_req_rsp->req = NULL;
    }
    if (query_req_rsp->resp != NULL) {
        free_pgsql_query_resp(query_req_rsp->resp);
        query_req_rsp->resp = NULL;
    }
    free(query_req_rsp);
}

void free_pgsql_record(struct pgsql_record_s *record)
{
    if (record == NULL) {
        return;
    }

    /* resp_msg was manually made in pgsql_matcher_add_record(), so need to free here. */
    if (record->resp_msg != NULL) {
        free_pgsql_regular_msg(record->resp_msg);
        record->resp_msg = NULL;
    }

    free(record);
}
