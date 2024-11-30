/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: algorithmofdish
 * Create: 2024-10-24
 * Description: trace viewer format module
 ******************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include "common.h"
#include "tprofiling.h"
#include "trace_viewer_fmt.h"

static u64 async_evt_id = 1;

u64 gen_async_event_id()
{
    return async_evt_id++;
}

int event_complete_to_json_str(struct trace_event_fmt_s *evt_fmt, strbuf_t *buf)
{
    int ret;

    ret = snprintf(buf->buf, buf->size,
        "{\"%s\": \"%s\", \"%s\": \"%s\", \"%s\": \"%c\", "
        "\"%s\": %u, \"%s\": %u, \"%s\": %llu, "
        "\"%s\": %.3lf, \"%s\": {%s}",
        TRACE_FIELD_EVENT_CATEGORY, evt_fmt->category,
        TRACE_FIELD_EVENT_NAME, evt_fmt->name,
        TRACE_FIELD_EVENT_PHASE, evt_fmt->phase,
        TRACE_FIELD_EVENT_PID, evt_fmt->pid,
        TRACE_FIELD_EVENT_TID, evt_fmt->tid,
        TRACE_FIELD_EVENT_TIMESTAMP, evt_fmt->ts / NSEC_PER_USEC,
        TRACE_FIELD_EVENT_DURATION, (double)evt_fmt->duration / NSEC_PER_USEC,
        TRACE_FIELD_EVENT_ARGS, evt_fmt->args);
    if (ret < 0 || ret >= buf->size) {
        return -ERR_TP_NO_BUFF;
    }
    strbuf_update_offset(buf, ret);

    if (evt_fmt->sf != 0) {
        ret = snprintf(buf->buf, buf->size, ", \"%s\": \"%llu\"",
            TRACE_FIELD_EVENT_STACK_REF, evt_fmt->sf);
        if (ret < 0 || ret >= buf->size) {
            return -ERR_TP_NO_BUFF;
        }
        strbuf_update_offset(buf, ret);
    }

    ret = snprintf(buf->buf, buf->size, "}");
    if (ret < 0 || ret >= buf->size) {
        return -ERR_TP_NO_BUFF;
    }
    strbuf_update_offset(buf, ret);

    return 0;
}

int event_async_to_json_str(struct trace_event_fmt_s *evt_fmt, strbuf_t *buf)
{
    int ret;
        //evt_fmt.phase = EVENT_PHASE_ASYNC_START;

    if (evt_fmt->category[0] == 'o' && evt_fmt->category[1] == 'f') {
        // offcpu
        ret = snprintf(buf->buf, buf->size,
            "{\"%s\": \"%s\", \"%s\": \"%s\", \"%s\": \"%c\", "
            "\"%s\": %u, \"%s\": %u, \"%s\": %llu, "
            "\"%s\": %llu, \"%s\": \"%s\", \"%s\": {%s}",
            TRACE_FIELD_EVENT_CATEGORY, evt_fmt->category,
            TRACE_FIELD_EVENT_NAME, evt_fmt->name,
            TRACE_FIELD_EVENT_PHASE, evt_fmt->phase,
            TRACE_FIELD_EVENT_PID, evt_fmt->pid,
            TRACE_FIELD_EVENT_TID, evt_fmt->tid,
            TRACE_FIELD_EVENT_TIMESTAMP, evt_fmt->ts / NSEC_PER_USEC,
            TRACE_FIELD_EVENT_ID, evt_fmt->id,
            TRACE_FIELD_EVENT_CNAME, evt_fmt->cname,
            TRACE_FIELD_EVENT_ARGS, evt_fmt->args);
        if (ret < 0 || ret >= buf->size) {
            return -ERR_TP_NO_BUFF;
        }
        strbuf_update_offset(buf, ret);
        if (evt_fmt->sf != 0) {
            ret = snprintf(buf->buf, buf->size, ", \"%s\": \"%llu\"",
                TRACE_FIELD_EVENT_STACK_REF, evt_fmt->sf);
            if (ret < 0 || ret >= buf->size) {
                return -ERR_TP_NO_BUFF;
            }
            strbuf_update_offset(buf, ret);
        }

        ret = snprintf(buf->buf, buf->size, "}");
        if (ret < 0 || ret >= buf->size) {
            return -ERR_TP_NO_BUFF;
        }
        strbuf_update_offset(buf, ret);
    } else {
        // oncpu
        ret = snprintf(buf->buf, buf->size,
            "{\"%s\": \"%s\", \"%s\": \"%s\", \"%s\": \"%c\", "
            "\"%s\": %u, \"%s\": %u, \"%s\": %llu, "
            "\"%s\": %llu, \"%s\": \"%s\", \"%s\": {%s}}",
            TRACE_FIELD_EVENT_CATEGORY, evt_fmt->category,
            TRACE_FIELD_EVENT_NAME, evt_fmt->name,
            TRACE_FIELD_EVENT_PHASE, evt_fmt->phase,
            TRACE_FIELD_EVENT_PID, evt_fmt->pid,
            TRACE_FIELD_EVENT_TID, evt_fmt->tid,
            TRACE_FIELD_EVENT_TIMESTAMP, evt_fmt->ts / NSEC_PER_USEC,
            TRACE_FIELD_EVENT_ID, evt_fmt->id,
            TRACE_FIELD_EVENT_CNAME, evt_fmt->cname,
            TRACE_FIELD_EVENT_ARGS, evt_fmt->args);
        if (ret < 0 || ret >= buf->size) {
            return -ERR_TP_NO_BUFF;
        }
        strbuf_update_offset(buf, ret);
    }

    return 0;
}

int event_sample_to_json_str(struct trace_event_fmt_s *evt_fmt, strbuf_t *buf)
{
    int ret;

    ret = snprintf(buf->buf, buf->size,
        "{\"%s\": \"%s\", \"%s\": \"%s\", \"%s\": \"%c\", "
        "\"%s\": %u, \"%s\": %u, \"%s\": %llu, "
        "\"%s\": {%s}",
        TRACE_FIELD_EVENT_CATEGORY, evt_fmt->category,
        TRACE_FIELD_EVENT_NAME, evt_fmt->name,
        TRACE_FIELD_EVENT_PHASE, evt_fmt->phase,
        TRACE_FIELD_EVENT_PID, evt_fmt->pid,
        TRACE_FIELD_EVENT_TID, evt_fmt->tid,
        TRACE_FIELD_EVENT_TIMESTAMP, evt_fmt->ts / NSEC_PER_USEC,
        TRACE_FIELD_EVENT_ARGS, evt_fmt->args);
    if (ret < 0 || ret >= buf->size) {
        return -ERR_TP_NO_BUFF;
    }
    strbuf_update_offset(buf, ret);

    if (evt_fmt->sf != 0) {
        ret = snprintf(buf->buf, buf->size, ", \"%s\": \"%llu\"",
            TRACE_FIELD_EVENT_STACK_REF, evt_fmt->sf);
        if (ret < 0 || ret >= buf->size) {
            return -ERR_TP_NO_BUFF;
        }
        strbuf_update_offset(buf, ret);
    }

    ret = snprintf(buf->buf, buf->size, "}");
    if (ret < 0 || ret >= buf->size) {
        return -ERR_TP_NO_BUFF;
    }
    strbuf_update_offset(buf, ret);

    return 0;
}

int event_counter_to_json_str(struct trace_event_fmt_s *evt_fmt, strbuf_t *buf)
{
    int ret;

    ret = snprintf(buf->buf, buf->size,
        "{\"%s\": \"%s\", \"%s\": \"%s\", \"%s\": \"%c\", "
        "\"%s\": %u, \"%s\": %llu, "
        "\"%s\": {%s}}",
        TRACE_FIELD_EVENT_CATEGORY, evt_fmt->category,
        TRACE_FIELD_EVENT_NAME, evt_fmt->name,
        TRACE_FIELD_EVENT_PHASE, evt_fmt->phase,
        TRACE_FIELD_EVENT_PID, evt_fmt->pid,
        TRACE_FIELD_EVENT_TIMESTAMP, evt_fmt->ts / NSEC_PER_USEC,
        TRACE_FIELD_EVENT_ARGS, evt_fmt->args);
    if (ret < 0 || ret >= buf->size) {
        return -ERR_TP_NO_BUFF;
    }
    strbuf_update_offset(buf, ret);

    return 0;
}

int event_instant_to_json_str(struct trace_event_fmt_s *evt_fmt, strbuf_t *buf)
{
    int ret;

    ret = snprintf(buf->buf, buf->size,
        "{\"%s\": \"%s\", \"%s\": \"%s\", \"%s\": \"%c\", "
        "\"%s\": %u, \"%s\": %u, \"%s\": %llu, "
        "\"%s\": \"%c\", \"%s\": {%s}}",
        TRACE_FIELD_EVENT_CATEGORY, evt_fmt->category,
        TRACE_FIELD_EVENT_NAME, evt_fmt->name,
        TRACE_FIELD_EVENT_PHASE, evt_fmt->phase,
        TRACE_FIELD_EVENT_PID, evt_fmt->pid,
        TRACE_FIELD_EVENT_TID, evt_fmt->tid,
        TRACE_FIELD_EVENT_TIMESTAMP, evt_fmt->ts / NSEC_PER_USEC,
        TRACE_FIELD_EVENT_SCOPE, evt_fmt->scope,
        TRACE_FIELD_EVENT_ARGS, evt_fmt->args);
    if (ret < 0 || ret >= buf->size) {
        return -ERR_TP_NO_BUFF;
    }
    strbuf_update_offset(buf, ret);

    return 0;
}

int event_meta_to_json_str(struct trace_event_fmt_s *evt_fmt, strbuf_t *buf)
{
    int ret;

    ret = snprintf(buf->buf, buf->size,
        "{\"%s\": \"%s\", \"%s\": \"%c\", \"%s\": %u, \"%s\": {%s}}",
        TRACE_FIELD_EVENT_NAME, evt_fmt->name,
        TRACE_FIELD_EVENT_PHASE, evt_fmt->phase,
        TRACE_FIELD_EVENT_PID, evt_fmt->pid,
        TRACE_FIELD_EVENT_ARGS, evt_fmt->args);
    if (ret < 0 || ret >= buf->size) {
        return -ERR_TP_NO_BUFF;
    }
    strbuf_update_offset(buf, ret);

    return 0;
}

int trace_event_fmt_to_json_str(struct trace_event_fmt_s *evt_fmt, char *buf, int size)
{
    strbuf_t strbuf = {
        .buf = buf,
        .size = size
    };

    switch (evt_fmt->phase)
    {
        case EVENT_PHASE_COMPLETE:
            return event_complete_to_json_str(evt_fmt, &strbuf);
        case EVENT_PHASE_ASYNC_START:
        case EVENT_PHASE_ASYNC_INSTANT:
        case EVENT_PHASE_ASYNC_END:
            return event_async_to_json_str(evt_fmt, &strbuf);
        case EVENT_PHASE_SAMPLE:
            return event_sample_to_json_str(evt_fmt, &strbuf);
        case EVENT_PHASE_COUNTER:
            return event_counter_to_json_str(evt_fmt, &strbuf);
        case EVENT_PHASE_INSTANT:
            return event_instant_to_json_str(evt_fmt, &strbuf);
        case EVENT_PHASE_META:
            return event_meta_to_json_str(evt_fmt, &strbuf);
        default:
            TP_WARN("Unknown event phase %c\n", evt_fmt->phase);
            return -1;
    }
}

int trace_file_fill_head(FILE *fp)
{
    int ret;

    ret = fprintf(fp, "{\"%s\": [\n{}", TRACE_FIELD_EVENTS);
    if  (ret < 0) {
        TP_ERROR("Failed to write local file, ret=%d\n", ret);
        return -1;
    }
    return 0;
}

int trace_file_fill_tail(FILE *fp)
{
    int ret;

    ret = fprintf(fp, "\n}");
    if  (ret < 0) {
        TP_ERROR("Failed to write local file, ret=%d\n", ret);
        return -1;
    }
    return 0;
}

/*
int stack_node_to_json_str(struct stack_node_s *stack_node, strbuf_t *buf)
{
    const char *end = "}";
    int ret;

    ret = snprintf(buf->buf, buf->size,
        "\"%llu\": {\"%s\": \"%s\", \"%s\": \"%s\"",
        stack_node->id,
        TRACE_FIELD_STACK_CATEGORY, EVENT_CATEGORY_FUNC,
        TRACE_FIELD_STACK_NAME, stack_node->func_name);
    if (ret < 0 || ret >= buf->size) {
        return -ERR_TP_NO_BUFF;
    }
    strbuf_update_offset(buf, ret);

    if (stack_node->parent != NULL) {
        ret = snprintf(buf->buf, buf->size, ", \"%s\": \"%llu\"",
            TRACE_FIELD_STACK_PARENT, stack_node->parent->id);
        if (ret < 0 || ret >= buf->size) {
            return -ERR_TP_NO_BUFF;
        }
        strbuf_update_offset(buf, ret);
    }

    ret = strbuf_append_str_with_check(buf, end, strlen(end));
    if (ret) {
        return -ERR_TP_NO_BUFF;
    }

    return 0;
}

int local_write_stack_node_iter(FILE *fp, struct stack_node_s *stack_node, char *is_first)
{
    char buf[1024];
    strbuf_t strbuf = {
        .buf = buf,
        .size = sizeof(buf)
    };
    struct stack_node_s *child, *tmp;
    int ret;

    buf[0] = 0;
    ret = stack_node_to_json_str(stack_node, &strbuf);
    if (ret) {
        return ret;
    }
    if (strbuf.size > 0) {
        strbuf.buf[0] = 0;
    } else {
        return -ERR_TP_NO_BUFF;
    }
    if (*is_first) {
        ret = fprintf(fp, "%s", buf);
    } else {
        ret = fprintf(fp, ",\n%s", buf);
    }
    if  (ret < 0) {
        TP_ERROR("Failed to write local file, ret=%d\n", ret);
        return -1;
    }
    *is_first = 0;

    if (stack_node->childs != NULL) {
        HASH_ITER(hh, stack_node->childs, child, tmp) {
            ret = local_write_stack_node_iter(fp, child, is_first);
            if (ret) {
                return -1;
            }
        }
    }

    return 0;
}

int trace_file_fill_stack_tree(FILE *fp, struct stack_node_s *stack_root)
{
    struct stack_node_s *child, *tmp;
    char is_first = 1;
    int ret;

    ret = fprintf(fp, "\"%s\": {", TRACE_FIELD_STACKS);
    if  (ret < 0) {
        TP_ERROR("Failed to write local file, ret=%d\n", ret);
        return -1;
    }

    if (stack_root->childs != NULL) {
        HASH_ITER(hh, stack_root->childs, child, tmp) {
            ret = local_write_stack_node_iter(fp, child, &is_first);
            if (ret) {
                return -1;
            }
        }
    }

    ret = fprintf(fp, "\n}");
    if  (ret < 0) {
        TP_ERROR("Failed to write local file, ret=%d\n", ret);
        return -1;
    }
    return 0;
}
*/

/*
 * Output format like:
 *   "1": {"category": "func", "name": "funcA"},
 *   "2": {"category": "func", "name": "funcB", "parent": "1"}
 */
int stack_trace_file_fill_stack_node(struct local_store_s *local_storage, struct stack_node_s *node)
{
    FILE *fp = local_storage->stack_fp;
    char *prefix = "";
    int saved_offset;
    int ret;

    saved_offset = ftell(fp);
    if (saved_offset == -1) {
        TP_ERROR("Failed to read offset of local tmp stack file, err=%s\n", strerror(errno));
        return -1;
    }

    if (local_storage->is_stack_write) {
        prefix = ",\n";
    }
    ret = fprintf(fp, "%s\"%llu\": {\"%s\": \"%s\", \"%s\": \"%s\"",
        prefix, node->id, TRACE_FIELD_STACK_CATEGORY, EVENT_CATEGORY_FUNC,
        TRACE_FIELD_STACK_NAME, node->func_name);
    if (ret < 0) {
        TP_WARN("Failed to write local tmp stack file, ret=%d\n", ret);
        goto reset;
    }

    if (node->parent != NULL) {
        ret = fprintf(fp, ", \"%s\": \"%llu\"",
            TRACE_FIELD_STACK_PARENT, node->parent->id);
        if (ret < 0) {
            TP_WARN("Failed to write local tmp stack file, ret=%d\n", ret);
            goto reset;
        }
    }

    ret = fprintf(fp, "}");
    if (ret < 0) {
        TP_WARN("Failed to write local tmp stack file, ret=%d\n", ret);
        goto reset;
    }

    local_storage->is_stack_write = 1;
    return 0;
reset:
    if (fseek(fp, saved_offset, SEEK_SET) != 0) {
        TP_ERROR("Failed to reset offset of local tmp stack file\n");
    }
    return -1;
}

int trace_file_fill_stack_from_file(FILE *fp, FILE *stack_fp)
{
    char buf[8192];
    int rd_sz;
    int ret;

    if (stack_fp == NULL) {
        return 0;
    }

    ret = fprintf(fp, "\"%s\": {", TRACE_FIELD_STACKS);
    if  (ret < 0) {
        TP_ERROR("Failed to write local file, ret=%d\n", ret);
        return -1;
    }

    ret = fseek(stack_fp, 0, SEEK_SET);
    if (ret != 0) {
        TP_ERROR("Failed to reset offset to zero of local tmp stack file\n");
        return -1;
    }

    buf[0] = 0;
    while((rd_sz = fread(buf, 1, sizeof(buf), stack_fp)) > 0) {
        if (fwrite(buf, 1, rd_sz, fp) != rd_sz) {
            TP_ERROR("Failed to write local file, err=%s\n", strerror(errno));
            return -1;
        }
    }
    if (ferror(stack_fp)) {
        TP_ERROR("Error reading from tmp stack file\n");
        return -1;
    }

    ret = fprintf(fp, "\n}");
    if  (ret < 0) {
        TP_ERROR("Failed to write local file, ret=%d\n", ret);
        return -1;
    }
    return 0;
}

int trace_file_fill_event_from_buffer(struct local_store_s *local_storage)
{
    return trace_file_fill_event_from_buffer2(local_storage, local_storage->buf);
}

int trace_file_fill_event_from_buffer2(struct local_store_s *local_storage, char *buf)
{
    int ret;

    ret = fprintf(local_storage->fp, ",\n%s", buf);
    if (ret < 0) {
        TP_ERROR("Failed to write local file, ret=%d\n", ret);
        local_storage->buf[0] = 0;
        return -1;
    }

    local_storage->buf[0] = 0;
    return 0;
}

void cleanup_proc_meta(struct proc_meta *proc_meta_written)
{
    struct proc_meta *meta, *tmp;

    HASH_ITER(hh, proc_meta_written, meta, tmp) {
        HASH_DEL(proc_meta_written, meta);
        free(meta);
    }
}