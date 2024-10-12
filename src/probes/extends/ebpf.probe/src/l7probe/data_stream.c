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
 * Create: 2023-05-31
 * Description:
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "protocol/expose/protocol_parser.h"
#include "data_stream.h"


static void destroy_frame_data(enum proto_type_t type, struct frame_data_s* frame_data)
{
    free_frame_data_s(type, frame_data);
}

static int push_frame_data(struct data_stream_s *data_stream, const struct frame_data_s* frame_data)
{
    struct frame_buf_s *frame_buf = &(data_stream->frame_bufs);

    if (frame_buf->frame_buf_size >= __FRAME_BUF_SIZE) {
        return -1;
    }

    frame_buf->frames[frame_buf->frame_buf_size] = (struct frame_data_s *)frame_data;
    frame_buf->frame_buf_size++;
    return 0;
}

struct api_stats* create_api_stats(char* api)
{
    struct api_stats* api_stats = (struct api_stats*) malloc(sizeof(struct api_stats));
    if (api_stats == NULL) {
        ERROR("Failed to malloc struct api_stats.\n");
        return NULL;
    }
    memset(api_stats, 0, sizeof(struct api_stats));
    (void) snprintf(api_stats->id.api, MAX_API_LEN, "%s", api);
    return api_stats;
}

void destroy_api_stats(struct api_stats *api_stats)
{
    struct api_stats *item, *tmp;
    H_ITER(api_stats, item, tmp) {
        H_DEL(api_stats, item);
        free(item);
    }
}

static void destroy_raw_data(struct raw_data_s* raw_data)
{
    (void)free(raw_data);
}

static struct raw_data_s* create_raw_data(size_t data_size)
{
    struct raw_data_s* raw_data;
    size_t mem_size = data_size + sizeof(struct raw_data_s);

    raw_data = (struct raw_data_s *)malloc(mem_size);
    if (raw_data == NULL) {
        return NULL;
    }

    raw_data->data_len = data_size;
    return raw_data;
}

static int push_raw_data(struct data_stream_s *data_stream, const struct raw_data_s* raw_data)
{
    struct raw_buf_s *raw_buf = &(data_stream->raw_bufs);

    if (raw_buf->raw_buf_size >= __RAW_BUF_SIZE) {
        return -1;
    }

    raw_buf->raw_datas[raw_buf->raw_buf_size] = (struct raw_data_s *)raw_data;
    raw_buf->raw_buf_size++;
    return 0;
}

static struct raw_data_s* replace_top_raw_data(struct data_stream_s *data_stream, const struct raw_data_s* new_data)
{
    struct raw_buf_s *raw_buf = &(data_stream->raw_bufs);

    if (raw_buf->raw_buf_size == 0) {
        return NULL;
    }

    struct raw_data_s* raw_data = raw_buf->raw_datas[0];
    if (raw_data == NULL) {
        return NULL;
    }

    raw_buf->raw_datas[0] = (struct raw_data_s *)new_data;
    return raw_data;
}

static struct raw_data_s* pop_raw_data(struct data_stream_s *data_stream)
{
    struct raw_buf_s *raw_buf = &(data_stream->raw_bufs);

    if (raw_buf->raw_buf_size == 0) {
        return NULL;
    }

    struct raw_data_s* raw_data = raw_buf->raw_datas[0];
    if (raw_data == NULL) {
        return NULL;
    }

    for (int i = 1; i < raw_buf->raw_buf_size && i < __RAW_BUF_SIZE; i++) {
        raw_buf->raw_datas[i - 1] = raw_buf->raw_datas[i];
    }
    raw_buf->raw_datas[raw_buf->raw_buf_size - 1] = NULL;
    raw_buf->raw_buf_size--;
    return raw_data;
}

static struct raw_data_s* peek_raw_data(struct data_stream_s *data_stream)
{
    struct raw_buf_s *raw_buf = &(data_stream->raw_bufs);

    if (raw_buf->raw_buf_size == 0) {
        return NULL;
    }

    struct raw_data_s* raw_data = raw_buf->raw_datas[0];
    return raw_data;
}

static struct raw_data_s* __do_overlay_raw_data(const struct raw_data_s* dst_data, const struct raw_data_s* src_data)
{
    char *p;
    struct raw_data_s* new_raw_data;
    size_t mem_size = dst_data->data_len + src_data->data_len + sizeof(struct raw_data_s);

    new_raw_data = (struct raw_data_s *)malloc(mem_size);
    if (new_raw_data == NULL) {
        return NULL;
    }

    new_raw_data->data_len = mem_size - sizeof(struct raw_data_s);
    new_raw_data->timestamp_ns = dst_data->timestamp_ns;
    new_raw_data->current_pos = dst_data->current_pos;
    new_raw_data->flags = 0;

    p = new_raw_data->data;
    (void)memcpy(p, dst_data->data, dst_data->data_len);

    p += dst_data->data_len;
    (void)memcpy(p, src_data->data, src_data->data_len);

    return new_raw_data;
}

static int overlay_raw_data(struct data_stream_s *data_stream)
{
    struct raw_data_s *overlay_data, *poped_data, *replaced_data;
    struct raw_buf_s *raw_buf = &(data_stream->raw_bufs);

    if (raw_buf->raw_buf_size < 2) {
        return -1;
    }

    if ((raw_buf->raw_datas[0] == NULL) || (raw_buf->raw_datas[1] == NULL)) {
        return -1;
    }

    overlay_data = __do_overlay_raw_data(raw_buf->raw_datas[0], raw_buf->raw_datas[1]);
    if (overlay_data == NULL) {
        return -1;
    }

    // Pop and free 1st raw data
    poped_data = pop_raw_data(data_stream);
    if (poped_data) {
        destroy_raw_data(poped_data);
    }

    // Replace and free 2nd raw data
    replaced_data = replace_top_raw_data(data_stream, overlay_data);
    if (replaced_data) {
        destroy_raw_data(replaced_data);
    } else {
        destroy_raw_data(overlay_data);
    }

    return 0;
}

static void __do_pop_frames(enum proto_type_t type, struct frame_buf_s *frame_bufs)
{
    int start;
    struct frame_data_s *frame;
    if (frame_bufs->current_pos == 0) {
        return;
    }
    for (int i = 0; i <= frame_bufs->current_pos - 1 && i < __FRAME_BUF_SIZE; i++) {
        frame = frame_bufs->frames[i];
        if (frame) {
            destroy_frame_data(type, frame);
        }
        frame_bufs->frames[i] = NULL;
    }

    start = 0;
    for (int i = frame_bufs->current_pos; i < frame_bufs->frame_buf_size && i < __FRAME_BUF_SIZE && start < __FRAME_BUF_SIZE; i++) {
        frame_bufs->frames[start++] = frame_bufs->frames[i];
        frame_bufs->frames[i] = NULL;
    }
    frame_bufs->frame_buf_size -= frame_bufs->current_pos;
    frame_bufs->current_pos = 0;

    return;
}

void data_stream_pop_frames(struct data_stream_s *data_stream)
{
    __do_pop_frames(data_stream->type, &(data_stream->frame_bufs));
    return;
}

int init_data_stream(struct data_stream_s *data_stream)
{
    (void)memset(data_stream, 0, sizeof(struct data_stream_s));
    return 0;
}

void deinit_data_stream(struct data_stream_s *data_stream)
{
    struct frame_data_s *frame_data;

    for (int i = 0; i < data_stream->raw_bufs.raw_buf_size && i < __RAW_BUF_SIZE; i++) {
        if (data_stream->raw_bufs.raw_datas[i] != NULL) {
            destroy_raw_data(data_stream->raw_bufs.raw_datas[i]);
            data_stream->raw_bufs.raw_datas[i] = NULL;
        }
    }
    data_stream->raw_bufs.raw_buf_size = 0;

    for (int i = 0; i < data_stream->frame_bufs.frame_buf_size && i < __FRAME_BUF_SIZE; i++) {
        if (data_stream->frame_bufs.frames[i] != NULL) {
            frame_data = data_stream->frame_bufs.frames[i];
            destroy_frame_data(data_stream->type, frame_data);
            data_stream->frame_bufs.frames[i] = NULL;
        }
    }
    data_stream->frame_bufs.frame_buf_size = 0;
    return;
}

enum parse_rslt_e {
    PARSE_NEXT = 0,
    PARSE_REBOUND,
    PARSE_REPEAT,
    PARSE_OVERLAY,
    PARSE_STOP,

    PARSE_ERROR
};


static enum parse_rslt_e __do_parse_frames(enum message_type_t msg_type, struct data_stream_s *data_stream, struct raw_data_s *raw_data)
{
    int ret;
    struct frame_data_s *frame_data;
    parse_state_t parse_state;
    enum parse_rslt_e rslt;

    frame_data = NULL;
    parse_state = proto_parse_frame(data_stream->type, msg_type, raw_data, &frame_data);
    switch (parse_state) {
        case STATE_SUCCESS:
        {
            if (frame_data == NULL) {
                // TODO: debuging
                rslt = PARSE_ERROR;
                break;
            }

            ret = push_frame_data(data_stream, (const struct frame_data_s *)frame_data);
            if (ret) {
                destroy_frame_data(data_stream->type, frame_data);
                frame_data = NULL;
                rslt = PARSE_STOP;
            } else {
                if (raw_data->current_pos == raw_data->data_len) {
                    rslt = PARSE_NEXT;
                } else {
                    rslt = PARSE_REPEAT;
                }
            }
            break;
        }
        case STATE_IGNORE:
        {
            rslt = PARSE_NEXT;
            break;
        }
        case STATE_INVALID:
        {
            if (raw_data->flags & RAW_DATA_FLAGS_INVALID) {
                rslt = PARSE_NEXT;
            } else {
                raw_data->flags |= RAW_DATA_FLAGS_INVALID;
                rslt = PARSE_REBOUND;
            }
            break;
        }
        case STATE_NEEDS_MORE_DATA:
        {
            ret = overlay_raw_data(data_stream);
            if (ret) {
                rslt = PARSE_STOP;
            } else {
                rslt = PARSE_OVERLAY;
            }
            break;
        }
        default:
        {
            rslt = PARSE_ERROR;
            break;
        }
    }

    return rslt;
}


int data_stream_parse_frames(enum message_type_t msg_type, struct data_stream_s *data_stream)
{
    enum parse_rslt_e rslt;
    struct raw_data_s *raw_data, *poped_raw_data;
    size_t new_pos, old_pos;

    do {
next:
        raw_data = peek_raw_data(data_stream);
        if (raw_data == NULL) {
            break;
        }

rebound:
        new_pos = proto_find_frame_boundary(data_stream->type, msg_type, raw_data);
        if (new_pos == -1) {
            raw_data = pop_raw_data(data_stream);
            if (raw_data) {
                destroy_raw_data(raw_data);
                raw_data = NULL;
            }
            goto next;
        }
        raw_data->current_pos = new_pos;

repeat:
        old_pos = raw_data->current_pos;
        rslt = __do_parse_frames(msg_type, data_stream, raw_data);
        if (rslt == PARSE_NEXT) {
            poped_raw_data = pop_raw_data(data_stream);
            if (poped_raw_data) {
                destroy_raw_data(poped_raw_data);
                poped_raw_data = NULL;
            }
            goto next;
        }

        if (rslt == PARSE_OVERLAY) {
            goto next;
        }

        if (rslt == PARSE_REBOUND) {
            goto rebound;
        }

        if (rslt == PARSE_REPEAT) {
            goto repeat;
        }

        if (rslt == PARSE_STOP) {
            raw_data->current_pos = old_pos;
        }

        if (rslt == PARSE_ERROR) {
            // TODO: debugging
        }
    } while(0);

    return 0;
}

int data_stream_add_raw_data(struct data_stream_s *data_stream, const char *data, size_t data_len, u64 timestamp_ns)
{
    int ret;
    struct raw_data_s *new_raw_data = create_raw_data(data_len);
    if (new_raw_data == NULL) {
        return -1;
    }

    new_raw_data->timestamp_ns = timestamp_ns;
    new_raw_data->current_pos = 0;
    new_raw_data->flags = 0;
    (void)memcpy(new_raw_data->data, data, data_len);

    ret = push_raw_data(data_stream, (const struct raw_data_s *)new_raw_data);
    if (ret) {
        destroy_raw_data(new_raw_data);
        return ret;
    }

    return 0;
}

