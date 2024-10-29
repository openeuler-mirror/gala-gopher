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
#ifndef __TRACE_VIEWER_FMT_H__
#define __TRACE_VIEWER_FMT_H__
#include <stdio.h>
#include <uthash.h>

#include "common.h"
#include "strbuf.h"
#include "stack_tree.h"

#define EVENT_PHASE_DUR_BEGIN       'B'
#define EVENT_PHASE_DUR_END         'E'
#define EVENT_PHASE_COMPLETE        'X'
#define EVENT_PHASE_COUNTER         'C'
#define EVENT_PHASE_ASYNC_START     'b'
#define EVENT_PHASE_ASYNC_INSTANT   'n'
#define EVENT_PHASE_ASYNC_END       'e'
#define EVENT_PHASE_INSTANT         'i'
#define EVENT_PHASE_SAMPLE          'P'
#define EVENT_PHASE_OBJECT_SNAPSHOT 'O'
#define EVENT_PHASE_META            'M'

#define TRACE_FIELD_EVENTS          "traceEvents"
#define TRACE_FIELD_EVENT_PID       "pid"
#define TRACE_FIELD_EVENT_TID       "tid"
#define TRACE_FIELD_EVENT_NAME      "name"
#define TRACE_FIELD_EVENT_PHASE     "ph"
#define TRACE_FIELD_EVENT_TIMESTAMP "ts"
#define TRACE_FIELD_EVENT_DURATION  "dur"
#define TRACE_FIELD_EVENT_ID        "id"
#define TRACE_FIELD_EVENT_CNAME     "cname"
#define TRACE_FIELD_EVENT_CATEGORY  "cat"
#define TRACE_FIELD_EVENT_ARGS      "args"
#define TRACE_FIELD_EVENT_STACK_REF "sf"
#define TRACE_FIELD_EVENT_SCOPE     "s"

#define TRACE_FIELD_STACKS          "stackFrames"
#define TRACE_FIELD_STACK_NAME      "name"
#define TRACE_FIELD_STACK_PARENT    "parent"
#define TRACE_FIELD_STACK_CATEGORY  "category"

#define EVENT_CATEGORY_ONCPU        "oncpu"
#define EVENT_CATEGORY_SYSCALL      "syscall"
#define EVENT_CATEGORY_PYGC         "python_gc"
#define EVENT_CATEGORY_PTHRD_SYNC   "pthread_sync"
#define EVENT_CATEGORY_FUNC         "func"
#define EVENT_CATEGORY_SAMPLE       "sample"
#define EVENT_CATEGORY_STUCK        "stuck"

#define EVENT_CNAME_OF_ONCPU        "good"

#define EVENT_META_PROC_NAME        "process_name"
#define EVENT_META_ARG_PROC_NAME    "name"

#define EVENT_INSTANT_SCOPE_GLOBAL  'g'
#define EVENT_INSTANT_SCOPE_PROCESS 'p'
#define EVENT_INSTANT_SCOPE_THREAD  't'

#define event_type_is_duration_begin(typ)   ((typ) == EVENT_PHASE_DUR_BEGIN)
#define event_type_is_duration_end(typ)     ((typ) == EVENT_PHASE_DUR_END)
#define event_type_is_duration(typ)         (event_type_is_duration_begin(typ) \
    || event_type_is_duration_end(typ))
#define event_type_is_complete(typ)         ((typ) == EVENT_PHASE_COMPLETE)
#define event_type_is_counter(typ)          ((typ) == EVENT_PHASE_COUNTER)
#define event_type_is_async_start(typ)      ((typ) == EVENT_PHASE_ASYNC_START)
#define event_type_is_async_instant(typ)    ((typ) == EVENT_PHASE_ASYNC_INSTANT)
#define event_type_is_async_end(typ)        ((typ) == EVENT_PHASE_ASYNC_END)
#define event_type_is_async(typ)            (event_type_is_async_start(typ) \
    || event_type_is_async_instant(typ) \
    || event_type_is_async_end(typ))
#define event_type_is_instant(typ)          ((typ) == EVENT_PHASE_INSTANT)
#define event_type_is_sample(typ)           ((typ) == EVENT_PHASE_SAMPLE)

struct trace_event_fmt_s {
    u32 pid;
    u32 tid;
    u64 ts;         // unit: ns
    u64 duration;   // unit: ns
    u64 id;
    u64 sf;
    char phase;
    char scope;     // used in instant event
    char name[32];
    char category[64];
    char cname[32];
    char args[256];
};

struct proc_meta {
    u32 pid;
    UT_hash_handle hh;
};

struct local_store_s {
    FILE *fp;
    FILE *stack_fp;
    char is_write;
    char is_stack_write;
    char trace_path[PATH_LEN];
    char trace_path_tmp[PATH_LEN];
    char stack_path_tmp[PATH_LEN];
    char buf[1024];
    struct stack_node_s *stack_root;
    int stack_node_num;     /* 统计加入 stack_root 中的调用栈节点的数量，用于控制内存使用 */
    struct proc_meta *proc_meta_written;
};

u64 gen_async_event_id();

int trace_event_fmt_to_json_str(struct trace_event_fmt_s *evt_fmt, char *buf, int size);
int trace_file_fill_head(FILE *fp);
int trace_file_fill_tail(FILE *fp);
// int trace_file_fill_stack_tree(FILE *fp, struct stack_node_s *stack_root);
int trace_file_fill_stack_from_file(FILE *fp, FILE *stack_fp);
int trace_file_fill_event_from_buffer(struct local_store_s *local_storage);
int trace_file_fill_event_from_buffer2(struct local_store_s *local_storage, char *buf);
int stack_trace_file_fill_stack_node(struct local_store_s *local_storage, struct stack_node_s *node);

void cleanup_proc_meta(struct proc_meta *proc_meta_written);

#endif