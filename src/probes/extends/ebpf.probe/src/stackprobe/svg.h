/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: Mr.lu
 * Create: 2022-08-18
 * Description: svg defined
 ******************************************************************************/
#ifndef __GOPHER_SVG_H__
#define __GOPHER_SVG_H__

#pragma once

#include <time.h>
#include "stack.h"
#include <curl/curl.h>

enum proc_stack_type_e {
    PROC_STACK_STORE_IN_HASH = 0, // when load_jvm_agent
    PROC_STACK_STORE_IN_FILE = 1, // when load_jstack_agent
    PROC_STACK_STORE_READED = 2   // when load_jstack_agent
};

struct post_info_s {
    int post_flag;
    int remain_size;
    char *buf_start;
    char *buf;
    CURL *curl;
};

#define DAYS_TIME           (24 * 60 *60)   // 1 DAY
#define WEEKS_TIME          (DAYS_TIME * 7)   // 1 WEEK

enum stack_svg_type_e {
    STACK_SVG_ONCPU = 0,
    STACK_SVG_OFFCPU = 1,
    STACK_SVG_MEMLEAK,
    STACK_SVG_IO,
    STACK_SVG_MAX
};

struct stack_svg_s {
    int next;
    size_t capacity;
    char **files;
};

struct stack_svgs_s {
    u32 period;                 // unit is second
    char svg_dir[PATH_LEN];
    time_t last_create_time;
    struct stack_svg_s svg_files;
};

#define FLAME_GRAPH_NEW     0x00000001
struct stack_flamegraph_s {
    u32 flags;
    FILE *fp;
    char flame_graph_file[PATH_LEN];
    char *flame_graph_dir;
};

struct stack_svg_mng_s {
    struct stack_svgs_s svg;
    struct stack_flamegraph_s flame_graph;
};

struct stack_svg_mng_s* create_svg_mng(u32 default_period);
void destroy_svg_mng(struct stack_svg_mng_s* svg_mng);
int set_svg_dir(struct stack_svgs_s *svg, const char *dir, const char *flame_name);
int create_svg_file(struct stack_svg_mng_s* svg_mng, const char *flame_graph, int en_type, int proc_id);
char is_svg_tmout(struct stack_svg_mng_s* svg_mng);

#endif
