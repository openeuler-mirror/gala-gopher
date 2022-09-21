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
 * Author: luzhihao
 * Create: 2022-08-22
 * Description: flame_graph prog
 ******************************************************************************/
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <time.h>

#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "flame_graph.h"

#if 1

static char __test_flame_graph_flags(struct stack_svg_mng_s *svg_mng, enum stack_svg_type_e en_type, u32 flags)
{
    struct stack_flamegraph_s *sfg;

    sfg = &(svg_mng->flame_graphs[en_type]);
    if (sfg->flags & flags) {
        return 1;
    }
    return 0;
}

static void __set_flame_graph_flags(struct stack_svg_mng_s *svg_mng, enum stack_svg_type_e en_type, u32 flags)
{
    struct stack_flamegraph_s *sfg;

    sfg = &(svg_mng->flame_graphs[en_type]);
    sfg->flags |= flags;
    return;
}

static void __reset_flame_graph_flags(struct stack_svg_mng_s *svg_mng, enum stack_svg_type_e en_type, u32 flags)
{
    struct stack_flamegraph_s *sfg;

    sfg = &(svg_mng->flame_graphs[en_type]);
    sfg->flags &= flags;
    return;
}

static FILE * __open_flame_graph_fp(struct stack_svg_mng_s *svg_mng, enum stack_svg_type_e en_type)
{
    struct stack_flamegraph_s *sfg;

    sfg = &(svg_mng->flame_graphs[en_type]);
    if (sfg->fp) {
        (void)pclose(sfg->fp);
        sfg->fp = NULL;
    }
    sfg->fp = fopen(sfg->flame_graph_file, "a+");
    if (sfg->fp == NULL) {
        ERROR("[FLAMEGRAPH]: open file failed.(%s)\n", sfg->flame_graph_file);
    }
    return sfg->fp;
}

static FILE * __get_flame_graph_fp(struct stack_svg_mng_s *svg_mng, enum stack_svg_type_e en_type)
{
    struct stack_flamegraph_s *sfg;

    sfg = &(svg_mng->flame_graphs[en_type]);
    return sfg->fp;
}

static void __mkdir_flame_graph_path(struct stack_svg_mng_s *svg_mng, enum stack_svg_type_e en_type)
{
    FILE *fp;
    struct stack_flamegraph_s *sfg;
    char commad[COMMAND_LEN];

    sfg = &(svg_mng->flame_graphs[en_type]);
    commad[0] = 0;
    (void)snprintf(commad, COMMAND_LEN, "/usr/bin/mkdir -p %s", sfg->flame_graph_dir ?: "/");
    fp = popen(commad, "r");
    if (fp != NULL) {
        (void)pclose(fp);
    }
    return;
}

static char* __get_flame_graph_file(struct stack_svg_mng_s *svg_mng, enum stack_svg_type_e en_type)
{
    struct stack_flamegraph_s *sfg;

    sfg = &(svg_mng->flame_graphs[en_type]);
    return sfg->flame_graph_file;
}

static void __flush_flame_graph_file(struct stack_svg_mng_s *svg_mng, enum stack_svg_type_e en_type)
{
    struct stack_flamegraph_s *sfg;

    sfg = &(svg_mng->flame_graphs[en_type]);
    if (sfg->fp) {
        (void)fflush(sfg->fp);
    }
    return;
}

static void __set_flame_graph_file(struct stack_svg_mng_s *svg_mng, enum stack_svg_type_e en_type)
{
    const char *fmt = "%s/tmp_%s";
    struct stack_flamegraph_s *sfg;

    sfg = &(svg_mng->flame_graphs[en_type]);
    sfg->flame_graph_file[0] = 0;
    (void)snprintf(sfg->flame_graph_file, PATH_LEN, fmt, sfg->flame_graph_dir ?: "", get_cur_time());
    return;
}

static void __rm_flame_graph_file(struct stack_svg_mng_s *svg_mng, enum stack_svg_type_e en_type)
{
#define __COMMAND_LEN   (2 * PATH_LEN)
    FILE *fp;
    char commad[__COMMAND_LEN];
    struct stack_flamegraph_s *sfg;

    sfg = &(svg_mng->flame_graphs[en_type]);

    if (!access(sfg->flame_graph_file, 0)) {
        commad[0] = 0;
        (void)snprintf(commad, __COMMAND_LEN, "/usr/bin/rm -f %s", sfg->flame_graph_file);
        fp = popen(commad, "r");
        if (fp != NULL) {
            (void)pclose(fp);
            fp = NULL;
        }
    }
    if (sfg->fp) {
        (void)fclose(sfg->fp);
        sfg->fp = NULL;
    }
}

static void __reopen_flame_graph_file(struct stack_svg_mng_s *svg_mng, enum stack_svg_type_e en_type)
{
    __rm_flame_graph_file(svg_mng, en_type);
    __set_flame_graph_file(svg_mng, en_type);
    (void)__open_flame_graph_fp(svg_mng, en_type);
    __set_flame_graph_flags(svg_mng, en_type, FLAME_GRAPH_NEW);
}

#define HISTO_TMP_LEN   (2 * STACK_SYMBS_LEN)
static char __histo_tmp_str[HISTO_TMP_LEN];
static int __do_wr_stack_histo(struct stack_svg_mng_s *svg_mng, enum stack_svg_type_e en_type, struct stack_trace_histo_s *stack_trace_histo, int first)
{
    FILE * fp = __get_flame_graph_fp(svg_mng, en_type);
    if (!fp) {
        ERROR("[FLAMEGRAPH]: Invalid fp.\n");
        return -1;
    }

    __histo_tmp_str[0] = 0;

    if (first) {
        (void)snprintf(__histo_tmp_str, HISTO_TMP_LEN, "%s %llu",
                stack_trace_histo->stack_symbs_str, stack_trace_histo->count);
    } else {
        (void)snprintf(__histo_tmp_str, HISTO_TMP_LEN, "\n%s %llu",
                stack_trace_histo->stack_symbs_str, stack_trace_histo->count);
    }
    (void)fputs(__histo_tmp_str, fp);
    return 0;
}

static void __do_wr_flamegraph(struct stack_svg_mng_s *svg_mng, struct stack_trace_histo_s *head, enum stack_svg_type_e en_type)
{
    int first_flag = 0;

    if (__test_flame_graph_flags(svg_mng, en_type, FLAME_GRAPH_NEW)) {
        first_flag = 1;
    }

    struct stack_trace_histo_s *item, *tmp;

    H_ITER(head, item, tmp) {
        (void)__do_wr_stack_histo(svg_mng, en_type, item, first_flag);
        first_flag = 0;
    }

    __flush_flame_graph_file(svg_mng, en_type);
    __reset_flame_graph_flags(svg_mng, en_type, ~FLAME_GRAPH_NEW);
}

#endif

void wr_flamegraph(struct stack_svg_mng_s *svg_mng, struct stack_trace_histo_s *head, enum stack_svg_type_e en_type)
{
    __do_wr_flamegraph(svg_mng, head, en_type);
    if (is_svg_tmout(svg_mng, en_type)) {
        (void)create_svg_file(svg_mng,
                              en_type,
                              __get_flame_graph_file(svg_mng, en_type));

        __reopen_flame_graph_file(svg_mng, en_type);
    }
}

int set_flame_graph_path(struct stack_svg_mng_s *svg_mng, const char* path, enum stack_svg_type_e en_type)
{
    size_t len;
    char dir[PATH_LEN];
    struct stack_flamegraph_s *sfg;

    len = strlen(path);
    if (len == 0 || len >= PATH_LEN) {
        return -1;
    }

    if (len == 1 && path[0] == '/') {
        return 0;
    }

    dir[0] = 0;
    if (path[0] == '/') {
        (void)strncpy(dir, path, len - 1);
    } else {
        (void)strncpy(dir, path, PATH_LEN - 1);
    }
    sfg = &(svg_mng->flame_graphs[en_type]);
    sfg->flame_graph_dir = strdup(dir);

    __mkdir_flame_graph_path(svg_mng, en_type);
    __set_flame_graph_file(svg_mng, en_type);
    if (__open_flame_graph_fp(svg_mng, en_type) == NULL) {
        return -1;
    }
    __set_flame_graph_flags(svg_mng, en_type, FLAME_GRAPH_NEW);
    return 0;
}

