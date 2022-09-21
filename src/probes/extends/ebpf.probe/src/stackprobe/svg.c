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
 * Description: svg prog
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
#include "stack.h"
#include "svg.h"

#define __COMMAND_LEN       (2 * COMMAND_LEN)
#define FAMEGRAPH_BIN       "/usr/bin/flamegraph.pl"
#define ONCPU_SVG_COMMAND   "%s --title=\" %s \" %s %s > %s"

struct svg_param_s {
    char *file_name;
    char *params;
    char *titile;
};

static struct svg_param_s svg_params[STACK_SVG_MAX] =
    {{"oncpu", "--countname=us", "On-CPU Time Flame Graph"},
    {"offcpu", "--countname=us", "Off-CPU Time Flame Graph"},
    {"io", "--colors=io --countname=us", "IO Time Flame Graph"}};

#if 1
static void __rm_svg(const char *svg_file)
{
    FILE *fp;
    char commad[__COMMAND_LEN];
    const char *fmt = "rm -rf %s";

    if (access(svg_file, 0) != 0) {
        return;
    }

    commad[0] = 0;
    (void)snprintf(commad, __COMMAND_LEN, fmt, svg_file);
    fp = popen(commad, "r");
    if (fp != NULL) {
        (void)pclose(fp);
        fp = NULL;
        INFO("[SVG]: Delete svg file(%s)\n", svg_file);
    }
}

static int __new_svg(const char *flame_graph, const char *svg_file, enum stack_svg_type_e en_type)
{
    const char *flamegraph_bin = FAMEGRAPH_BIN;
    char commad[__COMMAND_LEN];
    FILE *fp;

    if (access(flamegraph_bin, 0) != 0) {
        ERROR("[SVG]: Please install flame graph rpm.\n");
        return -1;
    }

    if (access(flame_graph, 0) != 0) {
        ERROR("[SVG]: %s is not exist.\n", flame_graph);
        return -1;
    }

    commad[0] = 0;
    (void)snprintf(commad, __COMMAND_LEN, ONCPU_SVG_COMMAND,
        flamegraph_bin, svg_params[en_type].titile,
        svg_params[en_type].params, flame_graph, svg_file);

    fp = popen(commad, "r");
    if (fp != NULL) {
        (void)pclose(fp);
        fp = NULL;
        INFO("[SVG]: Create svg file(%s)\n", svg_file);
        return 0;
    }

    return -1;
}

static void __destroy_flamegraph(struct stack_flamegraph_s *flame_graph)
{
    if (flame_graph->fp) {
        (void)fclose(flame_graph->fp);
    }
    flame_graph->fp = NULL;
    if (flame_graph->flame_graph_dir) {
        (void)free(flame_graph->flame_graph_dir);
    }
    flame_graph->flame_graph_dir = NULL;
    return;
}

static void __destroy_svg_files(struct stack_svg_s *svg_files)
{
    char *file;
    for (int i = 0; i < svg_files->capacity; i++) {
        file = svg_files->files[i];
        if (file) {
            (void)free(file);
        }
    }
    if (svg_files->files) {
        (void)free(svg_files->files);
        svg_files->files = NULL;
    }
    return;
}

static int __create_svg_files(struct stack_svg_s* svg_files, u32 period)
{
    size_t svg_capacity;
    char **files;

    svg_capacity = (size_t)DIV_ROUND_UP(WEEKS_TIME, period);
    files = (char **)malloc(svg_capacity * sizeof(char *));
    if (!files) {
        return -1;
    }
    (void)memset(files, 0, svg_capacity * sizeof(char *));
    svg_files->capacity = svg_capacity;
    svg_files->files = files;
    svg_files->next = 0;
    return 0;
}

static int stack_get_next_svg_file(struct stack_svgs_s* svgs, enum stack_svg_type_e en_type, char svg_file[], size_t size)
{
    int next;
    char svg_name[PATH_LEN];

    if (svgs->svg_files.files == NULL) {
        return -1;
    }

    if (svgs->svg_files.capacity == 0) {
        return -1;
    }

    next = svgs->svg_files.next;
    if (svgs->svg_files.files[next] != NULL) {
        __rm_svg(svgs->svg_files.files[next]);
        (void)free(svgs->svg_files.files[next]);
        svgs->svg_files.files[next] = NULL;
    }

    svg_name[0] = 0;
    (void)snprintf(svg_name, PATH_LEN, "%s_%s.svg", svg_params[en_type].file_name, get_cur_time());

    svg_file[0] = 0;
    (void)snprintf(svg_file, size, "%s/%s", svgs->svg_dir, svg_name);
    __rm_svg(svg_file);

    svgs->svg_files.files[next] = strdup(svg_file);
    next = (next + 1) % svgs->svg_files.capacity;
    svgs->svg_files.next = next;
    return 0;
}
#endif

char is_svg_tmout(struct stack_svg_mng_s* svg_mng, enum stack_svg_type_e en_type)
{
    struct stack_svgs_s *svgs = &(svg_mng->svgs[en_type]);
    time_t current = (time_t)time(NULL);
    time_t secs;

    if (current > svgs->last_create_time) {
        secs = current - svgs->last_create_time;
        if (secs >= svgs->period) {
            svgs->last_create_time = current;
            return 1;
        }
    }
    return 0;
}

int create_svg_file(struct stack_svg_mng_s* svg_mng, enum stack_svg_type_e en_type, const char *flame_graph)
{
    char svg_file[PATH_LEN];
    struct stack_svgs_s* svgs;

    svgs = &(svg_mng->svgs[en_type]);

    if (stack_get_next_svg_file(svgs, en_type, svg_file, PATH_LEN)) {
        return -1;
    }

    return __new_svg(flame_graph, (const char *)svg_file, en_type);
}

struct stack_svg_mng_s* create_svg_mng(u32 default_period)
{
    struct stack_svgs_s *svgs;
    enum stack_svg_type_e en_type = STACK_SVG_ONCPU;
    struct stack_svg_mng_s* svg_mng = malloc(sizeof(struct stack_svg_mng_s));
    if (!svg_mng) {
        return NULL;
    }

    (void)memset(svg_mng, 0, sizeof(struct stack_svg_mng_s));
    for (; en_type < STACK_SVG_MAX; en_type++) {
        svgs = &(svg_mng->svgs[en_type]);
        svgs->last_create_time = (time_t)time(NULL);
        svgs->period = default_period;
        (void)__create_svg_files(&(svgs->svg_files), default_period);
    }
    return svg_mng;
}

void destroy_svg_mng(struct stack_svg_mng_s* svg_mng)
{
    struct stack_svgs_s *svgs;
    struct stack_flamegraph_s *flame_graph;
    enum stack_svg_type_e en_type = STACK_SVG_ONCPU;

    if (!svg_mng) {
        return;
    }

    for (; en_type < STACK_SVG_MAX; en_type++) {
        svgs = &(svg_mng->svgs[en_type]);
        __destroy_svg_files(&(svgs->svg_files));

        flame_graph = &(svg_mng->flame_graphs[en_type]);
        __destroy_flamegraph(flame_graph);
    }
    (void)free(svg_mng);
    return;
}

int set_svg_dir(struct stack_svg_mng_s* svg_mng, const char *dir, enum stack_svg_type_e en_type)
{
    size_t len;
    struct stack_svgs_s *svgs;

    if (!svg_mng) {
        return -1;
    }

    len = strlen(dir);
    if (len <= 1 || len >= PATH_LEN) {
        return -1;
    }

    svgs = &(svg_mng->svgs[en_type]);
    if (dir[len - 1] == '/') {
        (void)strncpy(svgs->svg_dir, dir, len - 1);
    } else {
        (void)strncpy(svgs->svg_dir, dir, len);
    }
    return 0;
}

int set_svg_period(struct stack_svg_mng_s* svg_mng, u32 period, enum stack_svg_type_e en_type)
{
    struct stack_svgs_s *svgs;

    if (!svg_mng) {
        return -1;
    }
    svgs = &(svg_mng->svgs[en_type]);

    __destroy_svg_files(&svgs->svg_files);
    if (__create_svg_files(&svgs->svg_files, period)) {
        return -1;
    }
    svgs->period = period;

    return 0;
}

