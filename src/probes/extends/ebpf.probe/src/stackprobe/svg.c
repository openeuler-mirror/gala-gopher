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

#ifdef FLAMEGRAPH_SVG

#define __COMMAND_LEN       (2 * COMMAND_LEN)
#define FAMEGRAPH_BIN       "/usr/bin/flamegraph.pl"
#define SVG_COMMAND   "%s --title=\" %s \" %s %s > %s 2>/dev/null"

struct svg_param_s {
    char *file_name;
    char *params;
    char *title;
};

static struct svg_param_s svg_params[STACK_SVG_MAX] =
    {{"oncpu", "--countname=us", "On-CPU Time Flame Graph"},
    {"offcpu", "--colors=io --countname=us", "Off-CPU Time Flame Graph"},
    {"mem", "--colors=mem --countname=Bytes", "Memory Leak Flame Graph"},
    {"mem", "--colors=mem --countname=Bytes", "Memory Leak Flame Graph"},
    {"io", "--colors=io --countname=us", "IO Time Flame Graph"}};
#endif
#ifdef FLAMEGRAPH_SVG
static void __rm_svg(const char *svg_file)
{
    FILE *fp;
    char command[__COMMAND_LEN];
    const char *fmt = "rm -rf %s";

    if (access(svg_file, 0) != 0) {
        return;
    }

    command[0] = 0;
    (void)snprintf(command, __COMMAND_LEN, fmt, svg_file);
    fp = popen(command, "r");
    if (fp != NULL) {
        (void)pclose(fp);
        fp = NULL;
        DEBUG("[SVG]: Delete svg file(%s)\n", svg_file);
    }
}

static int __new_svg(const char *flame_graph, const char *svg_file, int en_type)
{
    const char *flamegraph_bin = FAMEGRAPH_BIN;
    char command[__COMMAND_LEN];
    FILE *fp;

    if (access(flamegraph_bin, 0) != 0) {
        ERROR("[SVG]: Please install flame graph rpm.\n");
        return -1;
    }

    if (access(flame_graph, 0) != 0) {
        ERROR("[SVG]: %s is not exist.\n", flame_graph);
        return -1;
    }

    command[0] = 0;
    (void)snprintf(command, __COMMAND_LEN, SVG_COMMAND,
        flamegraph_bin, svg_params[en_type].title,
        svg_params[en_type].params, flame_graph, svg_file);

    fp = popen(command, "r");
    if (fp != NULL) {
        (void)pclose(fp);
        fp = NULL;
        DEBUG("[SVG]: Create svg file(%s)\n", svg_file);
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
    if (!svg_files->files) {
        return;
    }
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

int __mkdir_with_svg_date(const char *svg_dir, char *svg_date_dir, size_t size)
{
    size_t len = strlen(svg_dir);
    const char *day = get_cur_date();
    if (len <= 1 || len + strlen(day) + 1 >= size) {
        return -1;
    }

    (void)snprintf(svg_date_dir, size, "%s/%s", svg_dir, day);
    if (access(svg_date_dir, F_OK) != 0) {
        FILE *fp;
        char command[COMMAND_LEN] = {0};
        (void)snprintf(command, COMMAND_LEN, "/usr/bin/mkdir -p %s", svg_date_dir);
        fp = popen(command, "r");
        if (fp != NULL) {
            (void)pclose(fp);
        }
    }

    return 0;
}

static int stack_get_next_svg_file(struct stack_svgs_s* svgs, char svg_file[], size_t size, int en_type, int proc_id)
{
    int next;
    char svg_name[PATH_LEN];
    char svg_date_dir[PATH_LEN] = {0};

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

    if (__mkdir_with_svg_date(svgs->svg_dir, svg_date_dir, PATH_LEN) < 0) {
        return -1;
    }

    svg_name[0] = 0;
    (void)snprintf(svg_name, PATH_LEN, "%s-%d.svg", get_cur_time(), proc_id);

    svg_file[0] = 0;
    (void)snprintf(svg_file, size, "%s/%s", svg_date_dir, svg_name);
    __rm_svg(svg_file);

    svgs->svg_files.files[next] = strdup(svg_file);
    next = (next + 1) % svgs->svg_files.capacity;
    svgs->svg_files.next = next;
    return 0;
}

char is_svg_tmout(struct stack_svg_mng_s* svg_mng)
{
    struct stack_svgs_s *svgs = &(svg_mng->svg);
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

int create_svg_file(struct stack_svg_mng_s* svg_mng, const char *flame_graph, int en_type, int proc_id)
{
    char svg_file[LINE_BUF_LEN];
    struct stack_svgs_s* svgs;

    svgs = &(svg_mng->svg);

    if (stack_get_next_svg_file(svgs, svg_file, LINE_BUF_LEN, en_type, proc_id)) {
        return -1;
    }

    return __new_svg(flame_graph, (const char *)svg_file, en_type);
}
#endif
struct stack_svg_mng_s* create_svg_mng(u32 default_period)
{
    u32 svg_period = default_period;

    struct stack_svg_mng_s* svg_mng = malloc(sizeof(struct stack_svg_mng_s));
    if (!svg_mng) {
        return NULL;
    }

    (void)memset(svg_mng, 0, sizeof(struct stack_svg_mng_s));

    if (default_period == 0) {
        svg_period = 180;
    }

    svg_mng->svg.last_create_time = (time_t)time(NULL);
    svg_mng->svg.period = svg_period;
#ifdef FLAMEGRAPH_SVG
    (void)__create_svg_files(&svg_mng->svg.svg_files, svg_period);
#endif
    return svg_mng;
}

void destroy_svg_mng(struct stack_svg_mng_s* svg_mng)
{
#ifdef FLAMEGRAPH_SVG
    struct stack_svgs_s *svgs;
    struct stack_flamegraph_s *flame_graph;
#endif
    enum stack_svg_type_e en_type = STACK_SVG_ONCPU;

    if (!svg_mng) {
        return;
    }

    for (; en_type < STACK_SVG_MAX; en_type++) {
#ifdef FLAMEGRAPH_SVG
        svgs = &(svg_mng->svg);
        __destroy_svg_files(&(svgs->svg_files));

        flame_graph = &(svg_mng->flame_graph);
        __destroy_flamegraph(flame_graph);
#endif
    }
    (void)free(svg_mng);
    return;
}

static void __mkdir_svg_dir(struct stack_svgs_s *svg)
{
    FILE *fp;
    char command[LINE_BUF_LEN];

    command[0] = 0;

    (void)snprintf(command, LINE_BUF_LEN, "/usr/bin/mkdir -p %s", svg->svg_dir ?: "/");
    fp = popen(command, "r");
    if (fp != NULL) {
        (void)pclose(fp);
    }
    return;
}

int set_svg_dir(struct stack_svgs_s *svg, const char *dir, const char *flame_name)
{
    size_t len;

    if (!svg) {
        return -1;
    }

    if (dir == NULL || dir[0] == 0) {
        dir = "/var/log/gala-gopher/stacktrace";
    }

    len = strlen(dir);
    if (len <= 1 || len + strlen(flame_name) >= PATH_LEN) {
        return -1;
    }

    if (dir[len - 1] == '/') {
        (void)snprintf(svg->svg_dir, PATH_LEN, "%s%s", dir, flame_name);
    } else {
        (void)snprintf(svg->svg_dir, PATH_LEN, "%s/%s", dir, flame_name);
    }
    __mkdir_svg_dir(svg);
    return 0;
}

