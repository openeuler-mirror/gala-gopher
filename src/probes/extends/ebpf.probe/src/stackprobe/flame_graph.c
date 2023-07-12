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

extern int g_post_max;

struct MemoryStruct {
  char *memory;
  size_t size;
};

static char *appname[STACK_SVG_MAX] = {
    "gala-gopher-oncpu",
    "gala-gopher-offcpu",
    "gala-gopher-memleak",
    "gala-gopher-io"
};

#if 1

static char __test_flame_graph_flags(struct stack_svg_mng_s *svg_mng, u32 flags)
{
    struct stack_flamegraph_s *sfg;

    sfg = &(svg_mng->flame_graph);
    if (sfg->flags & flags) {
        return 1;
    }
    return 0;
}

static void __set_flame_graph_flags(struct stack_svg_mng_s *svg_mng, u32 flags)
{
    struct stack_flamegraph_s *sfg;

    sfg = &(svg_mng->flame_graph);
    sfg->flags |= flags;
    return;
}

static void __reset_flame_graph_flags(struct stack_svg_mng_s *svg_mng, u32 flags)
{
    struct stack_flamegraph_s *sfg;

    sfg = &(svg_mng->flame_graph);
    sfg->flags &= flags;
    return;
}

static FILE *__open_flame_graph_fp(struct stack_svg_mng_s *svg_mng)
{
    struct stack_flamegraph_s *sfg;

    sfg = &(svg_mng->flame_graph);
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


static void __mkdir_flame_graph_path(struct stack_svg_mng_s *svg_mng)
{
    FILE *fp;
    char commad[COMMAND_LEN];

    commad[0] = 0;
    (void)snprintf(commad, COMMAND_LEN, "/usr/bin/mkdir -p %s", svg_mng->flame_graph.flame_graph_dir ?: "/");
    fp = popen(commad, "r");
    if (fp != NULL) {
        (void)pclose(fp);
    }
    return;
}

static char *__get_flame_graph_file(struct stack_svg_mng_s *svg_mng)
{
    struct stack_flamegraph_s *sfg;

    sfg = &(svg_mng->flame_graph);
    return sfg->flame_graph_file;
}

static void __flush_flame_graph_file(struct stack_svg_mng_s *svg_mng)
{
    struct stack_flamegraph_s *sfg;

    sfg = &(svg_mng->flame_graph);
    if (sfg->fp) {
        (void)fflush(sfg->fp);
    }
    return;
}

static void __set_flame_graph_file(struct stack_svg_mng_s *svg_mng)
{
    const char *fmt = "%s/tmp_%s";
    struct stack_flamegraph_s *sfg;

    sfg = &(svg_mng->flame_graph);
    sfg->flame_graph_file[0] = 0;
    (void)snprintf(sfg->flame_graph_file, PATH_LEN, fmt, sfg->flame_graph_dir ?: "", get_cur_time());
    return;
}

static void __rm_flame_graph_file(struct stack_svg_mng_s *svg_mng)
{
#define __COMMAND_LEN   (2 * PATH_LEN)
    FILE *fp;
    char commad[__COMMAND_LEN];
    struct stack_flamegraph_s *sfg;

    sfg = &(svg_mng->flame_graph);

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

static void __reopen_flame_graph_file(struct stack_svg_mng_s *svg_mng)
{
    __rm_flame_graph_file(svg_mng);
    __set_flame_graph_file(svg_mng);
    (void)__open_flame_graph_fp(svg_mng);
    __set_flame_graph_flags(svg_mng, FLAME_GRAPH_NEW);
}



static size_t __write_memory_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(!ptr) {
        /* out of memory! */
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }
    
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    
    return realsize;
}
 
// http://localhost:4040/ingest?name=gala-gopher-oncpu&from=1671189474&until=1671189534
static int __build_url(char *url, struct post_server_s *post_server, int en_type)
{
    time_t now, before;
    (void)time(&now);
    if (post_server->last_post_ts == 0) {
        before = now - TMOUT_PERIOD;
    } else {
        before = post_server->last_post_ts + 1;
    }
    post_server->last_post_ts = now;

    (void)snprintf(url, LINE_BUF_LEN, 
        "http://%s/ingest?name=%s-%s&from=%ld&until=%ld",
        post_server->host,
        appname[en_type],
        post_server->app_suffix,
        (long)before,
        (long)now);
    return 0;
}


static void __curl_post(struct post_server_s *post_server, struct post_info_s *post_info, int en_type)
{
    CURLcode res;
    CURL *curl = post_info->curl;
    if (curl == NULL) {
        goto end2;
    }

    long post_len = (long)strlen(post_info->buf_start);
    if (post_len == 0) {
        DEBUG("[FLAMEGRAPH]: buf is null. No need to curl post post to %s\n", appname[en_type]);
        goto end1;
    }

    char url[LINE_BUF_LEN] = {0};
    __build_url(url, post_server, en_type);
    struct MemoryStruct chunk;
    chunk.memory = malloc(1);  /* will be grown as needed by realloc above */
    chunk.size = 0;    /* no data at this point */

    //curl_easy_setopt(curl, CURLOPT_URL, post_server->host);
    curl_easy_setopt(curl, CURLOPT_URL, url);

    curl_easy_setopt(curl, CURLOPT_TIMEOUT, post_server->timeout);

    /* send all data to this function */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, __write_memory_cb);

    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    /* some servers do not like requests that are made without a user-agent
    field, so we provide one */
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_info->buf_start);

    /* if we do not provide POSTFIELDSIZE, libcurl will strlen() by
    itself */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, post_len);

    /* Perform the request, res will get the return code */
    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK) {
        ERROR("[FLAMEGRAPH]: curl post to %s failed: %s\n", url, curl_easy_strerror(res));
    } else {
        INFO("[FLAMEGRAPH]: curl post post to %s success\n", url);
    }

    if (chunk.memory) {
        free(chunk.memory);
    }
end1:
    /* always cleanup */
    curl_easy_cleanup(curl);
end2:
    if (post_info->buf_start != NULL) {
        free(post_info->buf_start);
        post_info->buf_start = NULL;
    }
    return;
}

static void __init_curl_handle(struct post_server_s *post_server, struct post_info_s *post_info)
{
    if (post_server == NULL || post_server->post_enable == 0) {
        return;
    }

    post_info->curl = curl_easy_init();
    if(post_info->curl) {
        post_info->buf = (char *)malloc(g_post_max);
        post_info->buf_start = post_info->buf;
        if (post_info->buf != NULL) {
            post_info->buf[0] = 0;
            post_info->post_flag = 1;
        }
    }
}

static void __do_wr_flamegraph(struct stack_svg_mng_s *svg_mng, struct post_server_s *post_server, int en_type)
{
    int first_flag = 0;
    struct post_info_s post_info = {.remain_size = g_post_max, .post_flag = 0};

    if (__test_flame_graph_flags(svg_mng, FLAME_GRAPH_NEW)) {
        first_flag = 1;
    }

    __init_curl_handle(post_server, &post_info);

    iter_histo_tbl(svg_mng, en_type, &first_flag, &post_info);

    if (post_info.post_flag) {
        __curl_post(post_server, &post_info, en_type);
    }
    
    __flush_flame_graph_file(svg_mng);
    __reset_flame_graph_flags(svg_mng, ~FLAME_GRAPH_NEW);
}

#endif

void wr_flamegraph(struct stack_svg_mng_s *svg_mng, int en_type,
    struct post_server_s *post_server)
{
    __do_wr_flamegraph(svg_mng, post_server, en_type);

    if (is_svg_tmout(svg_mng)) {
        (void)create_svg_file(svg_mng,
                              __get_flame_graph_file(svg_mng), en_type);

        __reopen_flame_graph_file(svg_mng);
    }
}

int set_flame_graph_path(struct stack_svg_mng_s *svg_mng, const char* path, const char *flame_name)
{
    size_t len;
    char dir[PATH_LEN] = {0};

    if (path == NULL || path[0] == 0) {
        path = "/var/log/gala-gopher/flamegraph";
    }

    len = strlen(path);
    if (len == 0 || len + strlen(flame_name) >= PATH_LEN) {
        return -1;
    }

    if (path[len - 1] == '/') {
        (void)snprintf(dir, PATH_LEN, "%s%s", path, flame_name);
    } else {
        (void)snprintf(dir, PATH_LEN, "%s/%s", path, flame_name);
    }

    svg_mng->flame_graph.flame_graph_dir = strdup(dir);

    __mkdir_flame_graph_path(svg_mng);
    __set_flame_graph_file(svg_mng);
    if (__open_flame_graph_fp(svg_mng) == NULL) {
        return -1;
    }
    __set_flame_graph_flags(svg_mng, FLAME_GRAPH_NEW);
    return 0;
}

int set_post_server(struct post_server_s *post_server, const char *server_str)
{
    if (server_str == NULL) {
        return -1;
    }

    char *p = strrchr(server_str, ':');
    if (p == NULL) {
        return -1;
    }

    curl_global_init(CURL_GLOBAL_ALL);
    post_server->post_enable = 1;
    post_server->timeout = 3;
    (void)strcpy(post_server->host, server_str);

    return 0;
}

void clean_post_server()
{
    curl_global_cleanup();
}
