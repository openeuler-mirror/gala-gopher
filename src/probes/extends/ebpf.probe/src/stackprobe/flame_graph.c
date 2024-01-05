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
CURL* g_curl = NULL;

struct MemoryStruct {
  char *memory;
  size_t size;
};

static char *appname[STACK_SVG_MAX] = {
    "gala-gopher-oncpu",
    "gala-gopher-offcpu",
    "gala-gopher-mem",
    "gala-gopher-io"
};

#ifdef FLAMEGRAPH_SVG
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

    if (access(sfg->flame_graph_file, 0) != 0) {
        return NULL;
    }

    return sfg->flame_graph_file;
}

static void __flush_flame_graph_file(struct stack_svg_mng_s *svg_mng)
{
    struct stack_flamegraph_s *sfg;

    sfg = &(svg_mng->flame_graph);
    if (sfg->fp) {
        (void)fflush(sfg->fp);
        (void)fclose(sfg->fp);
        sfg->fp = NULL;
    }
    return;
}

static void __set_flame_graph_file(struct stack_svg_mng_s *svg_mng, int proc_id)
{
    const char *fmt = "%s/tmp_%d";
    struct stack_flamegraph_s *sfg;

    sfg = &(svg_mng->flame_graph);
    sfg->flame_graph_file[0] = 0;
    (void)snprintf(sfg->flame_graph_file, PATH_LEN, fmt, sfg->flame_graph_dir ?: "", proc_id);
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
}

static void __reopen_flame_graph_file(struct stack_svg_mng_s *svg_mng, int proc_id)
{
    __set_flame_graph_file(svg_mng, proc_id);
    (void)__open_flame_graph_fp(svg_mng);
}
#endif
static size_t __write_memory_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(!ptr) {
        /* out of memory! */
        ERROR("[FLAMEGRAPH]:not enough memory (realloc returned NULL)\n");
        return 0;
    }
    
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    
    return realsize;
}
 
// http://localhost:4040/ingest?name=gala-gopher-oncpu.56789&from=1671189474&until=1671189534&units=samples&sampleRate=100",
static int __build_url(struct stack_svg_mng_s *svg_mng, char *url,
    struct post_server_s *post_server, int en_type, int proc_id)
{
    time_t now, before;
    (void)time(&now);
    if (svg_mng->last_post_ts == 0) {
        before = now - TMOUT_PERIOD;
    } else {
        before = svg_mng->last_post_ts + 1;
    }
    svg_mng->last_post_ts = now;

    if (post_server->multi_instance_flag) {
        (void)snprintf(url, LINE_BUF_LEN, 
            "http://%s/ingest?name=%s-%s.%d&from=%ld&until=%ld&units=%s&sampleRate=%u",
            post_server->host,
            appname[en_type],
            post_server->app_suffix,
            proc_id,
            (long)before,
            (long)now,
            en_type == STACK_SVG_MEM ? "bytes" : "samples",
            1000 / post_server->perf_sample_period); // 1000 ms
    } else {
        (void)snprintf(url, LINE_BUF_LEN, 
            "http://%s/ingest?name=%s-%s&from=%ld&until=%ld&units=%s&sampleRate=%u",
            post_server->host,
            appname[en_type],
            post_server->app_suffix,
            (long)before,
            (long)now,
            en_type == STACK_SVG_MEM ? "bytes" : "samples",
            1000 / post_server->perf_sample_period); // 1000 ms
    }

    return 0;
}


void curl_post(struct stack_svg_mng_s *svg_mng, struct post_server_s *post_server,
    struct post_info_s *post_info, int en_type, int proc_id)
{
    CURLcode res;
    if (g_curl == NULL) {
        return;
    }

    long post_len = (long)strlen(post_info->buf_start);
    if (post_len == 0) {
        DEBUG("[FLAMEGRAPH]: buf is null. No need to curl post post to %s\n", appname[en_type]);
        return;
    }

    char url[LINE_BUF_LEN] = {0};
    __build_url(svg_mng, url, post_server, en_type, proc_id);
    struct MemoryStruct chunk;
    chunk.memory = malloc(1);  /* will be grown as needed by realloc above */
    chunk.size = 0;    /* no data at this point */

    //curl_easy_setopt(curl, CURLOPT_URL, post_server->host);
    curl_easy_setopt(g_curl, CURLOPT_URL, url);

    // reuse connection
    curl_easy_setopt(g_curl, CURLOPT_FORBID_REUSE, 0L);

    //  force the use of a cached one connection
    curl_easy_setopt(g_curl, CURLOPT_FRESH_CONNECT, 0L);

    curl_easy_setopt(g_curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(g_curl, CURLOPT_TCP_KEEPIDLE, 20L);
    curl_easy_setopt(g_curl, CURLOPT_TCP_KEEPINTVL, 10L);

    curl_easy_setopt(g_curl, CURLOPT_TIMEOUT, post_server->timeout);

    /* send all data to this function */
    curl_easy_setopt(g_curl, CURLOPT_WRITEFUNCTION, __write_memory_cb);

    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(g_curl, CURLOPT_WRITEDATA, (void *)&chunk);

    /* some servers do not like requests that are made without a user-agent
    field, so we provide one */
    curl_easy_setopt(g_curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");

    curl_easy_setopt(g_curl, CURLOPT_POSTFIELDS, post_info->buf_start);

    /* if we do not provide POSTFIELDSIZE, libcurl will strlen() by
    itself */
    curl_easy_setopt(g_curl, CURLOPT_POSTFIELDSIZE, post_len);

    /* Perform the request, res will get the return code */
    res = curl_easy_perform(g_curl);
    /* Check for errors */
    if(res != CURLE_OK) {
        ERROR("[FLAMEGRAPH]: curl post to %s failed: %s\n", url, curl_easy_strerror(res));
    } else {
        DEBUG("[FLAMEGRAPH]: curl post post to %s success\n", url);
    }

    if (chunk.memory) {
        free(chunk.memory);
    }
    return;
}

void init_curl_handle(struct post_server_s *post_server, struct post_info_s *post_info)
{
    if (post_server == NULL || post_server->post_enable == 0) {
        return;
    }

    if (g_curl == NULL) {
        g_curl = curl_easy_init();
    }

    if(g_curl) {
        post_info->buf = (char *)malloc(g_post_max);
        post_info->buf_start = post_info->buf;
        if (post_info->buf != NULL) {
            post_info->buf[0] = 0;
            post_info->post_flag = 1;
        }
    }
}

static void __do_wr_flamegraph(struct stack_svg_mng_s *svg_mng, struct proc_stack_trace_histo_s *proc_histo,
    struct post_server_s *post_server, int en_type)
{
    iter_histo_tbl(proc_histo, post_server, svg_mng, en_type);
#ifdef FLAMEGRAPH_SVG
    __flush_flame_graph_file(svg_mng);
#endif
}
#ifdef FLAMEGRAPH_SVG
void create_pids_svg_file(int proc_obj_map_fd, struct stack_svg_mng_s *svg_mng, int en_type)
{
    struct proc_s key = {0};
    struct proc_s next_key = {0};
    struct obj_ref_s value = {0};
    int ret, proc_id;
    const char *flame_graph;

    if (proc_obj_map_fd <= 0) {
        return;
    }

    while (bpf_map_get_next_key(proc_obj_map_fd, &key, &next_key) == 0) {
        ret = bpf_map_lookup_elem(proc_obj_map_fd, &next_key, &value);
        key = next_key;
        if (ret < 0) {
            continue;
        }
        proc_id = key.proc_id;
        __set_flame_graph_file(svg_mng, proc_id);
        flame_graph = __get_flame_graph_file(svg_mng);
        if (flame_graph == NULL) {
            continue;
        }
        (void)create_svg_file(svg_mng,
                            flame_graph, en_type, proc_id);
        __rm_flame_graph_file(svg_mng);
    }
}
#endif
void wr_flamegraph(struct proc_stack_trace_histo_s **proc_histo_tbl, struct stack_svg_mng_s *svg_mng, int en_type,
    struct post_server_s *post_server)
{
    if (*proc_histo_tbl == NULL) {
        return;
    }

    struct proc_stack_trace_histo_s *proc_histo, *proc_tmp;
    H_ITER(*proc_histo_tbl, proc_histo, proc_tmp) {
        if (H_COUNT(proc_histo->histo_tbl) <= 0) {
            continue;
        }
#ifdef FLAMEGRAPH_SVG
        __reopen_flame_graph_file(svg_mng, proc_histo->proc_id);
#endif
        __do_wr_flamegraph(svg_mng, proc_histo, post_server, en_type);
    }
}
#ifdef FLAMEGRAPH_SVG
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
    return 0;
}
#endif
int set_post_server(struct post_server_s *post_server, const char *server_str, unsigned int perf_sample_period,
                    char multi_instance_flag)
{
    post_server->post_enable = 1;
    post_server->timeout = 3;
    post_server->perf_sample_period = perf_sample_period == 0 ? DEFAULT_PERF_SAMPLE_PERIOD : perf_sample_period;
    post_server->multi_instance_flag = multi_instance_flag;

    if (server_str == NULL) {
        return -1;
    }

    char *p = strrchr(server_str, ':');
    if (p == NULL) {
        return -1;
    }

    curl_global_init(CURL_GLOBAL_ALL);

    (void)strcpy(post_server->host, server_str);

    return 0;
}

void clean_post_server()
{
    curl_global_cleanup();
}

void clean_curl()
{
    if (g_curl != NULL) {
        curl_easy_cleanup(g_curl);
        g_curl = NULL;
    }
}
