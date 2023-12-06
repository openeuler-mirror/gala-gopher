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
 * Description: stack probe defined
 ******************************************************************************/
#ifndef __GOPHER_STACK_PROBE_H__
#define __GOPHER_STACK_PROBE_H__

#pragma once

#include "hash.h"
#include "symbol.h"
#include "svg.h"
#include "stack.h"

#define BPF_FUNC_NAME_LEN 32
#define APP_SUFFIX_LEN 64

#define JSTACK_AGENT_FILE       "JstackProbeAgent.jar"

struct stack_symbs_s {
    struct addr_symb_s user_stack_symbs[PERF_MAX_STACK_DEPTH];
    struct addr_symb_s kern_stack_symbs[PERF_MAX_STACK_DEPTH];
    u32 py_stack_len;
    struct py_symbol py_stack_symbols[MAX_PYTHON_STACK_DEPTH_MAX];
    struct stack_pid_s pid;
};

struct raw_stack_trace_s {
    u32 stack_size;
    u32 raw_trace_count;
    struct raw_trace_s raw_traces[];
};

struct py_stack_trace_s {
    u32 size;
    u32 len;
    struct py_stack py_traces[];
};

#define __FUNC_NAME_LEN     64
#define STACK_SYMBS_LEN     (2 * (PERF_MAX_STACK_DEPTH * __FUNC_NAME_LEN))  // KERN + USER

struct stack_trace_histo_s {
    H_HANDLE;
    char stack_symbs_str[STACK_SYMBS_LEN];
    u64 count;
};

struct proc_stack_trace_histo_s {
    H_HANDLE;
    int proc_id;
    enum proc_stack_type_e proc_stack_type;
    struct stack_trace_histo_s *histo_tbl;
};

struct proc_cache_s {
    H_HANDLE;
    struct stack_pid_s k;
    struct proc_symbs_s *proc_symbs;
};

enum stack_stats_e {
    STACK_STATS_RAW = 0,
    STACK_STATS_LOSS = 1,
    STACK_STATS_HISTO_ERR,
    STACK_STATS_HISTO_FOLDED,
    STACK_STATS_ID2SYMBS,
    STACK_STATS_PCACHE_DEL,
    STACK_STATS_PCACHE_CRT,
    STACK_STATS_KERN_ADDR_ERR,
    STACK_STATS_USR_ADDR_ERR,
    STACK_STATS_MAP_LKUP_ERR,
    STACK_STATS_KERN_ADDR,
    STACK_STATS_USR_ADDR,
    STACK_STATS_USR_KERN_ADDR,
    STACK_STATS_P_CACHE,
    STACK_STATS_SYMB_CACHE,

    STACK_STATS_MAX
};

struct stack_stats_s {
    u64 count[STACK_STATS_MAX];
};

struct flame_graph_param_s {
    char svg_dir[PATH_LEN];
    char flame_graph[PATH_LEN];
};

struct stack_param_s {
    u32 period;
    char logs[PATH_LEN];
    char debug_dir[PATH_LEN];
    struct flame_graph_param_s params[STACK_SVG_MAX];
};

struct svg_stack_trace_s {
    int bpf_prog_fd;
    struct bpf_object *obj;
    const char *custom_btf_path;
    pthread_t wr_flame_thd;

    struct bpf_buffer *perf_buff_a;
    struct bpf_buffer *perf_buff_b;

    struct raw_stack_trace_s *raw_stack_trace_a;
    struct raw_stack_trace_s *raw_stack_trace_b;
    struct py_stack_trace_s *py_stack_trace_a;
    struct py_stack_trace_s *py_stack_trace_b;

    struct stack_svg_mng_s *svg_mng;
    struct proc_stack_trace_histo_s *proc_histo_tbl;
};

struct post_server_s {
    char post_enable;
    char multi_instance_flag;
    u32 perf_sample_period; // ms
    long timeout; // sec
    char host[PATH_LEN];
    char app_suffix[APP_SUFFIX_LEN];
};

struct stack_trace_s {
    char pad[3];
    char is_stackmap_a;
    char multi_instance_flag;
    char native_stack_flag;
    int cpus_num;
    u32 whitelist_enable;
    int convert_map_fd;
    int proc_obj_map_fd;
    int stackmap_a_fd;
    int stackmap_b_fd;
    int py_proc_map_fd;
    int py_symbols_map_fd;
    int py_symbol_ids_map_fd;
    int py_sample_heap_map_fd;
    u64 convert_stack_count;
    time_t running_times;
    struct post_server_s post_server;

    struct svg_stack_trace_s *svg_stack_traces[STACK_SVG_MAX];
    struct ksymb_tbl_s *ksymbs;
    struct proc_cache_s *proc_cache;
    u32 proc_cache_mirro_count;
    struct proc_cache_s *proc_cache_mirro[PROC_CACHE_MAX_COUNT]; // No release is required.

    struct elf_reader_s *elf_reader;

    struct stack_stats_s stats;

    void* log_mgr;

    struct stack_param_s stack_params;

    int pmu_fd[];   // It must be put to the last.
};

void iter_histo_tbl(struct proc_stack_trace_histo_s *proc_histo, struct post_server_s *post_server,
    struct stack_svg_mng_s *svg_mng, int en_type);

#endif
