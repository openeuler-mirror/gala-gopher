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
 * Author: Mr.lu
 * Create: 2021-09-28
 * Description: bpf header
 ******************************************************************************/
#ifndef __GOPHER_LIB_BPF_H__
#define __GOPHER_LIB_BPF_H__

#pragma once

#if !defined( BPF_PROG_KERN ) && !defined( BPF_PROG_USER )

#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include "elf_reader.h"
#include "gopher_elf.h"
#include "object.h"
#include "common.h"

#define EBPF_RLIM_LIMITED  100*1024*1024 // 100M
#define EBPF_RLIM_INFINITY (~0UL)
static __always_inline int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_WARN)
        return vfprintf(stderr, format, args);

    return 0;
}

static __always_inline int set_memlock_rlimit(unsigned long limit)
{
    struct rlimit rlim_new = {
        .rlim_cur   = limit,
        .rlim_max   = limit,
    };

    if (setrlimit(RLIMIT_MEMLOCK, (const struct rlimit *)&rlim_new) != 0) {
        (void)fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        return 0;
    }
    return 1;
}

#define GET_MAP_OBJ(probe_name, map_name) (probe_name##_skel->maps.map_name)
#define GET_MAP_FD(probe_name, map_name) bpf_map__fd(probe_name##_skel->maps.map_name)
#define GET_PROG_FD(prog_name) bpf_program__fd(probe_name##_skel->progs.prog_name)

#define BPF_OBJ_GET_MAP_FD(obj, map_name)   \
            ({ \
                int __fd = -1; \
                struct bpf_map *__map = bpf_object__find_map_by_name((obj), (map_name)); \
                if (__map) { \
                    __fd = bpf_map__fd(__map); \
                } \
                __fd; \
            })

#define BPF_OBJ_PIN_MAP_PATH(obj, map_name, path)   \
            ({ \
                int __ret = -1; \
                struct bpf_map *__map = bpf_object__find_map_by_name((obj), (map_name)); \
                if (__map) { \
                    __ret = bpf_map__set_pin_path(__map, path); \
                } \
                __ret; \
            })


#define __MAP_SET_PIN_PATH(probe_name, map_name, map_path) \
    do { \
        int ret; \
        struct bpf_map *__map; \
        \
        __map = GET_MAP_OBJ(probe_name, map_name); \
        ret = bpf_map__set_pin_path(__map, map_path); \
        DEBUG("======>SHARE map(" #map_name ") set pin path \"%s\"(ret=%d).\n", map_path, ret); \
    } while (0)

#define __PIN_SHARE_MAP_ALL(probe_name) \
        do { \
            __MAP_SET_PIN_PATH(probe_name, cgrp_obj_map, CGRP_MAP_PATH); \
            __MAP_SET_PIN_PATH(probe_name, nm_obj_map, NM_MAP_PATH); \
            __MAP_SET_PIN_PATH(probe_name, proc_obj_map, PROC_MAP_PATH); \
        } while (0)

#define INIT_BPF_APP(app_name, limit) \
    static char __init = 0; \
    do { \
        if (!__init) { \
            /* Set up libbpf errors and debug info callback */ \
            (void)libbpf_set_print(libbpf_print_fn); \
            \
            /* Bump RLIMIT_MEMLOCK  allow BPF sub-system to do anything */ \
            if (set_memlock_rlimit(limit) == 0) { \
                ERROR("BPF app(" #app_name ") failed to set mem limit.\n"); \
                return -1; \
            } \
            __init = 1; \
        } \
    } while (0)

#define LOAD(probe_name, end) \
    struct probe_name##_bpf *probe_name##_skel = NULL;           \
    struct bpf_link *probe_name##_link[PATH_NUM] __maybe_unused; \
    int probe_name##_link_current = 0;    \
    do { \
        int err; \
        /* Open load and verify BPF application */ \
        probe_name##_skel = probe_name##_bpf__open(); \
        if (!probe_name##_skel) { \
            ERROR("Failed to open BPF " #probe_name " skeleton\n"); \
            goto end; \
        } \
        __PIN_SHARE_MAP_ALL(probe_name); \
        if (probe_name##_bpf__load(probe_name##_skel)) { \
            ERROR("Failed to load BPF " #probe_name " skeleton\n"); \
            goto end; \
        } \
        /* Attach tracepoint handler */ \
        err = probe_name##_bpf__attach(probe_name##_skel); \
        if (err) { \
            ERROR("Failed to attach BPF " #probe_name " skeleton\n"); \
            probe_name##_bpf__destroy(probe_name##_skel); \
            probe_name##_skel = NULL; \
            goto end; \
        } \
        INFO("Succeed to load and attach BPF " #probe_name " skeleton\n"); \
    } while (0)

#define OPEN(probe_name, end, load) \
    struct probe_name##_bpf *probe_name##_skel = NULL;           \
    struct bpf_link *probe_name##_link[PATH_NUM] __maybe_unused; \
    int probe_name##_link_current = 0;    \
    do { \
        if (load) \
        {\
            /* Open load and verify BPF application */ \
            probe_name##_skel = probe_name##_bpf__open(); \
            if (!probe_name##_skel) { \
                ERROR("Failed to open BPF " #probe_name " skeleton\n"); \
                goto end; \
            } \
        }\
    } while (0)
    
#define MAP_SET_PIN_PATH(probe_name, map_name, map_path, load) \
    do { \
        if (load) \
        { \
            __MAP_SET_PIN_PATH(probe_name, map_name, map_path); \
        } \
    } while (0)
    
#define LOAD_ATTACH(probe_name, end, load) \
    do { \
        if (load) \
        { \
            int err; \
            __PIN_SHARE_MAP_ALL(probe_name); \
            if (probe_name##_bpf__load(probe_name##_skel)) { \
                ERROR("Failed to load BPF " #probe_name " skeleton\n"); \
                goto end; \
            } \
            /* Attach tracepoint handler */ \
            err = probe_name##_bpf__attach(probe_name##_skel); \
            if (err) { \
                ERROR("Failed to attach BPF " #probe_name " skeleton\n"); \
                probe_name##_bpf__destroy(probe_name##_skel); \
                probe_name##_skel = NULL; \
                goto end; \
            } \
            INFO("Succeed to load and attach BPF " #probe_name " skeleton\n"); \
        } \
    } while (0)

#define UNLOAD(probe_name) \
    do { \
        int err; \
        if (probe_name##_skel != NULL) { \
            probe_name##_bpf__destroy(probe_name##_skel); \
        } \
        for (int i = 0; i < probe_name##_link_current; i++) { \
            err = bpf_link__destroy(probe_name##_link[i]); \
            if (err < 0) { \
                ERROR("Failed to detach BPF " #probe_name " %d\n", err); \
                break; \
            } \
        } \
    } while (0)

#define UNATTACH_ONELINK(probe_name, bpf_link_p) \
    do { \
        int err = bpf_link__destroy(bpf_link_p); \
        if (err < 0) { \
            ERROR("Failed to detach BPF" #probe_name " %d\n", err); \
        } \
    } while (0)

#define ELF_REAL_PATH(binary_file, elf_abs_path, container_id, elf_path, path_num) \
    do { \
        path_num = get_exec_file_path( #binary_file, (const char *)elf_abs_path, #container_id, elf_path, PATH_NUM); \
        if ((path_num) <= 0) { \
            ERROR("Failed to get proc(" #binary_file ") abs_path.\n"); \
            free_exec_path_buf(elf_path, path_num); \
            break; \
        } \
    } while (0)

#define UBPF_ATTACH(probe_name, sec, elf_path, func_name, succeed) \
    do { \
        int err; \
        u64 symbol_offset; \
        err = gopher_get_elf_symb((const char *)elf_path, #func_name, &symbol_offset); \
        if (err < 0) { \
            ERROR("Failed to get func(" #func_name ") in(%s) offset.\n", elf_path); \
            succeed = 0; \
            break; \
        } \
        \
        /* Attach tracepoint handler */ \
        probe_name##_link[probe_name##_link_current] = bpf_program__attach_uprobe( \
            probe_name##_skel->progs.ubpf_##sec, false /* not uretprobe */, -1, elf_path, (size_t)symbol_offset); \
        err = libbpf_get_error(probe_name##_link[probe_name##_link_current]); \
        if (err) { \
            ERROR("Failed to attach uprobe(" #sec "): %d\n", err); \
            succeed = 0; \
            break; \
        } \
        INFO("Success to attach uprobe(" #probe_name "): to elf: %s\n", elf_path); \
        probe_name##_link_current += 1; \
        succeed = 1; \
    } while (0)

#define UBPF_RET_ATTACH(probe_name, sec, elf_path, func_name, succeed) \
    do { \
        int err; \
        u64 symbol_offset; \
        err = gopher_get_elf_symb((const char *)elf_path, #func_name, &symbol_offset); \
        if (err < 0) { \
            ERROR("Failed to get func(" #func_name ") in(%s) offset.\n", elf_path); \
            succeed = 0; \
            break; \
        } \
        \
        /* Attach tracepoint handler */ \
        probe_name##_link[probe_name##_link_current] = bpf_program__attach_uprobe( \
            probe_name##_skel->progs.ubpf_ret_##sec, true /* uretprobe */, -1, elf_path, (size_t)symbol_offset); \
        err = libbpf_get_error(probe_name##_link[probe_name##_link_current]); \
        if (err) { \
            ERROR("Failed to attach uretprobe(" #sec "): %d\n", err); \
            succeed = 0; \
            break; \
        } \
        INFO("Success to attach uretprobe(" #probe_name ") to elf: %s\n", elf_path); \
        probe_name##_link_current += 1; \
        succeed = 1; \
    } while (0)

#define URETBPF_ATTACH(probe_name, sec, elf_path, func_name, succeed) \
    do { \
        int err; \
        u64 symbol_offset; \
        err = gopher_get_elf_symb((const char *)elf_path, #func_name, &symbol_offset); \
        if (err < 0) { \
            ERROR("Failed to get func(" #func_name ") in(%s) offset.\n", elf_path); \
            succeed = 0; \
            break; \
        } \
        \
        /* Attach tracepoint handler */ \
        probe_name##_link[probe_name##_link_current] = bpf_program__attach_uprobe( \
            probe_name##_skel->progs.__uprobe_bpf_##sec, false, -1, elf_path, (size_t)symbol_offset); \
        err = libbpf_get_error(probe_name##_link[probe_name##_link_current]); \
        if (err) { \
            ERROR("Failed to attach __uprobe_bpf_(" #sec "): %d\n", err); \
            succeed = 0; \
            break; \
        } \
        probe_name##_link_current += 1; \
        probe_name##_link[probe_name##_link_current] = bpf_program__attach_uprobe( \
            probe_name##_skel->progs.__uprobe_ret_bpf_##sec, true, -1, elf_path, (size_t)symbol_offset); \
        err = libbpf_get_error(probe_name##_link[probe_name##_link_current]); \
        if (err) { \
            ERROR("Failed to attach __uprobe_ret_bpf_(" #sec "): %d\n", err); \
            succeed = 0; \
            break; \
        } \
        INFO("Success to attach URETBPF_ATTACH(" #probe_name ") to elf: %s\n", elf_path); \
        probe_name##_link_current += 1; \
        succeed = 1; \
    } while (0)


#define UBPF_ATTACH_ONELINK(probe_name, sec, elf_path, func_name, bpf_link_p, succeed) \
    do { \
        int err; \
        u64 symbol_offset; \
        err = gopher_get_elf_symb((const char *)elf_path, #func_name, &symbol_offset); \
        if (err < 0) { \
            ERROR("Failed to get func(" #func_name ") in(%s) offset.\n", elf_path); \
            succeed = 0; \
            break; \
        } \
        \
        /* Attach tracepoint handler */ \
        bpf_link_p = bpf_program__attach_uprobe( \
            probe_name##_skel->progs.ubpf_##sec, false, -1, elf_path, (size_t)symbol_offset); \
        err = libbpf_get_error(bpf_link_p); \
        if (err) { \
            ERROR("Failed to attach uprobe(" #probe_name ") sec(" #sec "): %d\n", err); \
            succeed = 0; \
            break; \
        } \
        INFO("Success to attach uprobe(" #probe_name ") sec(" #sec "): to elf: %s\n", elf_path); \
        succeed = 1; \
    } while (0)

#define UBPF_RET_ATTACH_ONELINK(probe_name, sec, elf_path, func_name, bpf_link_p, succeed) \
    do { \
        int err; \
        u64 symbol_offset; \
        err = gopher_get_elf_symb((const char *)elf_path, #func_name, &symbol_offset); \
        if (err < 0) { \
            ERROR("Failed to get func(" #func_name ") in(%s) offset.\n", elf_path); \
            succeed = 0; \
            break; \
        } \
        \
        /* Attach tracepoint handler */ \
        bpf_link_p = bpf_program__attach_uprobe( \
            probe_name##_skel->progs.ubpf_ret_##sec, true, -1, elf_path, (size_t)symbol_offset); \
        err = libbpf_get_error(bpf_link_p); \
        if (err) { \
            ERROR("Failed to attach uretprobe(" #probe_name ") sec(" #sec "): %d\n", err); \
            succeed = 0; \
            break; \
        } \
        INFO("Success to attach uretprobe(" #probe_name ") sec(" #sec ") to elf: %s\n", elf_path); \
        succeed = 1; \
    } while (0)


static __always_inline __maybe_unused struct perf_buffer* __do_create_pref_buffer(int map_fd,
                perf_buffer_sample_fn cb, perf_buffer_lost_fn lost_cb)
{
    struct perf_buffer *pb;
    int ret;

#if (CURRENT_LIBBPF_VERSION  >= LIBBPF_VERSION(0, 8))
    pb = perf_buffer__new(map_fd, 8, cb, lost_cb, NULL, NULL);
#else
    struct perf_buffer_opts pb_opts = {};
    pb_opts.sample_cb = cb;
    pb_opts.lost_cb = lost_cb;
    pb = perf_buffer__new(map_fd, 8, &pb_opts);
#endif
    if (pb == NULL){
        fprintf(stderr, "ERROR: perf buffer new failed\n");
        return NULL;
    }
    ret = libbpf_get_error(pb);
    if (ret) {
        fprintf(stderr, "ERROR: failed to setup perf_buffer: %d\n", ret);
        perf_buffer__free(pb);
        return NULL;
    }
    return pb;
}

static __always_inline __maybe_unused struct perf_buffer* create_pref_buffer2(int map_fd,
                perf_buffer_sample_fn cb, perf_buffer_lost_fn lost_cb)
{
    return __do_create_pref_buffer(map_fd, cb, lost_cb);
}

static __always_inline __maybe_unused struct perf_buffer* create_pref_buffer(int map_fd, perf_buffer_sample_fn cb)
{
    return __do_create_pref_buffer(map_fd, cb, NULL);
}

static __always_inline __maybe_unused void poll_pb(struct perf_buffer *pb, int timeout_ms)
{
    int ret;

    while ((ret = perf_buffer__poll(pb, timeout_ms)) >= 0) {
        ;
    }
    return;
}

#define SKEL_MAX_NUM  20
typedef void (*skel_destroy_fn)(void *);

struct __bpf_skel_s {
    skel_destroy_fn fn;
    void *skel;
    void *_link[PATH_NUM];
    size_t _link_num;
};
struct bpf_prog_s {
    struct perf_buffer* pb;
    struct perf_buffer* pbs[SKEL_MAX_NUM];  // 支持每个探针拥有各自的perf_buffer，目前tcpprobe使用
    pthread_t resident_thd[SKEL_MAX_NUM];
    struct __bpf_skel_s skels[SKEL_MAX_NUM];
    size_t num;
};

static __always_inline __maybe_unused void free_bpf_prog(struct bpf_prog_s *prog)
{
    (void)free(prog);
}

static __always_inline __maybe_unused struct bpf_prog_s *alloc_bpf_prog(void)
{
    struct bpf_prog_s *prog = malloc(sizeof(struct bpf_prog_s));
    if (prog == NULL) {
        return NULL;
    }

    (void)memset(prog, 0, sizeof(struct bpf_prog_s));
    return prog;
}

static __always_inline __maybe_unused void unload_bpf_prog(struct bpf_prog_s **unload_prog)
{
    struct bpf_prog_s *prog = *unload_prog;

    *unload_prog = NULL;
    if (prog == NULL) {
        return;
    }

    for (int i = 0; i < prog->num; i++) {
        if (prog->skels[i].skel) {
            prog->skels[i].fn(prog->skels[i].skel);

            for (int j = 0; j < prog->skels[i]._link_num; j++) {
                if (prog->skels[i]._link[j]) {
                    (void)bpf_link__destroy(prog->skels[i]._link[j]);
                }
            }
        }

        if (prog->pbs[i]) {
            perf_buffer__free(prog->pbs[i]);
        }
    }

    if (prog->pb) {
        perf_buffer__free(prog->pb);
    }
    free_bpf_prog(prog);
    return;
}


#endif
#endif
