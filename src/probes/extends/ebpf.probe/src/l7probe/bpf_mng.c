/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wo_cow
 * Create: 2023-03-07
 * Description: BPF prog lifecycle management
 ******************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "args.h"
#include "object.h"
#include "include/uprobe_loader.h"
#include "include/conn_tracker.h"
#include "bpf/kern_sock.skel.h"

enum bpf_index_t {
    BPF_KERN_SOCK = 0,
    BPF_LIBSSl,
    BPF_INDEX_MAX
};

#define L7_CONN_DATA_MAP        "conn_data_events"
#define L7_CONN_CONTROL_MAP     "conn_control_events"
#define L7_CONN_STATS_MAP       "conn_stats_events"
#define L7_CONN_DATA_PATH        "/sys/fs/bpf/gala-gopher/__l7_conn_data"
#define L7_CONN_CONTROL_PATH     "/sys/fs/bpf/gala-gopher/__l7_conn_control"
#define L7_CONN_STATS_PATH       "/sys/fs/bpf/gala-gopher/__l7_conn_stats"
#define L7_SSL_PROG              "/opt/gala-gopher/extend_probes/l7_bpf/libssl.bpf.o"

#define __LOAD_PROBE(probe_name, end, load) \
    OPEN(probe_name, end, load); \
    MAP_SET_PIN_PATH(probe_name, conn_data_events, L7_CONN_DATA_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, conn_control_events, L7_CONN_CONTROL_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, conn_stats_events, L7_CONN_STATS_PATH, load); \
    LOAD_ATTACH(probe_name, end, load)

typedef int (*LoadFunc)(struct bpf_prog_s *prog);
extern volatile sig_atomic_t stop;

typedef struct {
    enum bpf_index_t bpf_index;
    LoadFunc func;
} BpfProc;

// cgroup_msg processing is slow, so we use threads to process msgs from different bpf prog to prevent blocking.
static void *__poll_pb(void *arg)
{
    struct perf_buffer *pb = arg;

    while (!stop) {
        if (pb) {
            if (perf_buffer__poll(pb, THOUSAND) < 0) {
                break;
            }
        }
    }

    return NULL;
}

static int __create_msg_hdl_thd(int msg_fd, perf_buffer_sample_fn cb, struct bpf_prog_s *prog)
{
    struct perf_buffer *pb = NULL;
    int ret;

    pb = create_pref_buffer(msg_fd, cb);
    if (pb == NULL) {
        ERROR("[L7PROBE]: Create perf buffer failed.\n");
        return -1;
    }
    prog->pbs[prog->num] = pb;

    ret = pthread_create(&prog->resident_thd[prog->num], NULL, __poll_pb, (void *)pb);
    if (ret != 0) {
        ERROR("[L7PROBE]: Failed to create message event handler thread.\n");
        return -1;
    }
    (void)pthread_detach(prog->resident_thd[prog->num]);
    prog->num++;
    return 0;
}

static struct bpf_object *__init_libssl_bpf()
{
    int ret;

    // 1. open bpf object
    struct bpf_object *obj = bpf_object__open_file(L7_SSL_PROG, NULL);
    ret = libbpf_get_error(obj);
    if (ret) {
        ERROR("[L7PROBE]: Opening libssl object file failed(err = %d).\n", ret);
        return NULL;
    }

    // 2. pin public bpf map
    ret = BPF_OBJ_PIN_MAP_PATH(obj, L7_CONN_DATA_MAP, L7_CONN_DATA_PATH);
    if (ret) {
        ERROR("L7PROBE] Failed to pin %s(err = %d).\n", L7_CONN_DATA_MAP, ret);
        bpf_object__close(obj);
        return NULL;
    }
    ret = BPF_OBJ_PIN_MAP_PATH(obj, L7_CONN_CONTROL_MAP, L7_CONN_CONTROL_PATH);
    if (ret) {
        ERROR("L7PROBE] Failed to pin %s(err = %d).\n", L7_CONN_CONTROL_MAP, ret);
        bpf_object__close(obj);
        return NULL;
    }
    ret = BPF_OBJ_PIN_MAP_PATH(obj, L7_CONN_STATS_MAP, L7_CONN_STATS_PATH);
    if (ret) {
        ERROR("L7PROBE] Failed to pin %s(err = %d).\n", L7_CONN_STATS_MAP, ret);
        bpf_object__close(obj);
        return NULL;
    }

    ret = bpf_object__load(obj);
    if (ret) {
        ERROR("L7PROBE] Failed to load %s.\n", L7_SSL_PROG);
        bpf_object__close(obj);
        return NULL;
    }
    return obj;
}

int l7_load_probe_libssl(struct bpf_prog_s *prog)
{
    int ret = 0;
    int init = 0;

    // 1. pin public bpf map
    struct bpf_object *obj = __init_libssl_bpf();
    if (obj == NULL) {
        return 0;
    }

    // 2. create thread of uprobe loading
    struct proc_load_args_s proc_load_args = {
        .proc_obj_map_fd = obj_get_proc_obj_map_fd(),
        .init = &init, // TODO: to delete
        .libname = "libssl",
        .bpf_obj = obj,
    };

    // The message event handling thread is started by l7_load_probe_kern_sock.
    ret = pthread_create(&prog->resident_thd[prog->num], NULL, load_n_unload_uprobe, (void *)&proc_load_args);
    if (ret != 0) {
        ERROR("[L7PROBE]: Failed to create libssl bpf load thread.\n");
        return 0;
    }
    (void)pthread_detach(prog->resident_thd[prog->num]);
    prog->num++;

    INFO("[L7PROBE]: init libssl bpf prog succeed.\n");
    return 0;
}

int l7_load_probe_kern_sock(struct bpf_prog_s *prog)
{
    int fd, ret;

    __LOAD_PROBE(kern_sock, err, 1);
    prog->skels[prog->num].skel = kern_sock_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)kern_sock_bpf__destroy;

    fd = GET_MAP_FD(kern_sock, conn_control_events);
    ret = __create_msg_hdl_thd(fd, l7_conn_control_msg_handler, prog);
    if (ret != 0) {
        return ret;
    }

    fd = GET_MAP_FD(kern_sock, conn_stats_events);
    ret = __create_msg_hdl_thd(fd, l7_conn_stats_msg_handler, prog);
    if (ret != 0) {
        return ret;
    }

    INFO("[L7PROBE]: init kern_sock bpf prog  succeed.\n");
    return 0;
err:
    UNLOAD(kern_sock);
    return -1;
}

static char is_load_probe(struct probe_params *args, enum bpf_index_t bpf_index)
{
    u32 bpf_switch = (u32)(1 << bpf_index);
    return args->load_probe & bpf_switch;
}

struct bpf_prog_s *init_bpf_progs(struct probe_params *args)
{
    struct bpf_prog_s *prog = alloc_bpf_prog();
    if (prog == NULL) {
        return NULL;
    }

    static BpfProc bpf_procs[] = {
        { BPF_KERN_SOCK, l7_load_probe_kern_sock },
        { BPF_LIBSSl, l7_load_probe_libssl }
    };

    for (int i = 0; i < BPF_INDEX_MAX; i++) {
        if (!is_load_probe(args, bpf_procs[i].bpf_index) || !bpf_procs[i].func) {
            continue;
        }

        if (bpf_procs[i].func(prog)) {
            return NULL;
        }

        //load_args(GET_MAP_FD(cgroup, args_map), args);
    }
    
    return prog;
}

