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
#include "include/pod.h"
#include "bpf/cgroup.skel.h"

enum bpf_index_t {
    BPF_KERN_SOCK,
    BPF_CGROUP,
    BPF_LIBSSl,
    BPF_GOSSL,
    BPF_INDEX_MAX
};

#define L7_ARGS_PATH "/sys/fs/bpf/gala-gopher/__l7_args"

#define __LOAD_PROBE(probe_name, end, load) \
    OPEN(probe_name, end, load); \
    LOAD_ATTACH(probe_name, end, load)

typedef int (*LoadFunc)(struct bpf_prog_s *prog);
extern volatile sig_atomic_t stop;

typedef struct {
    enum bpf_index_t bpf_index;
    LoadFunc func;
    char *bpf_name;
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

int l7_load_probe_cgroup(struct bpf_prog_s *prog)
{
    int fd, ret;
    struct perf_buffer *pb = NULL;

    __LOAD_PROBE(cgroup, err, 1);
    prog->skels[prog->num].skel = cgroup_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)cgroup_bpf__destroy;

    fd = GET_MAP_FD(cgroup, cgroup_msg_map);
    pb = create_pref_buffer(fd, l7_cgroup_msg_handler);
    if (pb == NULL) {
        ERROR("[L7PROBE] Create 'cgroup' perf buffer failed.\n");
        goto err;
    }
    prog->pbs[prog->num] = pb;
    ret = pthread_create(&prog->msg_evt_thd[prog->num], NULL, __poll_pb, (void *)pb);
    if (ret != 0) {
        fprintf(stderr, "Failed to create cgroup message event handler thread.\n");
        return -1;
    }
    prog->num++;

    return 0;

err:
    UNLOAD(cgroup);
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
        { BPF_KERN_SOCK, NULL, "kern_sock" },
        { BPF_CGROUP, l7_load_probe_cgroup, "cgroup" },
        { BPF_LIBSSl, NULL, "libssl" },
        { BPF_GOSSL, NULL, "gossl" },
    };

    for (int i = 0; i < BPF_INDEX_MAX; i++) {
        if (!is_load_probe(args, bpf_procs[i].bpf_index) || !bpf_procs[i].func) {
            continue;
        }

        if (bpf_procs[i].func(prog)) {
            goto err;
        }

        //load_args(GET_MAP_FD(cgroup, args_map), args);

        INFO("[L7PROBE]: init bpf prog [%s] succeed.\n", bpf_procs[i].bpf_name);
    }
    
    return prog;

err:
    unload_bpf_prog(&prog);
    return NULL;
}

