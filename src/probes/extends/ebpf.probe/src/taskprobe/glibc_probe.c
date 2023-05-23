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
 * Create: 2022-07-13
 * Description: glibc probe
 ******************************************************************************/
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/resource.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "task.h"
#include "proc.h"
#include "glibc.skel.h"
#include "bpf_prog.h"

#define __LOAD_PROBE(probe_name, end, load) \
    OPEN(probe_name, end, load); \
    MAP_SET_PIN_PATH(probe_name, args_map, ARGS_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, g_proc_map, PROC_PATH, load); \
    LOAD_ATTACH(probe_name, end, load)

void output_proc_metrics(void *ctx, int cpu, void *data, __u32 size);

static int load_glibc_create_pb(struct bpf_prog_s* prog, int fd)
{
    struct perf_buffer *pb;

    if (prog->pb == NULL) {
        pb = create_pref_buffer(fd, output_proc_metrics);
        if (pb == NULL) {
            fprintf(stderr, "ERROR: crate perf buffer failed\n");
            return -1;
        }
        prog->pb = pb;
        INFO("Success to create glibc pb buffer.\n");
    }
    return 0;
}

int load_glibc_bpf_prog(struct task_probe_s *task_probe, const char *glibc_path, struct bpf_prog_s **new_prog)
{
    int ret, succeed;
    int link_num = 0;
    struct bpf_prog_s *prog;

    *new_prog = NULL;

    prog = alloc_bpf_prog();
    if (prog == NULL) {
        return -1;
    }

    __LOAD_PROBE(glibc, err, 1);
    prog->skels[prog->num].skel = glibc_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)glibc_bpf__destroy;
    prog->num++;
    task_probe->proc_map_fd = GET_MAP_FD(glibc, g_proc_map);
    task_probe->args_fd = GET_MAP_FD(glibc, args_map);

    // Glibc bpf prog attach function 'getaddrinfo'
    UBPF_ATTACH(glibc, getaddrinfo, glibc_path, getaddrinfo, succeed);
    if (!succeed) {
        goto err;
    }
    prog->skels[prog->num]._link[link_num++] = (void *)glibc_link[glibc_link_current - 1];

    UBPF_RET_ATTACH(glibc, getaddrinfo, glibc_path, getaddrinfo, succeed);
    if (!succeed) {
        goto err;
    }
    prog->skels[prog->num]._link[link_num++] = (void *)glibc_link[glibc_link_current - 1];

    // Glibc bpf prog attach function 'gethostbyname2'
    UBPF_ATTACH(glibc, gethostbyname2, glibc_path, gethostbyname2, succeed);
    if (!succeed) {
        goto err;
    }
    prog->skels[prog->num]._link[link_num++] = (void *)glibc_link[glibc_link_current - 1];

    UBPF_RET_ATTACH(glibc, gethostbyname2, glibc_path, gethostbyname2, succeed);
    if (!succeed) {
        goto err;
    }
    prog->skels[prog->num]._link[link_num++] = (void *)glibc_link[glibc_link_current - 1];

    // Glibc bpf prog attach function 'gethostbyname'
    UBPF_ATTACH(glibc, gethostbyname, glibc_path, gethostbyname, succeed);
    if (!succeed) {
        goto err;
    }
    prog->skels[prog->num]._link[link_num++] = (void *)glibc_link[glibc_link_current - 1];

    UBPF_RET_ATTACH(glibc, gethostbyname, glibc_path, gethostbyname, succeed);
    if (!succeed) {
        goto err;
    }
    prog->skels[prog->num]._link[link_num++] = (void *)glibc_link[glibc_link_current - 1];
    prog->skels[prog->num]._link_num = link_num;

    ret = load_glibc_create_pb(prog, GET_MAP_FD(glibc, g_proc_output));
    if (ret) {
        goto err;
    }

    *new_prog = prog;
    return 0;

err:
    UNLOAD(glibc);

    if (prog) {
        free_bpf_prog(prog);
    }
    return -1;
}

