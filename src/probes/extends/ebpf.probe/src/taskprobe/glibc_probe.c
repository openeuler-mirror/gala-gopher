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
    MAP_SET_PIN_PATH(probe_name, period_map, PERIOD_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, g_proc_map, PROC_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, g_proc_output, PROC_OUTPUT_PATH, load); \
    LOAD_ATTACH(probe_name, end, load)

struct bpf_prog_s* load_glibc_bpf_prog(struct probe_params *args)
{
    int ret, succeed;
    int link_num = 0;
    char glibc_path[PATH_LEN];
    struct bpf_prog_s *prog;

    if (!(args->load_probe & TASK_PROBE_DNS_OP)) {
        return NULL;
    }

    prog = alloc_bpf_prog();
    if (prog == NULL) {
        return NULL;
    }

    __LOAD_PROBE(glibc, err, 1);
    prog->skels[prog->num].skel = glibc_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)glibc_bpf__destroy;
    prog->num++;

    glibc_path[0] = 0;
    ret = get_glibc_path(NULL, glibc_path, PATH_LEN);
    if (ret) {
        goto err;
    }

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

    return prog;

err:
    UNLOAD(glibc);

    if (prog) {
        free_bpf_prog(prog);
    }
    return NULL;
}

