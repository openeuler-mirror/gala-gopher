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
 * Create: 2021-05-17
 * Description: kill_probe user prog
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
#include "args.h"

#include "killprobe.skel.h"
#include "killprobe.h"

#define PROBE_NAME "kill_info"

static struct probe_params params = {.period = DEFAULT_PERIOD};

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{
    struct val_t *pv;

    pv = (struct val_t *)data;

    (void)fprintf(stdout,
        "|%s|%llu|%u|%u|%s|\n",
        PROBE_NAME,
        pv->killer_pid,
        pv->signal,
        pv->killed_pid,
        pv->comm);
    (void)fflush(stdout);
}


int main(int argc, char **argv)
{
    int map_fd, err;
    struct perf_buffer* pb = NULL;

    err = args_parse(argc, argv, &params);
    if (err != 0)
        return -1;

    printf("arg parse interval time:%us\n", params.period);

    INIT_BPF_APP(killprobe, EBPF_RLIM_LIMITED);
    LOAD(killprobe, err);

    map_fd = GET_MAP_FD(killprobe, output);

    pb = create_pref_buffer(map_fd, print_bpf_output);
    if (pb == NULL) {
        fprintf(stderr, "ERROR: crate perf buffer failed\n");
        goto err;
    }

    poll_pb(pb, params.period * THOUSAND);

    perf_buffer__free(pb);
err:
    UNLOAD(killprobe);
    return 0;
}