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
 * Author: wo_cow
 * Create: 2022-06-10
 * Description: cgprobe user prog
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
#include "cgprobe.skel.h"
#include "cgprobe.h"

#define CGPROBE "cgprobe"

#define OUTPUT_PATH "/sys/fs/bpf/gala-gopher/__cgprobe_output"
#define ARGS_PATH "/sys/fs/bpf/gala-gopher/__cgprobe_args"
#define RM_BPF_PATH "/usr/bin/rm -rf /sys/fs/bpf/gala-gopher/__cgprobe*"

#define __LOAD_CG_PROBE(probe_name, end, load) \
    OPEN(probe_name, end, load); \
    MAP_SET_PIN_PATH(probe_name, output, OUTPUT_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, args_map, ARGS_PATH, load); \
    LOAD_ATTACH(probe_name, end, load)

static struct probe_params params = {.period = DEFAULT_PERIOD};


static void print_cg_metrics(void *ctx, int cpu, void *data, __u32 size)
{
    struct mem_cgroup_gauge* cg  = (struct mem_cgroup_gauge*)data;

    (void)fprintf(stdout,
        "|%s|%llu|%u|%d|\n",
        CGPROBE,
        cg->cgroup_id,
        cg->nr_pages,
        cg->oom_order);
    (void)fflush(stdout);
}

static void load_args(int args_fd, struct probe_params* params)
{
    __u32 key = 0;
    struct ns_args_s args = {0};

    args.period = NS(params->period);

    (void)bpf_map_update_elem(args_fd, &key, &args, BPF_ANY);
}

int main(int argc, char **argv)
{
    int err = -1;
    struct perf_buffer* pb = NULL;
    FILE *fp = NULL;

    fp = popen(RM_BPF_PATH, "r");
    if (fp != NULL) {
        (void)pclose(fp);
        fp = NULL;
    }

    err = args_parse(argc, argv, &params);
    if (err != 0) {
        return -1;
    }

    printf("arg parse interval time:%us\n", params.period);

    INIT_BPF_APP(cgprobe, EBPF_RLIM_LIMITED);
    __LOAD_CG_PROBE(cgprobe, err, 1);
    load_args(GET_MAP_FD(cgprobe, args_map), &params);
    pb = create_pref_buffer(GET_MAP_FD(cgprobe, output), print_cg_metrics);
    if (pb == NULL) {
        fprintf(stderr, "ERROR: crate perf buffer failed\n");
        goto err;
    }

    printf("Successfully started!\n");
    poll_pb(pb, params.period * THOUSAND);

err:
    if (pb) {
        perf_buffer__free(pb);
    }
    UNLOAD(cgprobe);
    return -err;
}
