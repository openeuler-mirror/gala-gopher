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
 * Description: thread probe
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
#include "thread.h"
#include "event.h"
#include "task.h"
#include "cpu.skel.h"
#include "thread.skel.h"
#include "bpf_prog.h"
#include "taskprobe.h"

#ifdef OO_NAME
#undef OO_NAME
#endif
#define OO_NAME  "thread"
#define THREAD_TBL_CPU      "thread_cpu"

static struct probe_params *g_args;

#define __LOAD_PROBE(probe_name, end, load) \
    OPEN(probe_name, end, load); \
    MAP_SET_PIN_PATH(probe_name, g_thread_output, THREAD_OUTPUT_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, g_thread_map, THREAD_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, g_proc_map, PROC_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, args_map, ARGS_PATH, load); \
    LOAD_ATTACH(probe_name, end, load)

static void report_thread_metrics(struct thread_data *thr)
{
    char entityId[INT_LEN];

    if (g_args->logs == 0) {
        return;
    }

    entityId[0] = 0;
    (void)snprintf(entityId, INT_LEN, "%d", thr->id.pid);

    report_logs(OO_NAME,
                entityId,
                "off_cpu_ns",
                EVT_SEC_WARN,
                "Process(COMM:%s TID:%d) is preempted(COMM:%s PID:%d) and off-CPU %llu ns.",
                thr->id.comm,
                thr->id.pid,
                thr->cpu.preempt_comm,
                thr->cpu.preempt_id,
                thr->cpu.off_cpu_ns);
}

static void output_thread_metrics_cpu(struct thread_data *thr)
{
    (void)fprintf(stdout,
        "|%s|%d|%d|%s|"
        "%llu|%u|\n",
        THREAD_TBL_CPU,
        thr->id.pid,
        thr->id.tgid,
        thr->id.comm,

        thr->cpu.off_cpu_ns,
        thr->cpu.migration_count);
    return;
}

static void output_thread_metrics(void *ctx, int cpu, void *data, __u32 size)
{
    struct thread_data *thr = (struct thread_data *)data;
    u32 flags = thr->flags;

    report_thread_metrics(thr);

    if (flags & TASK_PROBE_THREAD_CPU) {
        output_thread_metrics_cpu(thr);
    }
    (void)fflush(stdout);
    return;
}

static int load_thread_create_pb(struct bpf_prog_s* prog, int fd)
{
    struct perf_buffer *pb;

    if (prog->pb == NULL) {
        pb = create_pref_buffer(fd, output_thread_metrics);
        if (pb == NULL) {
            fprintf(stderr, "ERROR: crate perf buffer failed\n");
            return -1;
        }
        INFO("Success to create thread pb buffer.\n");
        prog->pb = pb;
    }
    return 0;
}

static int load_thread_cpu_prog(struct bpf_prog_s *prog, char is_load)
{
    int ret = 0;

    __LOAD_PROBE(cpu, err, is_load);
    if (is_load) {
        prog->skels[prog->num].skel = cpu_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)cpu_bpf__destroy;
        prog->num++;

        ret = load_thread_create_pb(prog, GET_MAP_FD(cpu, g_thread_output));
    }

    return ret;
err:
    UNLOAD(cpu);
    return -1;
}

static int load_thread_prog(struct bpf_prog_s *prog, char is_load)
{
    int ret = 0;

    __LOAD_PROBE(thread, err, is_load);
    if (is_load) {
        prog->skels[prog->num].skel = thread_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)thread_bpf__destroy;
        prog->num++;
    }

    return ret;
err:
    UNLOAD(thread);
    return -1;
}

struct bpf_prog_s* load_thread_bpf_prog(struct probe_params *args)
{
    struct bpf_prog_s *prog;
    char is_load_cpu;

    g_args = args;
    prog = alloc_bpf_prog();
    if (prog == NULL) {
        return NULL;
    }

    is_load_cpu = is_load_probe(args, TASK_PROBE_THREAD_CPU);

    if (load_thread_cpu_prog(prog, is_load_cpu)) {
        goto err;
    }

    if (load_thread_prog(prog, is_load_cpu)) {
        goto err;
    }

    return prog;

err:
    unload_bpf_prog(&prog);
    g_args = NULL;
    return NULL;
}

