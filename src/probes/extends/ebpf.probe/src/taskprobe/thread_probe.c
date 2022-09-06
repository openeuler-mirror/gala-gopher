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
#include "thread_io.skel.h"
#include "cpu.skel.h"
#include "bpf_prog.h"

#ifdef OO_NAME
#undef OO_NAME
#endif
#define OO_NAME  "thread"
#define THREAD_TBL_IO       "thread_io"
#define THREAD_TBL_CPU      "thread_cpu"

static struct probe_params *g_args;

#define US(ms)  ((u64)(ms) * 1000)

#define __LOAD_PROBE(probe_name, end, load) \
    OPEN(probe_name, end, load); \
    MAP_SET_PIN_PATH(probe_name, g_task_output, TASK_OUTPUT_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, period_map, PERIOD_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, g_task_map, TASK_PATH, load); \
    LOAD_ATTACH(probe_name, end, load)

static void report_task_metrics(struct task_data *data)
{
    char entityId[INT_LEN];
    u64 latency_thr_us = US(g_args->latency_thr);

    if (g_args->logs == 0) {
        return;
    }

    entityId[0] = 0;
    (void)snprintf(entityId, INT_LEN, "%d", data->id.pid);

    if (data->cpu.off_cpu_ns > 0) {
        report_logs(OO_NAME,
                    entityId,
                    "off_cpu_ns",
                    EVT_SEC_WARN,
                    "Process(COMM:%s TID:%d) is preempted(COMM:%s PID:%d) and off-CPU %llu ns.",
                    data->id.comm,
                    data->id.pid,
                    data->cpu.preempt_comm,
                    data->cpu.preempt_id,
                    data->cpu.off_cpu_ns);
    }

    if (data->io.iowait_us > latency_thr_us) {
        report_logs(OO_NAME,
                    entityId,
                    "iowait_us",
                    EVT_SEC_WARN,
                    "Process(COMM:%s TID:%d) iowait %llu us.",
                    data->id.comm,
                    data->id.pid,
                    data->io.iowait_us);
    }

    if (data->io.hang_count > 0) {
        report_logs(OO_NAME,
                    entityId,
                    "hang_count",
                    EVT_SEC_WARN,
                    "Process(COMM:%s TID:%d) io hang %u.",
                    data->id.comm,
                    data->id.pid,
                    data->io.hang_count);
    }

    if (data->io.bio_err_count > 0) {
        report_logs(OO_NAME,
                    entityId,
                    "bio_err_count",
                    EVT_SEC_WARN,
                    "Process(COMM:%s TID:%d) bio error %u.",
                    data->id.comm,
                    data->id.pid,
                    data->io.bio_err_count);
    }
}

static void output_task_metrics_io(struct task_data *task_data)
{
    (void)fprintf(stdout,
        "|%s|%d|%d|%s|"
        "%llu|%llu|%llu|%u|%u|\n",
        THREAD_TBL_IO,
        task_data->id.pid,
        task_data->id.tgid,
        task_data->id.comm,

        task_data->io.bio_bytes_read,
        task_data->io.bio_bytes_write,
        task_data->io.iowait_us,
        task_data->io.hang_count,
        task_data->io.bio_err_count);
    return;
}

static void output_task_metrics_cpu(struct task_data *task_data)
{
    (void)fprintf(stdout,
        "|%s|%d|%d|%s|"
        "%llu|%u|\n",
        THREAD_TBL_CPU,
        task_data->id.pid,
        task_data->id.tgid,
        task_data->id.comm,

        task_data->cpu.off_cpu_ns,
        task_data->cpu.migration_count);
    return;
}

static void output_task_metrics(void *ctx, int cpu, void *data, __u32 size)
{
    struct task_data *task_data = (struct task_data *)data;
    u32 flags = task_data->flags;

    report_task_metrics(task_data);

    if (flags & TASK_PROBE_THREAD_IO) {
        output_task_metrics_io(task_data);
    } else if (flags & TASK_PROBE_THREAD_CPU) {
        output_task_metrics_cpu(task_data);
    }
    (void)fflush(stdout);
    return;
}

static int load_task_create_pb(struct bpf_prog_s* prog, int fd)
{
    struct perf_buffer *pb;

    if (prog->pb == NULL) {
        pb = create_pref_buffer(fd, output_task_metrics);
        if (pb == NULL) {
            fprintf(stderr, "ERROR: crate perf buffer failed\n");
            return -1;
        }
        INFO("Success to create thread pb buffer.\n");
        prog->pb = pb;
    }
    return 0;
}

static int load_task_io_prog(struct bpf_prog_s *prog, char is_load)
{
    int ret = 0;

    __LOAD_PROBE(thread_io, err, is_load);
    if (is_load) {
        prog->skels[prog->num].skel = thread_io_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)thread_io_bpf__destroy;
        prog->num++;

        ret = load_task_create_pb(prog, GET_MAP_FD(thread_io, g_task_output));
    }

    return ret;
err:
    UNLOAD(thread_io);
    return -1;
}

static int load_task_cpu_prog(struct bpf_prog_s *prog, char is_load)
{
    int ret = 0;

    __LOAD_PROBE(cpu, err, is_load);
    if (is_load) {
        prog->skels[prog->num].skel = cpu_skel;
        prog->skels[prog->num].fn = (skel_destroy_fn)cpu_bpf__destroy;
        prog->num++;

        ret = load_task_create_pb(prog, GET_MAP_FD(cpu, g_task_output));
    }

    return ret;
err:
    UNLOAD(cpu);
    return -1;
}

struct bpf_prog_s* load_task_bpf_prog(struct probe_params *args)
{
    struct bpf_prog_s *prog;
    char is_load_io, is_load_cpu;

    g_args = args;
    prog = alloc_bpf_prog();
    if (prog == NULL) {
        return NULL;
    }

    is_load_io = is_load_probe(args, TASK_PROBE_THREAD_IO);
    is_load_cpu = is_load_probe(args, TASK_PROBE_THREAD_CPU);

    if (load_task_io_prog(prog, is_load_io)) {
        goto err;
    }

    if (load_task_cpu_prog(prog, is_load_cpu)) {
        goto err;
    }

    return prog;

err:
    unload_bpf_prog(&prog);
    g_args = NULL;
    return NULL;
}

