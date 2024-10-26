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
 * Create: 2024-10-09
 * Description: Python GC probe
 ******************************************************************************/
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
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
#include "event.h"
#include "pygc.skel.h"
#include "pygc_bpf.h"
#include "bpf_prog.h"

#define __LOAD_PROBE(probe_name, end, load, buffer) \
    INIT_OPEN_OPTS(probe_name); \
    PREPARE_CUSTOM_BTF(probe_name); \
    OPEN_OPTS(probe_name, end, load); \
    MAP_INIT_BPF_BUFFER(probe_name, gc_output, buffer, load); \
    LOAD_ATTACH(taskprobe, probe_name, end, load)

#define PROC_TBL_PYGC           "proc_pygc"

static struct pygc_entry_s *create_pygc_entry(struct task_probe_s *task_probe, const struct pygc_evt_s *evt)
{
    struct pygc_entry_s* entry = (struct pygc_entry_s *)malloc(sizeof(struct pygc_entry_s));
    if (entry == NULL) {
        return NULL;
    }

    memset(entry, 0, sizeof(struct pygc_entry_s));
    entry->proc_id = (u32)(evt->id >> INT_LEN);

    H_ADD_I(task_probe->pygc_entrys, proc_id, entry);
    return entry;
}

static struct pygc_entry_s * lkup_pygc_entry(struct task_probe_s *task_probe, const struct pygc_evt_s *evt)
{
    struct pygc_entry_s* entry = NULL;
    u32 proc_id = (u32)(evt->id >> INT_LEN);

    H_FIND_I(task_probe->pygc_entrys, &proc_id, entry);
    return entry;
}

static int add_pygc_entry(struct task_probe_s *task_probe, const struct pygc_evt_s *evt)
{
    u64 delay;
    struct pygc_entry_s* entry = lkup_pygc_entry(task_probe, evt);
    if (entry == NULL) {
        entry = create_pygc_entry(task_probe, evt);
    }

    if (entry == NULL) {
        ERROR("[TASKPROBE] Failed to create python GC entry.\n");
        return -1;
    }

    entry->last_rcv_data = (time_t)time(NULL);

    entry->gc_count++;
    if (evt->end_time > evt->start_time) {
        delay = NS2MS(evt->end_time - evt->start_time);
        entry->latency_sum += delay;
        entry->latency_max = max(entry->latency_max, delay);
    }
    return 0;
}

static char is_need_report(struct task_probe_s *task_probe, struct pygc_entry_s* entry)
{
    time_t current = (time_t)time(NULL);
    time_t secs;

    if ((entry->last_report == (time_t)0) || (current < entry->last_report)) {
        entry->last_report = current;
        return 0;
    }

    if (current > entry->last_report) {
        secs = current - entry->last_report;
        if (secs >= task_probe->ipc_body.probe_param.period) {
            entry->last_report = current;
            return 1;
        }
    }

    return 0;
}

static void reset_pygc_entry(struct pygc_entry_s *entry)
{
    entry->gc_count = 0;
    entry->latency_max = 0;
    entry->latency_sum = 0;
}

static char is_entry_inactive(struct pygc_entry_s* entry)
{
#define __INACTIVE_TIME_SECS     (10 * 60)       // 10min
    time_t current = (time_t)time(NULL);
    time_t secs;

    if (current > entry->last_rcv_data) {
        secs = current - entry->last_rcv_data;
        if (secs >= __INACTIVE_TIME_SECS) {
            return 1;
        }
    }

    return 0;
}

static int output_pygc_metrics(struct pygc_entry_s* entry)
{
    (void)fprintf(stdout,
        "|%s|%u|"
        "%llu|%llu|%llu|\n",

        PROC_TBL_PYGC,
        entry->proc_id,

        entry->gc_count,
        entry->latency_sum,
        entry->latency_max);
    return 0;
}

void scan_pygc_entrys(struct task_probe_s *task_probe)
{
    struct pygc_entry_s *entry, *tmp;

    H_ITER(task_probe->pygc_entrys, entry, tmp) {
        if (is_need_report(task_probe, entry)) {
            output_pygc_metrics(entry);
            reset_pygc_entry(entry);
        }

        if (is_entry_inactive(entry)) {
            H_DEL(task_probe->pygc_entrys, entry);
            free(entry);
        }
    }
}

static int save_pygc_metrics(void *ctx, void *data, u32 size)
{
    struct task_probe_s *task_probe = (struct task_probe_s *)ctx;

    return add_pygc_entry(task_probe, (const struct pygc_evt_s *)data);
}

int load_pygc_prog(struct task_probe_s *task_probe, const char *elf, struct bpf_prog_s **new_prog)
{
    int ret, succeed;
    size_t link_num = 0;
    struct bpf_prog_s *prog;
    struct bpf_buffer *buffer = NULL;

    *new_prog = NULL;

    prog = alloc_bpf_prog();
    if (prog == NULL) {
        return -1;
    }

    __LOAD_PROBE(pygc, err, 1, buffer);
    prog->skels[prog->num].skel = pygc_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)pygc_bpf__destroy;
    prog->custom_btf_paths[prog->num] = pygc_open_opts.btf_custom_path;

    // Python GC bpf prog attach function 'collect_with_callback'
    UBPF_ATTACH(pygc, collect_with_callback, elf, collect_with_callback, succeed);
    if (!succeed) {
        goto err;
    }
    prog->skels[prog->num]._link[link_num++] = (void *)pygc_link[pygc_link_current - 1];

    UBPF_RET_ATTACH(pygc, collect_with_callback, elf, collect_with_callback, succeed);
    if (!succeed) {
        goto err;
    }
    prog->skels[prog->num]._link[link_num++] = (void *)pygc_link[pygc_link_current - 1];
    prog->skels[prog->num]._link_num = link_num;

    ret = bpf_buffer__open(buffer, save_pygc_metrics, NULL, task_probe);
    if (ret) {
        ERROR("[TASKPROBE] Open 'pygc' bpf_buffer failed.\n");
        goto err;
    }
    prog->buffer = buffer;

    prog->num++;

    *new_prog = prog;
    return 0;

err:
    bpf_buffer__free(buffer);
    UNLOAD(pygc);
    CLEANUP_CUSTOM_BTF(pygc);

    if (prog) {
        free_bpf_prog(prog);
    }
    return -1;
}

void destroy_pygc_entrys(struct task_probe_s *task_probe)
{
    struct pygc_entry_s *entry, *tmp;

    H_ITER(task_probe->pygc_entrys, entry, tmp) {
        H_DEL(task_probe->pygc_entrys, entry);
        free(entry);
    }
}


