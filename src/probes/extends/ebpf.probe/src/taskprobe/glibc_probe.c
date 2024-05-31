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
#include "glibc.skel.h"
#include "glibc_bpf.h"
#include "bpf_prog.h"

#define __LOAD_PROBE(probe_name, end, load, buffer) \
    INIT_OPEN_OPTS(probe_name); \
    PREPARE_CUSTOM_BTF(probe_name); \
    OPEN_OPTS(probe_name, end, load); \
    MAP_INIT_BPF_BUFFER(probe_name, dns_output, buffer, load); \
    MAP_SET_PIN_PATH(probe_name, args_map, ARGS_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, g_proc_map, PROC_PATH, load); \
    LOAD_ATTACH(taskprobe, probe_name, end, load)

#define PROC_DNS_TBL  "proc_dns"
#define OO_NAME "dns"

static struct dns_entry_s * create_dns_entry(struct task_probe_s *task_probe, const struct dns_cache_s* cache)
{
    struct dns_entry_s* entry = (struct dns_entry_s *)malloc(sizeof(struct dns_entry_s));
    if (entry == NULL) {
        return NULL;
    }

    memset(entry, 0, sizeof(struct dns_entry_s));
    entry->id.proc_id = cache->proc_id;
    memcpy(entry->id.domain, cache->domain, DOMAIN_LEN);

    H_ADD_KEYPTR(task_probe->dns_entrys, &entry->id, sizeof(struct dns_id_s), entry);
    return entry;
}

static struct dns_entry_s * lkup_dns_entry(struct task_probe_s *task_probe, const struct dns_cache_s* cache)
{
    struct dns_entry_s* entry = NULL;
    struct dns_id_s id;

    id.proc_id = cache->proc_id;
    memcpy(id.domain, cache->domain, DOMAIN_LEN);

    H_FIND(task_probe->dns_entrys, &id, sizeof(struct dns_id_s), entry);
    return entry;
}

static int add_dns_entry(struct task_probe_s *task_probe, const struct dns_cache_s* cache)
{
    u64 delay;
    struct dns_entry_s* entry = lkup_dns_entry(task_probe, cache);
    if (entry == NULL) {
        entry = create_dns_entry(task_probe, cache);
    }

    if (entry == NULL) {
        ERROR("[TASKPROBE] Failed to create dns entry.\n");
        return -1;
    }

    entry->last_rcv_data = (time_t)time(NULL);

    entry->dns_op_count++;
    entry->err_count += (cache->error == 0) ? 0 : 1;
    if ((cache->end_ts > cache->start_ts) && (cache->error == 0)) {
        delay = cache->end_ts - cache->start_ts;
        entry->latency_sum += delay;
        entry->latency_max = max(entry->latency_max, delay);
    }
    return 0;
}

static char is_entry_inactive(struct dns_entry_s* entry)
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

static char is_entry_tmout(struct task_probe_s *task_probe, struct dns_entry_s* entry)
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

int rcv_dns_cache(void *ctx, void *data, u32 size)
{
    struct task_probe_s *task_probe = (struct task_probe_s *)ctx;
    return add_dns_entry(task_probe, (const struct dns_cache_s *)data);
}

static void reset_dns_entry(struct dns_entry_s *entry)
{
    entry->dns_op_count = 0;
    entry->err_count = 0;
    entry->latency_max = 0;
    entry->latency_sum = 0;
    entry->err_ratio = 0.0;
}

static void report_dns_event(struct task_probe_s *task_probe, struct dns_entry_s *entry)
{
#ifdef ENABLE_REPORT_EVENT
#define __ENTITY_ID_LEN 128

    char entityId[__ENTITY_ID_LEN];
    struct event_info_s evt = {0};

    if (entry->err_ratio == 0.0) {
        return;
    }

    if (task_probe->ipc_body.probe_param.logs == 0) {
        return;
    }

    entityId[0] = 0;
    (void)snprintf(entityId, __ENTITY_ID_LEN, "%u_%s", entry->id.proc_id, entry->id.domain);

    evt.entityName = OO_NAME;
    evt.entityId = entityId;
    evt.pid = (int)entry->id.proc_id;
    evt.metrics = "error_ratio";

    report_logs((const struct event_info_s *)&evt,
                EVT_SEC_WARN,
                "Process(PID:%u) DNS error ratio(%.3f %).",
                entry->id.proc_id,
                entry->err_ratio);
#endif
    return;
}

static void output_dns_entry(struct dns_entry_s *entry)
{
    u64 succeed_op_count = 0;
    u64 latency_avg = 0;
    float err_ratio = 0.0;

    if (entry->dns_op_count > entry->err_count) {
        succeed_op_count = entry->dns_op_count - entry->err_count;
        latency_avg = entry->latency_sum / succeed_op_count;
        latency_avg = latency_avg >> 6;
    }

    if (entry->err_count != 0 && entry->dns_op_count != 0) {
        err_ratio = (float)((float)entry->err_count / (float)entry->dns_op_count);
        entry->err_ratio = err_ratio * 100; // Percentage
    }

    (void)fprintf(stdout,
        "|%s|%u|%s|"
        "%llu|%llu|%.3f|%llu|%llu|\n",
        PROC_DNS_TBL,
        entry->id.proc_id,
        entry->id.domain,

        latency_avg,
        entry->latency_max >> 6,
        entry->err_ratio,
        entry->dns_op_count,
        entry->err_count);
    return;
}

void scan_dns_entrys(struct task_probe_s *task_probe)
{
    struct dns_entry_s *entry, *tmp;

    H_ITER(task_probe->dns_entrys, entry, tmp) {
        if (is_entry_tmout(task_probe, entry)) {
            output_dns_entry(entry);
            report_dns_event(task_probe, entry);
            reset_dns_entry(entry);
        }

        if (is_entry_inactive(entry)) {
            H_DEL(task_probe->dns_entrys, entry);
            free(entry);
        }
    }
}

void destroy_dns_entrys(struct task_probe_s *task_probe)
{
    struct dns_entry_s *entry, *tmp;

    H_ITER(task_probe->dns_entrys, entry, tmp) {
        H_DEL(task_probe->dns_entrys, entry);
        free(entry);
    }
}

int load_glibc_bpf_prog(struct task_probe_s *task_probe, const char *glibc_path, struct bpf_prog_s **new_prog)
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

    __LOAD_PROBE(glibc, err, 1, buffer);
    prog->skels[prog->num].skel = glibc_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)glibc_bpf__destroy;
    prog->custom_btf_paths[prog->num] = glibc_open_opts.btf_custom_path;

    task_probe->args_fd = GET_MAP_FD(glibc, args_map);
    task_probe->proc_map_fd = GET_MAP_FD(glibc, g_proc_map);

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

    ret = bpf_buffer__open(buffer, rcv_dns_cache, NULL, task_probe);
    if (ret) {
        ERROR("[TASKPROBE] Open 'glibc' bpf_buffer failed.\n");
        goto err;
    }
    prog->buffer = buffer;

    prog->num++;

    *new_prog = prog;
    return 0;

err:
    bpf_buffer__free(buffer);
    UNLOAD(glibc);
    CLEANUP_CUSTOM_BTF(glibc);

    if (prog) {
        free_bpf_prog(prog);
    }
    return -1;
}

