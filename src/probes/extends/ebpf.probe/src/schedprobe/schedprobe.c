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
 * Author: luzhihao
 * Create: 2022-11-07
 * Description: sched probe
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
#include "bpf_prog.h"
#include "sched.h"
#include "kern_symb.h"
#include "event.h"

static struct sched_probe_s probe;
static volatile sig_atomic_t stop = 0;

#define OO_NAME         "proc"

#define IS_IEG_ADDR(addr)     ((addr) != 0xcccccccccccccccc && (addr) != 0xffffffffffffffff)

static int stack_id2symbs(u32 fd, u32 stack_id, struct addr_symb_s kern_stack_symbs[], size_t size)
{
    int index = 0;
    u64 ip[PERF_MAX_STACK_DEPTH] = {0};

    if (bpf_map_lookup_elem(fd, &stack_id, ip) != 0) {
        return -1;
    }

    for (int i = PERF_MAX_STACK_DEPTH - 1; (i >= 0 && index < size); i--) {
        if (ip[i] != 0 && IS_IEG_ADDR(ip[i])) {
            (void)search_kern_addr_symb(probe.ksymbs, ip[i], &(kern_stack_symbs[index]));
            index++;
        }
    }
    return 0;
}

static void build_stack_trace(u32 fd, u32 stack_id, char *stack_trace, size_t trace_len)
{
    int ret;
    int len = trace_len;
    char *pos = stack_trace;
    struct addr_symb_s kern_stack_symbs[PERF_MAX_STACK_DEPTH];
    const char *fmt = "<0x%llx> %s\n";
    (void)memset(kern_stack_symbs, 0, sizeof(struct addr_symb_s) * PERF_MAX_STACK_DEPTH);

    (void)stack_id2symbs(fd, stack_id, kern_stack_symbs, PERF_MAX_STACK_DEPTH);

    for (int i = PERF_MAX_STACK_DEPTH - 1; i >= 0; i--) {
        if (kern_stack_symbs[i].orign_addr != 0) {
            ret = __snprintf(&pos, (const int)len, &len,\
                fmt, kern_stack_symbs[i].orign_addr, kern_stack_symbs[i].sym);
            if (ret < 0) {
                break;
            }
        }
    }
}

static int build_systime_lat_msg(struct event *sched_evt, char msg[], size_t msg_len)
{
    int ret;
    int len = msg_len;
    char *pos = msg;
    enum sched_evt_t state;
    const char *state_str[SCHED_LAT_MAX] = {"enter", "hold", "exit"};
    const char *fmt = "CPU %s sys-state.(CPU = %d, Comm = %s, PID = %u, Latency = %llums)\n";

    if (sched_evt->body.systime.start != 0) {
        state = SCHED_LAT_START;
    } else if (sched_evt->body.systime.end != 0) {
        state = SCHED_LAT_END;
    } else {
        state = SCHED_LAT_CONT;
    }

    u64 delay = sched_evt->body.systime.delay >> 6;  // ns -> ms

    ret = __snprintf(&pos, (const int)len, &len, fmt, state_str[state],\
        sched_evt->cpu, sched_evt->comm, sched_evt->proc_id, delay);
    if (ret < 0) {
        return ret;
    }

    build_stack_trace(probe.sched_systime_stackmap_fd, sched_evt->stack_id, pos, len);
    return 0;
}

static int build_syscall_lat_msg(struct event *syscall_evt, char msg[], size_t msg_len)
{
    int ret;
    int len = msg_len;
    char *pos = msg;
    u64 latency, delay;
    int evt_type;
    const char *evt[2] = {"sleep", "wait"};

    const char *fmt = "COMM: %s syscall %s.(CPU = %d, PID = %u, SYSID = %u, Latency = %llums, Delay = %llums)\n";

    delay = syscall_evt->body.syscall.exit - syscall_evt->body.syscall.enter;
    delay = delay >> 6;  // ns -> ms

    evt_type = (syscall_evt->body.syscall.sleep != 0) ? 0 : 1;
    latency = (syscall_evt->body.syscall.sleep != 0) ? syscall_evt->body.syscall.sleep : syscall_evt->body.syscall.wait;

    ret = __snprintf(&pos, (const int)len, &len, fmt, syscall_evt->comm, evt[evt_type],\
        syscall_evt->cpu, syscall_evt->proc_id, syscall_evt->body.syscall.sysid, latency, delay);
    if (ret < 0) {
        return ret;
    }

    build_stack_trace(probe.sched_syscall_stackmap_fd, syscall_evt->stack_id, pos, len);
    return 0;
}


#define __ENTITY_ID_LEN     32
#define __ENTITY_MSG_LEN    (512)
static void __build_entity_id(int procid, char *buf, int buf_len)
{
    (void)snprintf(buf, buf_len, "%d", procid);
}

static void report_sched_logs(struct event *sched_evt)
{
    char msg[__ENTITY_MSG_LEN];
    char entityId[__ENTITY_ID_LEN];
    char *metrics[EVT_MAX] = {"sched_systime", "sched_syscall"};
    struct event_info_s evt = {0};

    if (probe.ipc_body.probe_param.logs == 0) {
        return;
    }

    msg[0] = 0;
    switch (sched_evt->e) {
        case EVT_SYSTIME:
        {
            if (build_systime_lat_msg(sched_evt, msg, __ENTITY_MSG_LEN) < 0) {
                return;
            }
            break;
        }
        case EVT_SYSCALL:
        {
            if (build_syscall_lat_msg(sched_evt, msg, __ENTITY_MSG_LEN) < 0) {
                return;
            }
            break;
        }
        default :
        {
            return;
        }
    }

    entityId[0] = 0;
    __build_entity_id(sched_evt->proc_id, entityId, __ENTITY_ID_LEN);

    evt.entityName = OO_NAME;
    evt.entityId = entityId;
    evt.metrics = metrics[sched_evt->e];
    evt.pid = (int)sched_evt->proc_id;

    report_logs((const struct event_info_s *)&evt,
                EVT_SEC_WARN,
                msg);
    return;
}

static void report_sched_metrics(struct event *sched_evt)
{
    u64 metrcis;
    char *tbl[EVT_MAX] = {"sched_systime", "sched_syscall"};

    switch (sched_evt->e) {
        case EVT_SYSTIME:
        {
            metrcis = sched_evt->body.systime.delay >> 6;  // ns -> ms
            break;
        }
        case EVT_SYSCALL:
        {
            metrcis = sched_evt->body.syscall.exit - sched_evt->body.syscall.enter;
            metrcis = metrcis >> 6;  // ns -> ms
            break;
        }
        default :
        {
            return;
        }
    }

    (void)fprintf(stdout, "|%s|%u"
        "|%llu|\n",
        tbl[sched_evt->e],
        sched_evt->proc_id,

        metrcis);
    (void)fflush(stdout);
}

void rcv_sched_report(void *ctx, int cpu, void *data, __u32 size)
{
    struct event *evt = data;

    report_sched_logs(evt);
    report_sched_metrics(evt);
}

static int is_target_wl(struct ipc_body_s *ipc_body)
{
    int i;

    for (i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        if (ipc_body->snooper_objs[i].type == SNOOPER_OBJ_PROC) {
            return 1;
        }
    }

    return 0;
}

static void load_sched_args(int fd, struct ipc_body_s *ipc_body)
{
    u32 key = 0;
    struct sched_args_s sched_args = {0};
    struct probe_params *args = &ipc_body->probe_param;

    if (args->latency_thr != 0) {
        sched_args.latency_thr = (u64)((u64)args->latency_thr * 1000 * 1000);
    }

    if (is_target_wl(ipc_body)) {
        sched_args.is_target_wl = 1;
    }

    (void)bpf_map_update_elem(fd, &key, &sched_args, BPF_ANY);
}

static int __init_probe(struct sched_probe_s *probep)
{
    (void)memset(probep, 0, sizeof(struct sched_probe_s));

    probep->ksymbs = create_ksymbs_tbl();
    if (probep->ksymbs == NULL) {
        return -1;
    }

    if (load_kern_syms(probep->ksymbs)) {
        return -1;
    }

    (void)sort_kern_syms(probep->ksymbs);
    return 0;
}

static void __deinit_probe(struct sched_probe_s *probep)
{
    if (probep->ksymbs) {
        destroy_ksymbs_tbl(probep->ksymbs);
        (void)free(probep->ksymbs);
        probep->ksymbs = NULL;
    }
    return;
}

static void sig_handling(int signal)
{
    stop = 1;
}

static void refresh_proc_filter_map(struct ipc_body_s *ipc_body)
{
    struct proc_s key = {0};
    struct proc_s next_key = {0};
    struct obj_ref_s val = {.count = 0};
    int fd;
    int i;

    fd = bpf_obj_get(GET_PROC_MAP_PIN_PATH(schedprobe));
    if (fd < 0) {
        fprintf(stderr, "WARN: Failed to get proc map fd\n");
        return;
    }

    while (bpf_map_get_next_key(fd, &key, &next_key) != -1) {
        (void)bpf_map_delete_elem(fd, &next_key);
        key = next_key;
    }

    for (i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        if (ipc_body->snooper_objs[i].type != SNOOPER_OBJ_PROC) {
            continue;
        }

        key.proc_id = ipc_body->snooper_objs[i].obj.proc.proc_id;
        (void)bpf_map_update_elem(fd, &key, &val, BPF_ANY);
    }
}

static int reload_sched_probe(struct ipc_body_s *ipc_body)
{
    int ret;

    if (ipc_body->probe_range_flags != probe.ipc_body.probe_range_flags) {
        unload_bpf_prog(&probe.sched_prog);
        ret = load_sched_bpf_prog(ipc_body, &probe);
        if (ret) {
            return -1;
        }
    }

    load_sched_args(probe.sched_args_fd, ipc_body);
    refresh_proc_filter_map(ipc_body);

    return 0;
}

int main(int argc, char **argv)
{
    int ret = 0;
    struct ipc_body_s ipc_body;
    int msq_id;

    if (signal(SIGINT, sig_handling) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        return -1;
    }

    msq_id = create_ipc_msg_queue(IPC_EXCL);
    if (msq_id < 0) {
        return -1;
    }

    ret = __init_probe(&probe);
    if (ret != 0) {
        __deinit_probe(&probe);
        return -1;
    }

    clean_map_files();

    INIT_BPF_APP(schedprobe, EBPF_RLIM_LIMITED);

    INFO("Successfully started!\n");

    while (!stop) {
        ret = recv_ipc_msg(msq_id, (long)PROBE_SCHED, &ipc_body);
        if (ret == 0) {
            if (reload_sched_probe(&ipc_body)) {
                goto err;
            }

            destroy_ipc_body(&probe.ipc_body);
            (void)memcpy(&probe.ipc_body, &ipc_body, sizeof(struct ipc_body_s));
        }

        if (probe.sched_prog == NULL) {
            sleep(DEFAULT_PERIOD);
            continue;
        }

        if (probe.sched_prog->pb != NULL) {
            if (perf_buffer__poll(probe.sched_prog->pb, THOUSAND) < 0) {
                goto err;
            }
        }
    }

    return 0;
err:
    unload_bpf_prog(&probe.sched_prog);
    destroy_ipc_body(&probe.ipc_body);
    __deinit_probe(&probe);
    return -1;
}

