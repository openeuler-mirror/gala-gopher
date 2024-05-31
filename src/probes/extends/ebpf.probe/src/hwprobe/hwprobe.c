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
 * Author: lizhenxing
 * Create: 2023-05-18
 * Description: hw probe
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
#include "ipc.h"
#include "nic.skel.h"
#include "mem.skel.h"
#include "hw.h"
#include "event.h"

#define OO_NAME "hw"  // Observation Object name
#define TBL_NIC_FAILURE "nic_failure"
#define TBL_MC_EVENT "mem_mc_event"

#define HW_ARGS_PATH             "/sys/fs/bpf/gala-gopher/__hw_args"
#define MC_EVENT_CHANNEL_PTAH    "/sys/fs/bpf/gala-gopher/__hw_mc_event_channel_map"
#define NIC_FAUILURE_CHANNEL_PTAH "/sys/fs/bpf/gala-gopher/__hw_nic_failure_channel_map"
#define RM_NIC_PATH              "/usr/bin/rm -rf /sys/fs/bpf/gala-gopher/__hw*"

#define __OPEN_NIC_PROBE(probe_name, end, load, buffer) \
    INIT_OPEN_OPTS(probe_name); \
    PREPARE_CUSTOM_BTF(probe_name); \
    OPEN_OPTS(probe_name, end, load); \
    MAP_INIT_BPF_BUFFER(probe_name, nic_failure_channel_map, buffer, load); \
    MAP_SET_PIN_PATH(probe_name, hw_args_map, HW_ARGS_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, nic_failure_channel_map, NIC_FAUILURE_CHANNEL_PTAH, load);

#define __OPEN_MEM_PROBE(probe_name, end, load, buffer) \
    INIT_OPEN_OPTS(probe_name); \
    PREPARE_CUSTOM_BTF(probe_name); \
    OPEN_OPTS(probe_name, end, load); \
    MAP_INIT_BPF_BUFFER(probe_name, mc_event_channel_map, buffer, load); \
    MAP_SET_PIN_PATH(probe_name, hw_args_map, HW_ARGS_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, mc_event_channel_map, MC_EVENT_CHANNEL_PTAH, load);

static volatile sig_atomic_t g_stop = 0;
static int hw_args_fd = -1;
static struct ipc_body_s g_ipc_body;
static struct bpf_prog_s *g_bpf_prog = NULL;

static void sig_int(int signo)
{
    g_stop = 1;
}

enum hw_event_mc_err_type {
    HW_EVENT_ERR_CORRECTED,
    HW_EVENT_ERR_UNCORRECTED,
    HW_EVENT_ERR_DEFERRED,
    HW_EVENT_ERR_FATAL,
    HW_EVENT_ERR_INFO,
};

static const char* mc_event_error_type(unsigned int err_type)
{
    switch (err_type) {
    case HW_EVENT_ERR_CORRECTED:
        return "Corrected";
    case HW_EVENT_ERR_UNCORRECTED:
        return "Uncorrected";
    case HW_EVENT_ERR_DEFERRED:
        return "Deferred";
    case HW_EVENT_ERR_FATAL:
        return "Fatal";
    case HW_EVENT_ERR_INFO:
        return "Info";
    default:
        return "Info";
    }
}

#ifdef ENABLE_REPORT_EVENT
#define __ENTITY_ID_LEN 32
static void __build_entity_id(char *dev, char *deriver, char *buf, int buf_len)
{
    (void)snprintf(buf, buf_len, "%s_%s", dev, deriver);
}

static int rcv_nic_failure(void *ctx, void *data, __u32 size)
{
    struct nic_failure_s *nic_failure = data;
    char entityId[__ENTITY_ID_LEN];
    struct event_info_s evt = {0};

    (void)fprintf(stdout, "|%s|%s|%s|%s|%d|%d|%d|%d|\n",
        TBL_NIC_FAILURE,
        "nic",
        nic_failure->entity.dev_name,
        nic_failure->entity.driver,
        nic_failure->entity.queue_index,
        nic_failure->xmit_timeout_count,
        nic_failure->carrier_up_count,
        nic_failure->carrier_down_count);
    (void)fflush(stdout);

    if (nic_failure->xmit_timeout_count > 0) {
        entityId[0] = 0;
        __build_entity_id(nic_failure->entity.dev_name, nic_failure->entity.driver, entityId, __ENTITY_ID_LEN);

        evt.entityName = OO_NAME;
        evt.entityId = entityId;
        evt.metrics = "nic_xmit_timeout";
        evt.dev = nic_failure->entity.dev_name;

        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "HW nic nic_xmit_timeout (dev: %s (%s), queue_index: %d)",
                    nic_failure->entity.dev_name, nic_failure->entity.driver, nic_failure->entity.queue_index);

        (void)fflush(stdout);
    }

    return 0;
}
#else
static int rcv_nic_failure(void *ctx, void *data, __u32 size)
{
    return 0;
}

#endif

static int rcv_mem_mc_event(void *ctx, void *data, __u32 size)
{
    struct mc_event_s *mc_event = data;

    (void)fprintf(stdout, "|%s|%s|%s|%s|%d|%d|%d|%d|\n",
        TBL_MC_EVENT,
        "mem",
        mc_event_error_type(mc_event->entity.err_type),
        mc_event->entity.label,
        mc_event->entity.mc_index,
        mc_event->entity.top_layer,
        mc_event->entity.mid_layer,
        mc_event->error_count);

    (void)fflush(stdout);
    return 0;
}

static int load_nic_probe(struct bpf_prog_s *prog, char nic_prob)
{
    int ret;
    struct bpf_buffer *buffer = NULL;

    if (nic_prob == 0) {
        return 0;
    }

    __OPEN_NIC_PROBE(nic, err, 1, buffer);

    int kern_ver = probe_kernel_version();
    PROG_ENABLE_ONLY_IF(nic, bpf_raw_trace_net_dev_xmit_timeout, kern_ver >= KERNEL_VERSION(5, 2, 0));

    LOAD_ATTACH(hwprobe, nic, err, 1);

    ret = bpf_buffer__open(buffer, rcv_nic_failure, NULL, NULL);
    if (ret) {
        ERROR("[HWPROBE] Open 'nic_failure_channel_map' bpf_buffer failed.\n");
        goto err;
    }
    prog->buffers[prog->num] = buffer;

    if (hw_args_fd < 0) {
        hw_args_fd = GET_MAP_FD(nic, hw_args_map);
    }
    prog->skels[prog->num].skel = nic_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)nic_bpf__destroy;
    prog->custom_btf_paths[prog->num] = nic_open_opts.btf_custom_path;
    prog->num++;

    return 0;

err:
    bpf_buffer__free(buffer);
    UNLOAD(nic);
    CLEANUP_CUSTOM_BTF(nic);
    return -1;
}

static int load_mem_probe(struct bpf_prog_s *prog, char mem_probe)
{
    int ret;
    struct bpf_buffer *buffer = NULL;

    if (mem_probe == 0) {
        return 0;
    }

    __OPEN_MEM_PROBE(mem, err, 1, buffer);

    int kern_ver = probe_kernel_version();
    int attach_tp = kern_ver > KERNEL_VERSION(4, 18, 0);
    PROG_ENABLE_ONLY_IF(mem, bpf_raw_trace_mc_event, attach_tp);
    PROG_ENABLE_ONLY_IF(mem, bpf_trace_mc_event_func, !attach_tp);

    LOAD_ATTACH(hwprobe, mem, err, 1);

    ret = bpf_buffer__open(buffer, rcv_mem_mc_event, NULL, NULL);
    if (ret) {
        ERROR("[HWPROBE] Open 'mc_event_channel_map' bpf_buffer failed.\n");
        goto err;
    }
    prog->buffers[prog->num] = buffer;

    if (hw_args_fd < 0) {
        hw_args_fd = GET_MAP_FD(mem, hw_args_map);
    }

    prog->skels[prog->num].skel = mem_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)mem_bpf__destroy;
    prog->custom_btf_paths[prog->num] = mem_open_opts.btf_custom_path;
    prog->num++;

    return 0;

err:
    bpf_buffer__free(buffer);
    UNLOAD(mem);
    CLEANUP_CUSTOM_BTF(mem);
    return -1;
}

static void hwprobe_unload_bpf(void)
{
    unload_bpf_prog(&g_bpf_prog);
    hw_args_fd = -1;
}

static int load_hw_args(struct ipc_body_s* ipc_body)
{
    if (hw_args_fd < 0) {
        return 0;
    }

    u32 key = 0;
    struct hw_args_s hw_args = {0};
    hw_args.report_period = NS(ipc_body->probe_param.period);

    return bpf_map_update_elem(hw_args_fd, &key, &hw_args, BPF_ANY);
}

static int hwprobe_load_bpf(struct ipc_body_s *ipc_body)
{
    int ret;
    struct bpf_prog_s *prog;
    char is_load_nic, is_load_mem;

    is_load_nic = IS_LOAD_PROBE(ipc_body->probe_range_flags, PROBE_RANGE_HW_NIC);
    is_load_mem = IS_LOAD_PROBE(ipc_body->probe_range_flags, PROBE_RANGE_HW_MEM);

    g_bpf_prog = alloc_bpf_prog();
    if (g_bpf_prog == NULL) {
        return -1;
    }
    prog = g_bpf_prog;

    ret = load_nic_probe(prog, is_load_nic);
    if (ret != 0) {
        ERROR("[IOPROBE] load nic probe failed.\n");
        goto err;
    }

    ret = load_mem_probe(prog, is_load_mem);
    if (ret != 0) {
        ERROR("[IOPROBE] load mem probe failed.\n");
        goto err;
    }

    ret = load_hw_args(ipc_body);
    if (ret != 0) {
        ERROR("[IOPROBE] load nic args failed.\n");
        goto err;
    }

    return 0;

err:
    hwprobe_unload_bpf();
    return ret;
}

int main(int argc, char **argv)
{
    int ret = 0;
    FILE *fp = NULL;
    struct ipc_body_s ipc_body;

    fp = popen(RM_NIC_PATH, "r");
    if (fp != NULL) {
        (void)pclose(fp);
        fp = NULL;
    }

    (void)memset(&g_ipc_body, 0, sizeof(g_ipc_body));

    int msq_id = create_ipc_msg_queue(IPC_EXCL);
    if (msq_id < 0) {
        ERROR("[HWPROBE] Get ipc msg queue failed.\n");
        goto err;
    }

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        ERROR("[HWPROBE] Can't set signal handler: %s\n", strerror(errno));
        goto err;
    }

    INIT_BPF_APP(hwprobe, EBPF_RLIM_LIMITED);

    while (!g_stop) {
        ret = recv_ipc_msg(msq_id, (long)PROBE_HW, &ipc_body);
        if (ret == 0) {
            hwprobe_unload_bpf();
            hwprobe_load_bpf(&ipc_body);

            destroy_ipc_body(&g_ipc_body);
            (void)memcpy(&g_ipc_body, &ipc_body, sizeof(g_ipc_body));
        }

        if (g_bpf_prog == NULL) {
            sleep(1);
            continue;
        }

        for (int i = 0; i < g_bpf_prog->num; i++) {
            if (g_bpf_prog->buffers[i]
                && ((ret = bpf_buffer__poll(g_bpf_prog->buffers[i], THOUSAND)) < 0)
                && ret != -EINTR) {
                ERROR("[HWPROBE]: perf poll prog_%d failed.\n", i);
                break;
            }
        }
    }

err:
    hwprobe_unload_bpf();
    destroy_ipc_body(&g_ipc_body);

    return ret;
}