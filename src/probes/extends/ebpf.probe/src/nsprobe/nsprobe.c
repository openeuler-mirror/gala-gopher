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
 * Create: 2022-06-6
 * Description: nsprobe user prog
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
#include "qdisc.skel.h"
#include "qdisc.h"
#include "containerd_probe.h"
#include "bps.h"
#include "tc_loader.h"
#include "nsprobe.h"

#define QDISC "qdisc"
#define QDISC_CPU "qdisc_cpu"
#define CONTAINER "container"

#define TC_BPS_PROG "bps.tcbpf.o"

#define OUTPUT_PATH "/sys/fs/bpf/gala-gopher/__nsprobe_output"
#define ARGS_PATH "/sys/fs/bpf/gala-gopher/__nsprobe_args"
#define RM_BPF_PATH "/usr/bin/rm -rf /sys/fs/bpf/gala-gopher/__nsprobe*"
#define RM_TC_MAP_PATH "/usr/bin/rm -rf /sys/fs/bpf/tc/globals/tc_bps_*"
#define TC_OUTPUT_MAP_PATH "/sys/fs/bpf/tc/globals/tc_bps_output"
#define TC_ARGS_MAP_PATH "/sys/fs/bpf/tc/globals/tc_bps_args"
#define CHECK_HELPER_CMD "/usr/bin/cat /proc/kallsyms | /usr/bin/grep bpf_skb_cgroup_classid"

#define __LOAD_NS_PROBE(probe_name, end, load) \
    OPEN(probe_name, end, load); \
    MAP_SET_PIN_PATH(probe_name, output, OUTPUT_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, args_map, ARGS_PATH, load); \
    LOAD_ATTACH(nsprobe, probe_name, end, load)

static struct probe_params_deprecated params = {.period = DEFAULT_PERIOD};
static volatile sig_atomic_t g_stop;
static struct container_hash_t *head = NULL;

static void sig_int(int signo)
{
    g_stop = 1;
}

static void output_qdisc_metrics(void *ctx, int cpu, void *data, __u32 size)
{
    struct qdisc *qdisc  = (struct qdisc *)data;

    (void)fprintf(stdout,
        "|%s|%u|%u|%s|%s|%u|%u|%u|%u|%u|%u|\n",
        QDISC,
        qdisc->handle,
        qdisc->ifindex,
        qdisc->dev_name,
        qdisc->kind,
        qdisc->netns_id,
        qdisc->egress.qlen,
        qdisc->egress.backlog,
        qdisc->egress.drops,
        qdisc->egress.requeues,
        qdisc->egress.overlimits);
    (void)fflush(stdout);
}

static void load_args(int args_fd, struct probe_params_deprecated* params)
{
    __u32 key = 0;
    struct ns_args_s args = {0};

    args.period = NS(params->period);

    (void)bpf_map_update_elem(args_fd, &key, &args, BPF_ANY);
}

static void rm_maps()
{
    FILE *fp = NULL;
    fp = popen(RM_BPF_PATH, "r");
    if (fp != NULL) {
        (void)pclose(fp);
        fp = NULL;
    }
    fp = popen(RM_TC_MAP_PATH, "r");
    if (fp != NULL) {
        (void)pclose(fp);
        fp = NULL;
    }
}

static bool is_kernel_support_tc_bps_load()
{
    int ret = system(CHECK_HELPER_CMD);
    if (ret < 0) {
        fprintf(stderr, "can't check kernel if support tc bps prog load: %d\n", ret);
        return false;
    }

    ret = WEXITSTATUS((unsigned)ret);
    if (ret) {
        INFO("kernel don't support tc bps prog loading\n");
        return false;
    }
    return true;
}

void store_bps(void *ctx, int cpu, void *data, u32 size)
{
    struct bps_msg_s *bps_msg = (struct bps_msg_s *)data;
    struct container_value* v;

    v = get_container_by_proc_id(&head, bps_msg->cg_classid);
    if (v == NULL) {
        return;
    }

    v->bps = bps_msg->bps;
}

void output_containers_metrics(struct container_hash_t **pphead)
{
    struct container_hash_t *item, *tmp;
    if (*pphead == NULL) {
        return;
    }

    H_ITER(*pphead, item, tmp) {
        (void)fprintf(stdout,
            "|%s|%s|%s|%u|%u|%u|%u|%u|%u|%llu|\n",
            CONTAINER,
            item->k.container_id,
            item->v.name,
            item->v.cpucg_inode,
            item->v.memcg_inode,
            item->v.pidcg_inode,
            item->v.mnt_ns_id,
            item->v.net_ns_id,
            item->v.proc_id,
            item->v.bps);
        (void)fflush(stdout);
    }
}

int main(int argc, char **argv)
{
    int err = -1;
    bool tc_load = false;
    struct perf_buffer* qdisc_pb = NULL;
    struct perf_buffer* tc_pb = NULL;

    rm_maps();

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %d\n", errno);
        return errno;
    }

    err = args_parse(argc, argv, &params);
    if (err != 0) {
        return -1;
    }

    INFO("arg parse interval time:%us\n", params.period);

    INIT_BPF_APP(nsprobe, EBPF_RLIM_LIMITED);
    __LOAD_NS_PROBE(qdisc, err, 1);

    load_args(GET_MAP_FD(qdisc, args_map), &params);
    qdisc_pb = create_pref_buffer(GET_MAP_FD(qdisc, output), output_qdisc_metrics);
    if (qdisc_pb == NULL) {
        fprintf(stderr, "ERROR: create perf buffer of ns metrics failed\n");
        goto err;
    }

    // load tc bpf and map
    tc_load = is_kernel_support_tc_bps_load();
    if (tc_load) {
        load_tc_bpf(params.netcard_list, TC_BPS_PROG, TC_TYPE_EGRESS);
        load_args(bpf_obj_get(TC_ARGS_MAP_PATH), &params);
        tc_pb = create_pref_buffer(bpf_obj_get(TC_OUTPUT_MAP_PATH), store_bps);
        if (tc_pb == NULL) {
            fprintf(stderr, "ERROR: create perf buffer of container metrics failed\n");
            goto err2;
        }
    }

    INFO("Successfully started!\n");
    obj_module_init();

    while (!g_stop) {
        get_containers(&head, &params);
        if ((err = perf_buffer__poll(qdisc_pb, THOUSAND)) < 0) {
            break;
        }
        if (tc_load && ((err = perf_buffer__poll(tc_pb, THOUSAND)) < 0) && err != -EINTR) {
            break;
        }
        output_containers_metrics(&head);
        sleep(params.period);
    }

err2:
    if (tc_pb) {
        perf_buffer__free(tc_pb);
    }
err:
    if (qdisc_pb) {
        perf_buffer__free(qdisc_pb);
    }
    UNLOAD(qdisc);
    put_containers(&head);
    if (tc_load) {
        offload_tc_bpf(TC_TYPE_EGRESS);
    }
    obj_module_exit();
    return -err;
}
