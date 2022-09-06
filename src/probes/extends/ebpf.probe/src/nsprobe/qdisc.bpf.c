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
 * Create: 2022-06-6
 * Description: qdisc bpf prog
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include <bpf/bpf_endian.h>
#include "bpf.h"
#include "output.h"
#include "qdisc.h"

char g_linsence[] SEC("license") = "GPL";
#define TCQ_F_INGRESS       2

#ifndef __QDISC_MAX
#define __QDISC_MAX (1024)
#endif
struct bpf_map_def SEC("maps") qdisc_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct Qdisc*),    // key
    .value_size = sizeof(struct qdisc),
    .max_entries = __QDISC_MAX,
};

static __always_inline struct qdisc* get_qdisc(struct Qdisc* q)
{
    return (struct qdisc *)bpf_map_lookup_elem(&qdisc_map, &q);
}

static __always_inline int del_qdisc(struct Qdisc* q)
{
    return bpf_map_delete_elem(&qdisc_map, &q);
}

static __always_inline int create_qdisc(struct Qdisc* q)
{
    struct qdisc v = {0};
    return bpf_map_update_elem(&qdisc_map, &q, &v, BPF_ANY);
}

static __always_inline int is_ingress_qdisc(struct Qdisc* q)
{
    u32 flags = _(q->flags);
    return (flags & TCQ_F_INGRESS);
}

static __always_inline int is_loopback_dev(struct Qdisc* q)
{
    char dev_name[IFNAMSIZ] = {0};
    struct netdev_queue *dev_queue = _(q->dev_queue);
    if (dev_queue == NULL)
        return 1;

    struct net_device *dev = _(dev_queue->dev);
    if (dev == NULL) {
        return 1;
    }

    char *name = _(dev->name);
    (void)bpf_probe_read_str(&dev_name, IFNAMSIZ, name);
    if (dev_name[0] == 'l' && dev_name[1] == 'o' && dev_name[2] == 0) {
        return 1;
    }
    return 0;
}

static __always_inline void get_qdisc_info(struct qdisc* qdisc, struct Qdisc* q)
{
    struct netdev_queue *dev_queue = _(q->dev_queue);
    if (dev_queue == NULL) {
        return;
    }

    struct net_device *dev = _(dev_queue->dev);
    if (dev == NULL) {
        return;
    }

    char *name = _(dev->name);
    (void)bpf_probe_read_str(&qdisc->dev_name, IFNAMSIZ, name);

    const struct Qdisc_ops * ops = _(q->ops);
    const char *id = _(ops->id);
    (void)bpf_probe_read_str(&qdisc->kind, IFNAMSIZ, id);

    struct net* net = _(dev->nd_net.net);
    qdisc->netns_id = _(net->ns.inum);
    qdisc->ifindex = _(dev->ifindex);
    qdisc->handle = _(q->handle);
    return;
}

static __always_inline void report_qdisc(void *ctx, struct qdisc* qdisc)
{
    u64 ts = bpf_ktime_get_ns();
    u64 period = get_period();

    if (qdisc->ts == 0) {
        qdisc->ts = ts;
        (void)bpf_perf_event_output(ctx, &output, BPF_F_ALL_CPU, qdisc, sizeof(struct qdisc));
        __builtin_memset(&(qdisc->egress), 0x0, sizeof(struct qdisc_stats));
        return;
    }

    if (ts > qdisc->ts) {
        if ((ts - qdisc->ts) >= period) {
            qdisc->ts = ts;
            (void)bpf_perf_event_output(ctx, &output, BPF_F_ALL_CPU, qdisc, sizeof(struct qdisc));
            __builtin_memset(&(qdisc->egress), 0x0, sizeof(struct qdisc_stats));
            return;
        }
    } else {
        qdisc->ts = 0; // error
    }
    return;
}

static __always_inline void calc_egress_stats(struct Qdisc *q, struct qdisc* qdisc)
{
    u32 tmp;

    tmp = _(q->qstats.qlen);
    qdisc->egress.qlen = max(qdisc->egress.qlen, tmp);

    tmp = _(q->qstats.backlog);
    qdisc->egress.backlog = max(qdisc->egress.backlog, tmp);

    qdisc->egress.drops = _(q->qstats.drops);
    qdisc->egress.requeues = _(q->qstats.requeues);
    qdisc->egress.overlimits = _(q->qstats.overlimits);

    return;
}

static __always_inline struct qdisc* lkup_qdisc(struct Qdisc *q)
{
    struct qdisc* qdisc;

    if (q == NULL) {
        return NULL;
    }

    qdisc = get_qdisc(q);
    if (qdisc == NULL) {
        if (is_ingress_qdisc(q)) {
            return NULL;
        }

        if (is_loopback_dev(q)) {
            return NULL;
        }
        (void)create_qdisc(q);
        qdisc = get_qdisc(q);
        if (qdisc == NULL) {
            return NULL;
        }
        get_qdisc_info(qdisc, q);
    }
    return qdisc;
}

KPROBE(__qdisc_run, pt_regs)
{
    struct Qdisc *q = (struct Qdisc *)PT_REGS_PARM1(ctx);
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();
    struct qdisc* qdisc = lkup_qdisc(q);
    if (qdisc == NULL) {
        return;
    }

    calc_egress_stats(q, qdisc);
    report_qdisc(ctx, qdisc);
}

KPROBE(qdisc_hash_del, pt_regs)
{
    struct Qdisc *q = (struct Qdisc *)PT_REGS_PARM1(ctx);
    u32 pid __maybe_unused = bpf_get_current_pid_tgid();
    (void)del_qdisc(q);
}
