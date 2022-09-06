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
 * Create: 2022-06-23
 * Description: bps bpf prog
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include <stddef.h>
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "nsprobe.h"
#include "bps.h"

#define NS_IN_S 1000000000
#define NS(sec)  ((__u64)(sec) * NS_IN_S)

#define BPF_F_INDEX_MASK    0xffffffffULL
#define BPF_F_ALL_CPU   BPF_F_INDEX_MASK
#define PIN_GLOBAL_NS 2

struct bpf_elf_map_t {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
};

struct bpf_elf_map_t SEC("maps") tc_bps_egress = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64), // cg_classid <=> proc_id
    .value_size = sizeof(struct egress_bandwidth_s), // egress_bandwidth
    .pinning = PIN_GLOBAL_NS,
    .max_elem = 1000,
    .flags = 0,
    .id = 0,
};

#ifndef __PERF_OUT_MAX
#define __PERF_OUT_MAX (64)
#endif
struct bpf_elf_map_t SEC("maps") tc_bps_output = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = __PERF_OUT_MAX,
    .flags = 0,
    .id = 0,
};

// Data collection args
struct bpf_elf_map_t SEC("maps") tc_bps_args = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32), // const value 0
    .value_size = sizeof(struct ns_args_s), // nsprobe args
    .pinning = PIN_GLOBAL_NS,
    .max_elem = 1,
    .flags = 0,
    .id = 0,
};

#ifndef __PERIOD
#define __PERIOD NS(30)
#endif
static __u64 get_period(void)
{
    __u32 key = 0;
    __u64 period = __PERIOD;

    struct ns_args_s *args;
    args = (struct ns_args_s *)bpf_map_lookup_elem(&tc_bps_args, &key);
    if (args) {
        period = args->period;
    }

    return period; // units from second to nanosecond
}

static void report_bps(struct __sk_buff *ctx, struct egress_bandwidth_s* egress_bandwidth, __u64 cg_classid)
{
    __u64 period = get_period();
    __u64 ts_now = bpf_ktime_get_ns();
    if (ts_now > egress_bandwidth->ts &&
        ts_now - egress_bandwidth->ts >= period) {
        unsigned long long bps = egress_bandwidth->total_tx_bytes / ((ts_now - egress_bandwidth->ts) / NS_IN_S);
        struct bps_msg_s bps_msg = {0};
        bps_msg.cg_classid = cg_classid;
        bps_msg.bps = bps;
        (void)bpf_perf_event_output(ctx, &tc_bps_output, BPF_F_ALL_CPU, &bps_msg, sizeof(struct bps_msg_s));
        egress_bandwidth->ts = ts_now;
        egress_bandwidth->total_tx_bytes = 0;
    }
    return;
}

SEC("tc")
int get_egress_bandwidth(struct __sk_buff *skb)
{
    __u64 cg_classid = bpf_skb_cgroup_classid(skb);

    if (cg_classid == 0) {
        return BPS_RET_OK;
    }

    struct egress_bandwidth_s *egress_bandwidth = bpf_map_lookup_elem(&tc_bps_egress, &cg_classid);
    if (egress_bandwidth == NULL) {
        return BPS_RET_OK;
    }
    __sync_fetch_and_add(&egress_bandwidth->total_tx_bytes, skb->len);
    report_bps(skb, egress_bandwidth, cg_classid);
    return BPS_RET_OK;
}

char g_license[] SEC("license") = "GPL";
