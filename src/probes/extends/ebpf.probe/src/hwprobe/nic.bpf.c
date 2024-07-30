/*
 * bpf code runs in the Linux kernel
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "hw_args.h"

char g_linsence[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct nic_entity_s));
    __uint(value_size, sizeof(struct nic_failure_s));
    __uint(max_entries, __HW_COUNT_MAX);
} nic_failure_count_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} nic_failure_channel_map SEC(".maps");

static __always_inline char* get_driver_name(const struct net_device *net_dev)
{
    struct device_driver *driver;
    struct device *parent;

    parent = _(net_dev->dev.parent);

    if (!parent) {
        return NULL;
    }

    driver = _(parent->driver);

    if (driver && _(driver->name)) {
        return (char *)_(driver->name);
    }

    return NULL;
}

static __always_inline void update_nic_entity(struct nic_entity_s *nic_entity, struct net_device *net_dev)
{

    (void)bpf_core_read_str(&nic_entity->dev_name, IFNAMSIZ, &net_dev->name);
    char *driver = get_driver_name(net_dev);
    if (driver != NULL) {
        (void)bpf_core_read_str(&nic_entity->driver, DRIVER_NAME_LEN, driver);
    }
}

static __always_inline struct nic_failure_s* get_nic_failure(struct nic_entity_s *nic_entity)
{
    struct nic_failure_s *nic_failure = (struct nic_failure_s *)bpf_map_lookup_elem(&nic_failure_count_map, nic_entity);
    if (nic_failure) {
        return nic_failure;
    }

    struct nic_failure_s new_nic_failure = {0};
    (void)__builtin_memcpy(&new_nic_failure.entity.dev_name, nic_entity->dev_name,  IFNAMSIZ);
    (void)__builtin_memcpy(&new_nic_failure.entity.driver, nic_entity->driver, DRIVER_NAME_LEN);
    new_nic_failure.entity.queue_index = nic_entity->queue_index;

    bpf_map_update_elem(&nic_failure_count_map, nic_entity, &new_nic_failure, BPF_ANY);
    return (struct nic_failure_s *)bpf_map_lookup_elem(&nic_failure_count_map, nic_entity);
}

static __always_inline void report_nic_failure(void *ctx, struct nic_failure_s* nic_failure)
{
    if (is_report_tmout(&(nic_failure->report_ts))) {
        (void)bpfbuf_output(ctx, &nic_failure_channel_map, nic_failure, sizeof(struct nic_failure_s));
        nic_failure->xmit_timeout_count = 0;
    }
}

KPROBE(netif_carrier_off, pt_regs)
{
    struct nic_entity_s nic_entity = {0};
    struct net_device *net_dev = (struct net_device *)PT_REGS_PARM1(ctx);
    if (net_dev == NULL) {
        return 0;
    }

    (void)update_nic_entity(&nic_entity, net_dev);

    struct nic_failure_s *nic_failure = get_nic_failure(&nic_entity);
    if (nic_failure == NULL) {
        return 0;
    }

    nic_failure->carrier_up_count = _(net_dev->carrier_up_count.counter);
    nic_failure->carrier_down_count = _(net_dev->carrier_down_count.counter);

    (void)report_nic_failure(ctx, nic_failure);

    return 0;
}

KRAWTRACE(net_dev_xmit_timeout, bpf_raw_tracepoint_args)
{
    struct nic_entity_s nic_entity = {0};
    struct net_device *net_dev = (struct net_device *)ctx->args[0];
    int queue_index = (int)ctx->args[1];
    if (net_dev == NULL) {
        return 0;
    }

    (void)update_nic_entity(&nic_entity, net_dev);
    nic_entity.queue_index = queue_index;

    struct nic_failure_s *nic_failure = get_nic_failure(&nic_entity);
    if (nic_failure == NULL) {
        return 0;
    }

    __sync_fetch_and_add(&(nic_failure->xmit_timeout_count), 1);
    report_nic_failure(ctx, nic_failure);
    return 0;
}
