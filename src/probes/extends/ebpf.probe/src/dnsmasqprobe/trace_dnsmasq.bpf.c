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
 * Author: dowzyx
 * Create: 2021-06-10
 * Description: dnsmasq_probe bpf prog
 ******************************************************************************/
#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif
#define BPF_PROG_USER
#include "bpf.h"
#include "trace_dnsmasq.h"

char g_license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct link_key));
    __uint(value_size, sizeof(struct link_value));
    __uint(max_entries, LINK_MAX_ENTRIES);
} dns_query_link_map SEC(".maps");

UPROBE(send_from, pt_regs)
{
    union mysockaddr    *to_p;
    union all_addr      *source_p;
    struct link_key     key = {0};
    struct link_value   value = {0};

    to_p = (union mysockaddr *)PT_REGS_PARM5(ctx);
    source_p = (union all_addr *)PT_REGS_PARM6(ctx);

    /* ip address */
    bpf_probe_read_user(&key.family, sizeof(short), &to_p->sa.sa_family);
    switch (key.family) {
        case AF_INET:
            bpf_probe_read_user(&key.c_addr.ip4, sizeof(int), &to_p->in.sin4_addr);
            bpf_probe_read_user(&key.c_port, sizeof(short), &to_p->in.sin_port);
            bpf_probe_read_user(&key.dns_addr.ip4, sizeof(int), &source_p->addr4);
            break;
        case AF_INET6:
            bpf_probe_read_user(&key.c_addr.ip6, IP6_LEN, &to_p->in6.sin6_addr);
            bpf_probe_read_user(&key.c_port, sizeof(short), &to_p->in6.sin_port);
            bpf_probe_read_user(&key.dns_addr.ip6, IP6_LEN, &source_p->addr6);
            break;
        default:
            bpf_printk("=== ip_str family:%d abnormal.\n", key.family);
            break;
    }

    /* link_value process info */
    value.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&value.comm, sizeof(value.comm));

    /* update hash map */
    bpf_map_update_elem(&dns_query_link_map, &key, &value, BPF_ANY);

    return;
}