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
 * Create: 2021-05-24
 * Description: ipvs_probe bpf prog
 ******************************************************************************/
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "trace_lvs.h"

#ifdef KERNEL_SUPPORT_LVS

char g_linsence[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct link_key));
    __uint(value_size, sizeof(struct link_value));
    __uint(max_entries, IPVS_MAX_ENTRIES);
} lvs_link_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u16));
    __uint(value_size, sizeof(u8));
    __uint(max_entries, IPVS_MIN_ENTRIES);
} lvs_flag_map SEC(".maps");

static void ipvs_state_get_key(const struct ip_vs_conn *p, struct link_key *key, struct ip *addr, u16 *port)
{
    key->family = _(p->af);
    switch (key->family) {
        case AF_INET:
            /* server */
            bpf_probe_read_kernel(&key->s_addr.in, sizeof(struct in_addr), &p->daddr);
            /* client */
            bpf_probe_read_kernel(&key->c_addr.in, sizeof(struct in_addr), &p->caddr);
            /* virtural */
            bpf_probe_read_kernel(&key->v_addr.in, sizeof(struct in_addr), &p->vaddr);
            break;
        case AF_INET6:
            bpf_probe_read_kernel(&key->s_addr.in6, sizeof(struct in6_addr), &p->daddr);
            /* client */
            bpf_probe_read_kernel(&key->c_addr.in6, sizeof(struct in6_addr), &p->caddr);
            /* virtural */
            bpf_probe_read_kernel(&key->v_addr.in6, sizeof(struct in6_addr), &p->vaddr);
            break;
        default:
            bpf_printk("===LVS probe get tcp af invalid. \n");
            break;
    }
    key->s_port = _(p->dport);
    key->c_port = _(p->cport);
    key->v_port = _(p->vport);
    *addr = key->v_addr;
    *port = key->v_port;

    return;
}

static void ipvs_fnat_state_get_key(const struct ip_vs_conn_fnat *p, struct link_key *key,
                                    struct ip *addr, u16 *port)
{
    key->family = _(p->af);
    switch (key->family) {
        case AF_INET:
            /* server */
            bpf_probe_read_kernel(&key->s_addr.in, sizeof(struct in_addr), &p->daddr);
            /* local */
            bpf_probe_read_kernel(&addr->in, sizeof(struct in_addr), &p->laddr);
            /* client */
            bpf_probe_read_kernel(&key->c_addr.in, sizeof(struct in_addr), &p->caddr);
            /* virtural */
            bpf_probe_read_kernel(&key->v_addr.in, sizeof(struct in_addr), &p->vaddr);
            break;
        case AF_INET6:
            /* server */
            bpf_probe_read_kernel(&key->s_addr.in6, sizeof(struct in6_addr), &p->daddr);
            /* local */
            bpf_probe_read_kernel(&addr->in6, sizeof(struct in6_addr), &p->laddr);
            /* client */
            bpf_probe_read_kernel(&key->c_addr.in6, sizeof(struct in6_addr), &p->caddr);
            /* virtural */
            bpf_probe_read_kernel(&key->v_addr.in6, sizeof(struct in6_addr), &p->vaddr);
            break;
        default:
            bpf_printk("===LVS probe get tcp af invalid. \n");
            break;
    }
    key->s_port = _(p->dport);
    key->c_port = _(p->cport);
    key->v_port = _(p->vport);
    *port = _(p->lport);

    return;
}

KPROBE(ip_vs_conn_new, pt_regs)
{
    u16 f_key = IPVS_FLAGS_KEY_VAL;

    /* obtain ipvs flags */
    u32 flags = (unsigned int)PT_REGS_PARM5(ctx);
    struct ip_vs_dest *dest = (struct ip_vs_dest *)PT_REGS_PARM6(ctx);
    atomic_t conn_flags = _(dest->conn_flags);
    flags |= conn_flags.counter;
    flags = flags & IP_VS_CONN_F_FWD_MASK;

    /* update hash map */
    bpf_map_update_elem(&lvs_flag_map, &f_key, &flags, BPF_ANY);

    return 0;
}

KRETPROBE(ip_vs_conn_new, pt_regs)
{
    u16 f_key = IPVS_FLAGS_KEY_VAL;
    char flags = IP_VS_CONN_F_LOCALNODE;
    struct link_key     key = {0};
    struct link_value   value = {0};

    /* lookup ipvs flags */
    char *buf = bpf_map_lookup_elem(&lvs_flag_map, &f_key);
    if (buf != (void *)0)
        flags = *buf;

    bpf_printk("===LVS new_ret get flags[0x%x]. \n", flags);

    /* obtain key data */
    if (flags < IP_VS_CONN_FULLNAT) {
        struct ip_vs_conn *conn_p = (struct ip_vs_conn *)PT_REGS_RC(ctx);
        ipvs_state_get_key(conn_p, &key, &value.l_addr, &value.l_port);
    } else {
        struct ip_vs_conn_fnat *conn_p = (struct ip_vs_conn_fnat *)PT_REGS_RC(ctx);
        ipvs_fnat_state_get_key(conn_p, &key, &value.l_addr, &value.l_port);
    }

    /* update hash map */
    bpf_map_update_elem(&lvs_link_map, &key, &value, BPF_ANY);

    return 0;
}

KPROBE(ip_vs_conn_expire, pt_regs)
{
    struct ip_vs_conn_fnat  *ip_vs_fnat_conn_p;
    struct ip_vs_conn       *ip_vs_conn_p;
    u16  f_key = IPVS_FLAGS_KEY_VAL;
    char flags = IP_VS_CONN_F_LOCALNODE;
    struct link_key     key = {0};
    struct link_value   *value_p;
    struct ip           local_addr = {0};
    u16                 local_port = 0;
    struct timer_list   *t = (struct timer_list *)PT_REGS_PARM1(ctx);

    /* lookup ipvs flags */
    char *buf = bpf_map_lookup_elem(&lvs_flag_map, &f_key);
    if (buf != (void *)0)
        flags = *buf;

    /* obtain struct ip_vs_conn's head addr */
    if (flags < IP_VS_CONN_FULLNAT) {
        ip_vs_conn_p = container_of(t, struct ip_vs_conn, timer);
    } else {
        ip_vs_fnat_conn_p = container_of(t, struct ip_vs_conn_fnat, timer);
    }

    /* obtain key data */
    if (flags < IP_VS_CONN_FULLNAT) {
        ipvs_state_get_key(ip_vs_conn_p, &key, &local_addr, &local_port);
    } else {
        ipvs_fnat_state_get_key(ip_vs_fnat_conn_p, &key, &local_addr, &local_port);
    }

    /* lookup hash map, update connect state */
    value_p = bpf_map_lookup_elem(&lvs_link_map, &key);
    if (value_p == (void *)0) {
        bpf_printk("===LVS ubind dest not in hash map.\n");
        return 0;
    }
    value_p->state = IP_VS_TCP_S_CLOSE;
    value_p->close_ts = bpf_ktime_get_ns();
    value_p->l_addr = local_addr;
    value_p->l_port = local_port;

    bpf_map_update_elem(&lvs_link_map, &key, value_p, BPF_ANY);

    return 0;
}
#endif
