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
#include "trace_lvs.h"

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

static int ipvs_state_get_key(const struct ip_vs_conn *p, struct link_key *key, struct ip *addr, u16 *port)
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
            return 1;
    }
    key->s_port = _(p->dport);
    key->c_port = _(p->cport);
    key->v_port = _(p->vport);
    *addr = key->v_addr;
    *port = key->v_port;

    return 0;
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
    struct ip_vs_conn_fnat *ip_vs_fnat_conn_p;
    struct ip_vs_conn *ip_vs_conn_p = (struct ip_vs_conn *)PT_REGS_RC(ctx);

    if (ip_vs_conn_p == NULL) {
        return 0;
    }

    /* lookup ipvs flags */
    char *buf = bpf_map_lookup_elem(&lvs_flag_map, &f_key);
    if (buf == NULL) {
        return 0;
    }

    /* obtain key data */
    flags = *buf;
    if (flags < IP_VS_CONN_FULLNAT) {
        /* droute mode may be running in ipvs-fnat or linux ipvs, try getting link_key through linux ipvs */
        if (ipvs_state_get_key(ip_vs_conn_p, &key, &value.l_addr, &value.l_port) == 0) {
            bpf_map_update_elem(&lvs_link_map, &key, &value, BPF_ANY);
            return 0;
        }
    }

    ip_vs_fnat_conn_p = (struct ip_vs_conn_fnat *)ip_vs_conn_p;
    ipvs_fnat_state_get_key(ip_vs_fnat_conn_p, &key, &value.l_addr, &value.l_port);

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
    struct timer_list *t = (struct timer_list *)PT_REGS_PARM1(ctx);

    /* lookup ipvs flags */
    char *buf = bpf_map_lookup_elem(&lvs_flag_map, &f_key);
    if (buf == NULL) {
        return 0;
    }

    /* obtain key data */
    flags = *buf;
    if (flags < IP_VS_CONN_FULLNAT) {
        ip_vs_conn_p = container_of(t, struct ip_vs_conn, timer);
        if (ipvs_state_get_key(ip_vs_conn_p, &key, &local_addr, &local_port)) {
            ip_vs_fnat_conn_p = container_of(t, struct ip_vs_conn_fnat, timer);
            ipvs_fnat_state_get_key(ip_vs_fnat_conn_p, &key, &local_addr, &local_port);
        }
    } else {
        ip_vs_fnat_conn_p = container_of(t, struct ip_vs_conn_fnat, timer);
        ipvs_fnat_state_get_key(ip_vs_fnat_conn_p, &key, &local_addr, &local_port);
    }

    /* lookup hash map, update connect state */
    value_p = bpf_map_lookup_elem(&lvs_link_map, &key);
    if (value_p == NULL) {
        return 0;
    }

    value_p->state = IP_VS_TCP_S_CLOSE;
    bpf_map_update_elem(&lvs_link_map, &key, value_p, BPF_ANY);
    return 0;
}
