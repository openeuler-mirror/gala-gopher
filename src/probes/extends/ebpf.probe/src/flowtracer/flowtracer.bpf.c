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

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "flowtracer.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// from `tools/testing/selftests/bpf/test_tcp_hdr_options.h`
#define CG_OK	1
#define CG_ERR	0
#define ERR2CG(err) (err)? CG_ERR: CG_OK

#define NFCT_INFOMASK 7UL
#define NFCT_PTRMASK ~(NFCT_INFOMASK)
#define CTINFO2DIR(ctinfo) ((ctinfo) >= IP_CT_IS_REPLY ? IP_CT_DIR_REPLY : IP_CT_DIR_ORIGINAL)

// FlowTracer data: maps from observed TCP flow tuple into received remote original address
#define MAX_ENTRIES_FLOW 65536
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_data);
    __uint(max_entries, MAX_ENTRIES_FLOW);
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // map is located at /sys/fs/bpf/flowtracer_data
} flowtracer_data SEC(".maps");

#ifdef GOPHER_DEBUG
// ring buffer to send events to user-space (for debug purposes)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ring_buffer SEC(".maps");

static void notify(enum flow_log_op op, struct flow_key *flow_key, struct flow_data *flow_data)
{
    struct flow_log *flow_log = bpf_ringbuf_reserve(&ring_buffer, sizeof(struct flow_log), 0);
    if (!flow_log) {
        return;
    }

    flow_log->op = op;
    flow_log->key = *flow_key;
    if (flow_data) {
        flow_log->data = *flow_data;
    }
    bpf_ringbuf_submit(flow_log, 0);
}
#else
static inline void notify(enum flow_log_op op, struct flow_key *flow_key, struct flow_data *flow_data) {}  // NOP
#endif

static inline int set_hdr_cb_flags(struct bpf_sock_ops *skops, __u32 extra)
{
    long err = bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | extra);
    return ERR2CG(err);
}

static int handle_hdr_opt_len(struct bpf_sock_ops *skops)
{
    const int bytes_to_reserve = sizeof(struct tcp_opt_source_info);
    int err = bpf_reserve_hdr_opt(skops, bytes_to_reserve, 0);
    return ERR2CG(err);
}

static int handle_write_hdr_opt(struct bpf_sock_ops *skops)
{
    struct tcp_opt_source_info opt = {0};
    opt.kind = TCP_OPT_SOURCE_INFO_KIND;
    opt.len = sizeof(struct tcp_opt_source_info);
    opt.address.ip4 = skops -> local_ip4;                               /* stored in network byte order (bpf.h) */
    opt.address.port = (__be16)bpf_htons((__u16)skops -> local_port);   /* stored in host byte order (bpf.h) */

    int err = bpf_store_hdr_opt(skops, &opt, sizeof(opt), 0);
    return ERR2CG(err);
}

static int handle_hdr_parse(struct bpf_sock_ops *skops)
{
    struct tcp_opt_source_info opt = {0};
    opt.kind = TCP_OPT_SOURCE_INFO_KIND;

    int err = bpf_load_hdr_opt(skops, &opt, sizeof(opt), 0);
    if (err < 0) {
        return CG_ERR;
    }

    __be32 local_ip4 = skops->local_ip4;                                /* stored in network byte order (bpf.h) */
    __be16 local_port = (__be16)bpf_htons((__u16)skops->local_port);    /* stored in host byte order (bpf.h) */
    __be32 remote_ip4 = skops->remote_ip4;                              /* stored in network byte order (bpf.h) */
    __be16 remote_port = (__be16)(skops->remote_port >> 16);            /* stored in network byte order (bpf.h) - high 16 bits of 32 bits variable */
    __be32 original_remote_ip4 = opt.address.ip4;
    __be16 original_remote_port = opt.address.port;                     /* network byte order (as written in handle_write_hdr_opt)*/

    if (remote_ip4 == original_remote_ip4 && remote_port == original_remote_port) {
        return CG_OK;  // keep only flows with changed address
    }

    // check if the flow is in the flowtracer map
    struct flow_key flow_key = {0};
    flow_key.local_ip4 = local_ip4;
    flow_key.local_port = local_port;
    flow_key.remote_ip4 = remote_ip4;
    flow_key.remote_port = remote_port;
    flow_key.l4_proto = IPPROTO_TCP;

    struct flow_data *flow_ptr = bpf_map_lookup_elem(&flowtracer_data, &flow_key);
    if (!flow_ptr) {
        // add a new flow
        struct flow_data flow = {0};
        flow.original_remote_ip4 = original_remote_ip4;
        flow.original_remote_port = original_remote_port;
        bpf_map_update_elem(&flowtracer_data, &flow_key, &flow, BPF_NOEXIST);

        // notify userspace that a new flow was added (debug purposes only)
        notify(FLOW_LOG_ADD, &flow_key, &flow);
    }

    return CG_OK;
}

SEC("sockops")
int flowtracer_sockops_fn(struct bpf_sock_ops *skops)
{
    __u32 op = skops -> op;

    switch (op) {
        case BPF_SOCK_OPS_TCP_CONNECT_CB:
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
            // enable callbacks
            return set_hdr_cb_flags(skops, BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
        case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
            // tell the kernel to allocate space for the header
            return handle_hdr_opt_len(skops);
        case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
            // give the kernel tcp header option contents
            return handle_write_hdr_opt(skops);
        case BPF_SOCK_OPS_PARSE_HDR_OPT_CB:
            // parse tcp header option
            return handle_hdr_parse(skops);
    }

    return CG_OK;
}

SEC("kprobe/__nf_conntrack_confirm")
int BPF_KPROBE(nf_conntrack_confirm, struct sk_buff *skb)
{
    // Function '__nf_conntrack_confirm' is called when conntrack confirms a connection. For outgoing connections
    // this happens immediately upon establishment (sending of SYN packet)
    unsigned long nfct;
    unsigned int ctinfo;
    struct nf_conn *ct;
    enum ip_conntrack_dir dir;
    struct nf_conntrack_tuple_hash sth[2];

    // Check if the current packet is IPv4/TCP
    void *skb_head = BPF_CORE_READ(skb, head);
    __u16 l3_offset = BPF_CORE_READ(skb, network_header);

    struct iphdr *iph = (struct iphdr *)(skb_head + l3_offset);

    if (BPF_CORE_READ_BITFIELD_PROBED(iph, version) != 4)
        return 0;  // only IPv4 is supported

    if (BPF_CORE_READ(iph, protocol) != IPPROTO_TCP) {
        return 0;  // only TCP is supported
    }

    // Init conntrack info
    BPF_CORE_READ_INTO(&nfct, skb, _nfct);
    ctinfo = nfct & NFCT_INFOMASK;
    ct = (struct nf_conn *)(nfct & NFCT_PTRMASK);
    dir = CTINFO2DIR(ctinfo);
    BPF_CORE_READ_INTO(&sth, ct, tuplehash);

    // collect conntrack entry
    __u32 src_ip_f = sth[dir].tuple.src.u3.ip;
    __be16 src_port_f = sth[dir].tuple.src.u.tcp.port;
    __u32 dst_ip_f = sth[dir].tuple.dst.u3.ip;
    __be16 dst_port_f = sth[dir].tuple.dst.u.tcp.port;
    __u32 src_ip_b = sth[!dir].tuple.src.u3.ip;
    __be16 src_port_b = sth[!dir].tuple.src.u.tcp.port;
    __u32 dst_ip_b = sth[!dir].tuple.dst.u3.ip;
    __be16 dst_port_b = sth[!dir].tuple.dst.u.tcp.port;

    if (dst_ip_b == src_ip_f && dst_port_b == src_port_f) {
        return 0;  // address is not translated, ignore
    }

    // Socket view -> Packet view
    // We can use conntrack information to map an observed socket address to a real destination address
    struct flow_key flow_key = {0};  // as observed at socket level of a client
    flow_key.local_ip4 = src_ip_f;
    flow_key.local_port = src_port_f;
    flow_key.remote_ip4 = dst_ip_f;
    flow_key.remote_port = dst_port_f;
    flow_key.l4_proto = IPPROTO_TCP;

    struct flow_data flow_data = {0}; // real address of a server
    flow_data.original_remote_ip4 = src_ip_b;
    flow_data.original_remote_port = src_port_b;

    bpf_map_update_elem(&flowtracer_data, &flow_key, &flow_data, BPF_NOEXIST);
    notify(FLOW_LOG_ADD, &flow_key, &flow_data);
    return 0;
}

SEC("kprobe/nf_conntrack_destroy")
int BPF_KPROBE(nf_conntrack_destroy, struct nf_conntrack *nfct)
{
    // Function nf_conntrack_destroy is called when conntrack module deletes connection entry from its table,
    // so it is a good time to delete the entry from flowtracer map too.

    // Function nf_conntrack_destroy gets a pointer to nf_conn.ct_general, which is the same
    // as pointer to the whole structure nf_conn
    struct nf_conntrack_tuple_hash th[2];
    BPF_CORE_READ_INTO(&th, (struct nf_conn *)nfct, tuplehash);

    if (th[IP_CT_DIR_ORIGINAL].tuple.dst.protonum != IPPROTO_TCP) {
        return 0;
    }

    // Conntrack tracks 4-tuple for original packets and 4-tuple for reply packets in tuplehash array.
    // If a connection is originated from the current host (= client), then 4-tuple of original packets
    // is the same as observed at the socket level.
    // Example of k8s pod talking to virtual service IP:
    //   * original: (10.0.0.159, 34568, 10.247.204.240, 8000) --> matches client's socket view
    //   * reply: (10.0.0.28, 8000, 192.168.3.14, 16256)
    // If a connection is incoming (= server), then 4-tuple of reply packets match the one observed
    // at the socket level.
    // Example of an externally accessible service running in a docker container:
    //   * original: (10.221.55.32, 57911, 10.82.1.33, 8001)
    //   * reply: (172.17.0.2, 8001, 10.221.55.32, 57911) --> matches server's socket view

    struct flow_key flow_key = {0};
    flow_key.local_ip4 = th[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
    flow_key.local_port = th[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port;
    flow_key.remote_ip4 = th[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
    flow_key.remote_port = th[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port;
    flow_key.l4_proto = IPPROTO_TCP;

    // Try to delete entry as if it was a client socket
    int err = bpf_map_delete_elem(&flowtracer_data, &flow_key);
    if (!err) {
        // notify userspace that a flow was deleted (debug purposes only)
        notify(FLOW_LOG_DEL, &flow_key, NULL);
    }

    flow_key.local_ip4 = th[IP_CT_DIR_REPLY].tuple.src.u3.ip;
    flow_key.local_port = th[IP_CT_DIR_REPLY].tuple.src.u.tcp.port;
    flow_key.remote_ip4 = th[IP_CT_DIR_REPLY].tuple.dst.u3.ip;
    flow_key.remote_port = th[IP_CT_DIR_REPLY].tuple.dst.u.tcp.port;

    // Try to delete entry as if it was a server socket
    err = bpf_map_delete_elem(&flowtracer_data, &flow_key);
    if (!err) {
        // notify userspace that a flow was deleted (debug purposes only)
        notify(FLOW_LOG_DEL, &flow_key, NULL);
    }

    return 0;
}