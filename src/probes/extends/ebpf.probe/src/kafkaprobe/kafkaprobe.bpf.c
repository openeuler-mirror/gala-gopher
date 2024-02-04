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
 * Author: sgdd66
 * Create: 2022-08-27
 * Description: kernel probe bpf prog for kafka
 ******************************************************************************/


#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include <bpf/bpf_endian.h>
#include "kafkaprobe.bpf.h"

#define ETH_P_8021AD    0x88A8          /* 802.1ad Service VLAN        */
#define ETH_P_8021Q    0x8100          /* 802.1Q VLAN Extended Header  */
#define ETH_P_IP    0x0800        /* Internet Protocol packet    */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct KafkaData));
    __uint(max_entries, MAP_MAX_ITEM);
} xdp_data_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, MAP_MAX_ITEM);
} xdp_ctrl_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u16));
    __uint(max_entries, MAP_MAX_ITEM);
} xdp_port_map SEC(".maps");

static __always_inline int proto_is_vlan(__u16 h_proto)
{
    return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
          h_proto == bpf_htons(ETH_P_8021AD));
}

static __always_inline int parse_ethhdr_vlan(struct hdr_cursor *nh, void *data_end)
{
    struct ethhdr *eth = nh->pos;
    int hdrsize = sizeof(*eth);
    struct vlan_hdr *vlh;
    __u16 h_proto;
    int i;

    /* Byte-count bounds check; check if current pointer + size of header
     * is after data_end.
     */
    if (nh->pos + hdrsize > data_end)
        return 1;

    nh->pos += hdrsize;

    vlh = nh->pos;
    h_proto = eth->h_proto;

    /* Use loop unrolling to avoid the verifier restriction on loops;
     * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
     */
    #pragma unroll
    for (i = 0; i < VLAN_MAX_DEPTH; i++) {
        if (!proto_is_vlan(h_proto))
            break;

        if (vlh + 1 > data_end)
            break;

        h_proto = vlh->h_vlan_encapsulated_proto;
        vlh++;
    }

    nh->pos = vlh;

    // if packet isn't IP Header, drop.
    if (h_proto != bpf_htons(ETH_P_IP)){
        return 2;
    }

    return 0;
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh, void *data_end, __u32 *addr)
{
    struct iphdr *iph = nh->pos;
    int hdrsize;

    if (iph + 1 > data_end)
        return 1;

    hdrsize = iph->ihl * 4;
    if(hdrsize < sizeof(*iph))
        return 2;

    /* Variable-length IPv4 header, need to use byte-based arithmetic */
    if (nh->pos + hdrsize > data_end)
        return 3;

    nh->pos += hdrsize;

    if (iph->protocol != IPPROTO_TCP)
        return 4;

    *addr = iph->saddr;
    return 0;
}

static __always_inline int is_inspected_port(__u16* port)
{
    __u16* aim_port;
    __u32* index = 0;
    aim_port = bpf_map_lookup_elem(&xdp_port_map, &index);
    if (!aim_port) {
        return 0;
    }
    if (*aim_port == *port) {
        return 1;
    } else {
        return 0;
    }
}

static __always_inline int parse_tcphdr(struct hdr_cursor *nh, void *data_end, __u16 *src_port, __u16 *dst_port)
{
    int len;
    struct tcphdr *tcp = nh->pos;

    if (tcp + 1 > data_end)
        return 1;

    len = tcp->doff * 4;
    /* Sanity check packet field is valid */
    if(len < sizeof(*tcp))
        return 2;

    /* Variable-length TCP header, need to use byte-based arithmetic */
    if (nh->pos + len > data_end)
        return 3;

    nh->pos += len;

    if (data_end == nh->pos)
        return 4;

    if (!is_inspected_port(&tcp->dest))
        return 5;

    *src_port = tcp->source;
    *dst_port = tcp->dest;
    return 0;
}

static __always_inline int get_empty_data(int **ctrl, struct KafkaData **rec)
{
    __u32 i,j;
    j = 0;
    
    #pragma unroll
    for (i=0;i<MAP_MAX_ITEM;i++) {
        *ctrl = bpf_map_lookup_elem(&xdp_ctrl_map, &j);
        if (!*ctrl){
            j+=1;
            continue;
        }
            
        if(**ctrl == 0){
            *rec = bpf_map_lookup_elem(&xdp_data_map, &j);
            if (!rec)
                return 0;
            **ctrl = 1;
            return 1;
        }
        j += 1;
    }

    return 0;
}

static __always_inline int copy_data(__u8 *dst, int len, __u8 *src, void *data_end)
{
    __u32 i,j;
    j = 0;

    #pragma unroll
    for (i = 0; i < SMALL_BUF_SIZE; i++) {        
        dst[j] = *src;
        
        j += 1;
        if (j >= len) {
            return 1;
        }        

        src += 1;
        if (src + 1 > data_end) {
            return 0;
        }        
    }

    return 0;
}

static __always_inline int parse_consumer(struct hdr_cursor *nh, void *data_end, __u32 *src_ip, __u16* src_port, __u16* dst_port)
{
    int *ctrl;
    struct KafkaData *rec = 0;

    struct PacketParser3 *part_data;
    struct PacketParser3 *topic_data;
    struct PacketParser1 *pos_data;
    __u32 off = 12;
    part_data = nh->pos + off;
    if(part_data + 1 > data_end)
        return 1;
    
    off += part_data->len + 28;
    topic_data = nh->pos + off;
    if(topic_data + 1 > data_end)
        return 2;

    if(topic_data->len == 1)
        return 3;
    off += topic_data->len + 14;
    pos_data = nh->pos + off;
    if(pos_data + 1 > data_end)
        return 4;

    if(!get_empty_data(&ctrl, &rec)){
        bpf_printk("array is full!");
        return 5; 
    }
        
    if(!rec)
        return 6;

    rec->src_ip = *src_ip;
    rec->src_port = *src_port;
    rec->dst_port = *dst_port;
    rec->type = CONSUMER_MSG_TYPE;
    rec->len = topic_data->len;
    if(rec->len>SMALL_BUF_SIZE){
        bpf_printk("Error: exceed buf, topic len: %d", rec->len);
        rec->len = SMALL_BUF_SIZE;
    }
    rec->num = hton32(pos_data->param1);
    copy_data(rec->data, rec->len, topic_data->data, data_end);
    // bpf_skb_load_bytes
    *ctrl = 2;

    return 0;    
}

static __always_inline int parse_producer(struct hdr_cursor *nh, void *data_end, __u32 *src_ip, __u16* src_port, __u16* dst_port)
{    
    int *ctrl;
    struct KafkaData *rec = 0;

    struct PacketParser3 *part_data;
    struct PacketParser3 *topic_data;
    struct PacketParser2 *topic_num;
    __u32 off = 12;
    part_data = nh->pos + off;
    if(part_data + 1 > data_end)
        return 1;

    off += part_data->len + 14;
    topic_data = nh->pos + off;
    if(topic_data + 1 > data_end)
        return 3;

    off += topic_data->len + 73;
    topic_num = nh->pos + off;
    if(topic_num + 1 > data_end)
        return 4;

    if(!get_empty_data(&ctrl, &rec)){
        bpf_printk("array is full!");
        return 5; 
    }
        
    if(!rec)
        return 6;

    rec->src_ip = *src_ip;
    rec->src_port = *src_port;
    rec->dst_port = *dst_port;
    rec->type = PRODUCER_MSG_TYPE;
    rec->len = topic_data->len;
    if(rec->len>SMALL_BUF_SIZE){
        bpf_printk("Error: exceed buf, topic len: %d", rec->len);
        rec->len = SMALL_BUF_SIZE;
    }
    rec->num = topic_num->param2;
    copy_data(rec->data, rec->len, topic_data->data, data_end);

    *ctrl = 2;

    return 0;
}

static __always_inline __u32 parse_record(struct hdr_cursor *nh, void *data_end, __u32 *src_ip, __u16* src_port, __u16* dst_port)
{
    int ret;
    struct PacketParser1 *ph = nh->pos;
    if (ph + 1 > data_end)
        return XDP_PASS;

    if (ph->param2 == 0x08000000)
    {
        ret = parse_producer(nh, data_end, src_ip, src_port, dst_port);
        if(ret > 4){
            bpf_printk("Error: parse producer fail, ret: %d", ret);
        }
    }else if(ph->param2 == 0x0c000100)
    {        
        ret = parse_consumer(nh, data_end, src_ip, src_port, dst_port);
        if(ret > 4){
            bpf_printk("Error: parse consumer fail, ret: %d", ret);
        }        
    }

    return XDP_PASS;
}

SEC("xdp_packet_parser")
int  xdp_parser_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor nh;
    nh.pos = data;
    __u32 src_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 ret;

    ret = parse_ethhdr_vlan(&nh, data_end);
    if(ret){
        return XDP_PASS;
    }
    
    ret = parse_iphdr(&nh, data_end, &src_ip);
    if(ret){
        return XDP_PASS;
    }
    
    ret = parse_tcphdr(&nh, data_end, &src_port, &dst_port);
    if(ret){
        return XDP_PASS;
    }

    return parse_record(&nh, data_end, &src_ip, &src_port, &dst_port);
}

char _license[] SEC("license") = "GPL";
