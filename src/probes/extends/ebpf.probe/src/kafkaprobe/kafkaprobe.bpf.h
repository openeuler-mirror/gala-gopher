#ifndef KAFKAPROBE_BPF_H
#define KAFKAPROBE_BPF_H

#define SMALL_BUF_SIZE 64
#define MIDDLE_BUF_SIZE 256
#define LARGE_BUF_SIZE 2048
#define NANOSEC_PER_SEC 1000000000

#define MAP_MAX_ITEM 5

#define PRODUCER_MSG_TYPE 0
#define CONSUMER_MSG_TYPE 1
#define UNKNOWN_MSG_TYPE 2
#define MSG_TYPE_NUM 3

#define VLAN_MAX_DEPTH 10

struct KafkaData {
    __u16 type;
    __u16 len;
    __u32 num;
    __u32 src_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 data[SMALL_BUF_SIZE];
};

struct PacketParser1{
    __u32 param1;
    __u32 param2;
};

struct PacketParser2{
    __u8 param1;
    __u8 param2;
};

struct PacketParser3{
    __u8 null;
    __u8 len;
    __u8 data[32];
};

struct hdr_cursor {
    void *pos;
};

struct collect_vlans {
    __u16 id[VLAN_MAX_DEPTH];
};

#define hton32(data) (((data & 0xff000000) >>24) | ((data & 0x00ff0000) >>8) | ((data & 0x0000ff00) <<8) | ((data & 0x000000ff) <<24) ) 

#define hton16(data) (((data & 0x000000ff) << 8 ) | ((data & 0x0000ff00) >> 8) )

#endif