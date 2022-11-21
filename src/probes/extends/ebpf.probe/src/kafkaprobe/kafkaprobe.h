#ifndef __KAFKAPROBE_H
#define __KAFKAPROBE_H

#pragma once

#include "bpf.h"


#define SMALL_BUF_SIZE 64
#define MIDDLE_BUF_SIZE 256
#define LARGE_BUF_SIZE 2048
#define NANOSEC_PER_SEC 1000000000

#define MAP_MAX_ITEM 5
#define CLIENT_MAX_ITEM 256

#define PRODUCER_MSG_TYPE 0
#define CONSUMER_MSG_TYPE 1
#define UNKNOWN_MSG_TYPE 2
#define MSG_TYPE_NUM 3

#define MAP_NUM 2

#define VLAN_MAX_DEPTH 10

struct KafkaConfig {
    char ifname[MIDDLE_BUF_SIZE];
    __u32 ifindex;
    char load_file_name[MIDDLE_BUF_SIZE];
    __u16 kafka_port;
    __u32 output_period;
    __u32 xdp_flag;
    char pin_path[MIDDLE_BUF_SIZE];
};

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

// loader.c
struct bpf_object *load_link_pin(struct KafkaConfig *cfg);
int unpin_unlink_unload(struct KafkaConfig *cfg, struct bpf_object *obj);
int open_bpf_map_file(struct KafkaConfig *cfg, const char *map_name, int *map_fd);
int unlink_xdp(struct KafkaConfig *cfg);
const char* get_local_ip();
int set_local_ip(char * ifname);

// statistic.c
char * IP_ntoh(__u32 ip);
__u32 IP_hton(char *IP);

__u64 gettime();

double calc_period(__u64 time1, __u64 time2);

const char *get_map_name(__u32 index);
const char *get_msg_type(__u32 index);
int u8ncmp(const __u8* d1, const __u8* d2, __u32 len);


int collect(int ctrl_map_fd, int data_map_fd, struct KafkaData *data);
int kafka_data_cmp(struct KafkaData *d1, struct KafkaData *d2);
int refresh_array(struct KafkaData *new_client, struct KafkaData *client_array, __u32 *topic_num);
int output_array_terminal(struct KafkaData *client_array, __u32* topic_num);
int clean_array(struct KafkaData *client_array, __u32* topic_num);

#define hton32(data) (((data & 0xff000000) >>24) | ((data & 0x00ff0000) >>8) | ((data & 0x0000ff00) <<8) | ((data & 0x000000ff) <<24) ) 

#define hton16(data) (((data & 0x000000ff) << 8 ) | ((data & 0x0000ff00) >> 8) )

#endif

