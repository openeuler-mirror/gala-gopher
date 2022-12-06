#ifndef __KAFKAPROBE_H
#define __KAFKAPROBE_H

#include "kafkaprobe.bpf.h"

// bpf内核程序中Map的数目
#define MAP_NUM 2

// 用户态中存储kafka client的最大数目
#define CLIENT_MAX_ITEM 256

struct KafkaConfig {
    char ifname[MIDDLE_BUF_SIZE];
    __u32 ifindex;
    char load_file_name[MIDDLE_BUF_SIZE];
    __u16 kafka_port;
    __u32 output_period;
    __u32 xdp_flag;
    char pin_path[MIDDLE_BUF_SIZE];
};

// loader.c
struct bpf_object *load_link_pin(struct KafkaConfig *cfg);
int unpin_unlink_unload(struct KafkaConfig *cfg, struct bpf_object *obj);
int open_bpf_map_file(struct KafkaConfig *cfg, const char *map_name, int *map_fd);
int unlink_xdp(struct KafkaConfig *cfg);
const char* get_local_ip();
int set_local_ip(char * ifname);
void set_native_mode(__u32 *flag);
void set_socket_mode(__u32 *flag);
void set_offload_mode(__u32 *flag);

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

#endif

