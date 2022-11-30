#ifndef __KAFKAPROBE_H
#define __KAFKAPROBE_H

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

#endif

