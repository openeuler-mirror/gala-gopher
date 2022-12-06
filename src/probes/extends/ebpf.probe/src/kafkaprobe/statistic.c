#include <stdio.h>
#include <stdlib.h>
#include <string.h> //memset
#include <arpa/inet.h> //htons
#include <time.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#include "bpf.h"

#include "kafkaprobe.h"

/* 收集数据 */
int collect(int ctrl_map_fd, int data_map_fd, struct KafkaData *data){
    memset(data, 0, sizeof(struct KafkaData));
    int ret;
    __u32 ctrl;

    for(int i=0;i<MAP_MAX_ITEM;i++){
        ctrl = 0;
        ret = bpf_map_lookup_elem(ctrl_map_fd, &i, &ctrl);
        if (ret){
            fprintf(stderr,"WARN: read %d xdp_ctrl_map fail\n", i);
            continue;
        }
            
        if (ctrl==2){
            ret = bpf_map_lookup_elem(data_map_fd, &i, data);
            if(ret){
                fprintf(stderr, "WARN: read %d xdp_data_map fail\n", i);
                continue;
            }
                
            ctrl = 0;
            ret = bpf_map_update_elem(ctrl_map_fd, &i, &ctrl, BPF_ANY);
            if(ret){
                fprintf(stderr, "WARN: write %d xdp_ctrl_map fail\n", i);
                continue;                
            }
            break;
        }
    }

    if(data->src_ip == 0){
        return 1;
    }

    return 0;
}

int kafka_data_cmp(struct KafkaData *d1, struct KafkaData *d2){
        if (d1->type!=d2->type)
            return 1;        
        if (d1->src_ip!=d2->src_ip)
            return 1;
        if (d1->src_port!=d2->src_port)
            return 1;
        if (d1->dst_port!=d2->dst_port)
            return 1;    
        if (d1->len!=d2->len)
            return 1;            
        if (u8ncmp(d1->data, d2->data, d1->len))
            return 1;

        return 0;    
}

/* 将数据写入数组 */
int refresh_array(struct KafkaData *new_client, struct KafkaData *client_array, __u32 *topic_num){
    for(int i=0;i<CLIENT_MAX_ITEM;i++){
        if (client_array[i].src_ip == 0){
            memcpy(&client_array[i], new_client, sizeof(struct KafkaData));

            if(new_client->type == PRODUCER_MSG_TYPE){
                topic_num[i] += new_client->num;
            }else if(new_client->type == CONSUMER_MSG_TYPE){
                topic_num[i] = 1;
            }

            return 0;
        }

        if(kafka_data_cmp(&client_array[i], new_client))
            continue;

        if(new_client->type == PRODUCER_MSG_TYPE){
            topic_num[i] += new_client->num;
        }else if(new_client->type == CONSUMER_MSG_TYPE){
            if(new_client->num > client_array[i].num){
                topic_num[i] += new_client->num - client_array[i].num;
                client_array[i].num = new_client->num;
            }
        }
        
        return 0;                    
    }
    
    return 1;
}

int clean_array(struct KafkaData *client_array, __u32* topic_num){
    struct KafkaData tmp_clinet_array[CLIENT_MAX_ITEM];
    int consumer_num = 0;
    for(int i=0;i<CLIENT_MAX_ITEM;i++){
        if(client_array[i].type == CONSUMER_MSG_TYPE && topic_num[i] > 0){
            memcpy(&tmp_clinet_array[consumer_num], &client_array[i], sizeof(struct KafkaData));
            consumer_num += 1;
        }
    }

    memset(client_array, 0, sizeof(struct KafkaData)*CLIENT_MAX_ITEM);
    memset(topic_num, 0, sizeof(__u32)*CLIENT_MAX_ITEM);
    memcpy(client_array, tmp_clinet_array, sizeof(struct KafkaData)*consumer_num);
    return 0;
}

int output_array_terminal(struct KafkaData *client_array, __u32* topic_num){
    for(int i=0;i<CLIENT_MAX_ITEM;i++){
        if(topic_num[i] == 0)
            break;

        fprintf(stderr, "|%s|%s|%s|%d|%d|%s|%s|%d|\n", 
            "kafkaprobe",
            get_msg_type(client_array[i].type),
            IP_ntoh(client_array[i].src_ip),
            htons(client_array[i].src_port),
            topic_num[i],
            client_array[i].data,
            get_local_ip(),
            htons(client_array[i].dst_port));
    }

    return 0;
}

char *IP_ntoh(__u32 ip){
    char *buf;
    struct in_addr addr = {0};

    addr.s_addr = ip;
    buf= inet_ntoa(addr);
    return buf;
}

__u32 IP_hton(char *IP){
    struct in_addr addr = {0};
    inet_aton(IP, &addr);
    return addr.s_addr;
}

__u64 gettime(){
    struct timespec t;
    int ret;

    ret = clock_gettime(CLOCK_MONOTONIC, &t);
    if (ret < 0) {
        fprintf(stderr, "Error with get time of day\n");
        return 0;
    }
    return (__u64) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

const char *MSG_TYPE[MSG_TYPE_NUM] = {
    "Producer", 
    "Consumer", 
    "Unknown"
};

const char *get_msg_type(__u32 index){
    if(index > MSG_TYPE_NUM){
        return NULL;
    }
    return MSG_TYPE[index];
}

const char *MAP_NAME[MAP_NUM] = {
    "xdp_data_map",
    "xdp_ctrl_map",
};

const char *get_map_name(__u32 index){
    if(index > MAP_NUM){
        return NULL;
    }
    return MAP_NAME[index];
}

int u8ncmp(const __u8* d1, const __u8* d2, __u32 len){
    __u8 diff;
    for(int i=0;i<len;i++){
        diff = d1[i] - d2[i];
        if(diff)
            return 1;
    }

    return 0;
}
