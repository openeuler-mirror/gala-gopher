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
 * Description: http probe user prog
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <string.h>

#include "args.h"
#include "kafkaprobe.h"

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

int quit_flag = 0;

void quit_handler(int sig){
    quit_flag = 1;
}

static void start_up(int ctrl_map_fd, int data_map_fd, int port_map_fd, struct KafkaConfig *cfg){
    struct KafkaData client_array[CLIENT_MAX_ITEM];
    __u32 topic_num[CLIENT_MAX_ITEM];
    struct KafkaData new_data;
    int ret;

    // 将kafka_port写入xdp_port_map中，设计上支持监控多个端口，目前只实现监控一个端口
    int i = 0;
    __u16 kafka_port = htons(cfg->kafka_port);
    ret = bpf_map_update_elem(port_map_fd, &i, &kafka_port, BPF_ANY);
    if(ret){
        fprintf(stderr, "Error: write kafka port into xdp_port_map fail, exit\n");
        return;                
    }

    __u64 start_time = gettime();
    __u64 now;
    while (!quit_flag) {
        ret = collect(ctrl_map_fd, data_map_fd, &new_data);
        if(ret){
            sleep(0.01);            
        }else{
            refresh_array(&new_data, client_array, topic_num);
        }
    
        now = gettime();
        if((now-start_time)/NANOSEC_PER_SEC > cfg->output_period){
            output_array_terminal(client_array, topic_num);
            clean_array(client_array, topic_num);
            start_time = now;
        }    
    }
}

static struct probe_params params = { .period = DEFAULT_PERIOD };

int set_kafka_config(struct KafkaConfig* cfg) 
{
    // 设置需要绑定的网卡名与index
    snprintf(cfg->ifname, MIDDLE_BUF_SIZE, "%s", params.ifname);
    cfg->ifindex = if_nametoindex(cfg->ifname);
    if (cfg->ifindex == 0) {
        fprintf(stderr, "ERROR: ifname %s unknown\n", cfg->ifname);
        return -1;
    }

    sprintf(cfg->load_file_name, "%s", "kafkaprobe.bpf.o");
    cfg->kafka_port = params.kafka_port;
    cfg->output_period = params.period;

    // 默认采用native模式。如果失败采用socket模式。当前不考虑offload模式
    set_native_mode(&cfg->xdp_flag);

    // 设定map在文件系统的挂载点。挂载后可以通过文件操作可以访问map。
    sprintf(cfg->pin_path, "%s", "/sys/fs/bpf");    
    return 0;
}

int main(int argn, char** argv){
    signal(SIGINT, quit_handler);

    int ret = 0;
    struct bpf_object *obj = NULL;
    struct KafkaConfig cfg;    

    printf("parse configure data...\n");
    ret = args_parse(argn, argv, &params);
    if (ret != 0) {
        return -1;
    }

    // 根据输入参数配置kafka监控工具
    memset(&cfg, 0, sizeof(struct KafkaConfig));
    ret = set_kafka_config(&cfg);
    if (ret != 0) {
        return -2;
    }

    ret = set_local_ip(cfg.ifname);
    if (ret != 0) {
        return -3;
    }

    printf("load, link, pin kafka probe prog...\n");
    INIT_BPF_APP(kafkaprobe, EBPF_RLIM_LIMITED);

    obj = load_link_pin(&cfg);
    if (!obj) {
        printf("Error: load_link_pin failed, exit!");
        goto clean;
    }

    // 获取map的文件句柄
    int data_map_fd, ctrl_map_fd, port_map_fd;
    open_bpf_map_file(&cfg, "xdp_data_map", &data_map_fd);
    open_bpf_map_file(&cfg, "xdp_ctrl_map", &ctrl_map_fd);
    open_bpf_map_file(&cfg, "xdp_port_map", &port_map_fd);


    // 开始采集
    printf("Kafka Probe Start!\n");
    start_up(ctrl_map_fd, data_map_fd, port_map_fd, &cfg);

clean:
    ret = unpin_unlink_unload(&cfg, obj);
    if(ret){
        printf("ERROR: unpin_unlink_unload fail, please clean by hand!\n");
        return 1;
    }    

    fprintf(stderr, "STOP PROCESS!\n");
    return 0;
}