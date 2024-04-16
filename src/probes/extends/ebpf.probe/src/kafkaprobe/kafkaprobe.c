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
#include <unistd.h>
#include <net/if.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#include "bpf.h"
#include "ipc.h"

#include "kafkaprobe.h"

#define KFK_BPF_OBJ_FILE_PATH "/opt/gala-gopher/extend_probes/kafkaprobe.bpf.o"

struct kfk_probe_s {
    struct ipc_body_s ipc_body;
    struct KafkaConfig cfg;
    struct bpf_object *prog;
    char *btf_custom_path;
    int data_map_fd;
    int ctrl_map_fd;
    int port_map_fd;
};

static struct kfk_probe_s g_kfk_probe = {0};
static volatile sig_atomic_t stop = 0;

static void quit_handler(int sig){
    stop = 1;
}

static int set_kafka_config(struct KafkaConfig* cfg, struct probe_params* params) 
{
    // 设置需要绑定的网卡名与index
    snprintf(cfg->ifname, MIDDLE_BUF_SIZE, "%s", params->target_dev);
    cfg->ifindex = if_nametoindex(cfg->ifname);
    if (cfg->ifindex == 0) {
        KFK_ERROR("ifname %s unknown\n", cfg->ifname);
        return -1;
    }

    sprintf(cfg->load_file_name, "%s", KFK_BPF_OBJ_FILE_PATH);
    cfg->kafka_port = params->kafka_port;
    cfg->output_period = params->period;

    // 默认采用native模式。如果失败采用socket模式。当前不考虑offload模式
    set_native_mode(&cfg->xdp_flag);

    // 设定map在文件系统的挂载点。挂载后可以通过文件操作可以访问map。
    sprintf(cfg->pin_path, "%s", GOPHER_MAP_DIR);    
    return 0;
}

static int load_kfk_bpf_prog(void)
{
    int ret;
    struct bpf_object *obj = NULL;
    struct KafkaConfig *cfg = &g_kfk_probe.cfg;

    ret = set_local_ip(cfg->ifname);
    if (ret != 0) {
        return -1;
    }

    if (g_kfk_probe.btf_custom_path) {
        free(g_kfk_probe.btf_custom_path);
        g_kfk_probe.btf_custom_path = NULL;
    }
    obj = load_link_pin(cfg, &(g_kfk_probe.btf_custom_path));
    if (!obj) {
        KFK_ERROR("load_link_pin failed, exit!\n");
        return -1;
    }

    g_kfk_probe.prog = obj;
    return 0;
}

// kafka 探针重新加载的条件：观测的网卡发生变更时，需要重新加载xdp程序。
static int need_to_reload(struct ipc_body_s *ipc_body)
{
    if (strcmp(ipc_body->probe_param.target_dev, g_kfk_probe.ipc_body.probe_param.target_dev) != 0) {
        return 1;
    }
    return 0;
}

static int set_map_fds(struct KafkaConfig *cfg)
{
    int ret;
    int data_map_fd = 0;
    int ctrl_map_fd = 0;
    int port_map_fd = 0;

    ret = open_bpf_map_file(cfg, "xdp_data_map", &data_map_fd);
    if (ret) {
        return -1;
    }
    open_bpf_map_file(cfg, "xdp_ctrl_map", &ctrl_map_fd);
    if (ret) {
        return -1;
    }
    open_bpf_map_file(cfg, "xdp_port_map", &port_map_fd);
    if (ret) {
        return -1;
    }

    g_kfk_probe.data_map_fd = data_map_fd;
    g_kfk_probe.ctrl_map_fd = ctrl_map_fd;
    g_kfk_probe.port_map_fd = port_map_fd;
    return 0;
}

// 将kafka_port写入xdp_port_map中，设计上支持监控多个端口，目前只实现监控一个端口
static int refresh_port_map(void)
{
    int ret;
    int i = 0;
    __u16 kafka_port = hton16(g_kfk_probe.cfg.kafka_port);

    ret = bpf_map_update_elem(g_kfk_probe.port_map_fd, &i, &kafka_port, BPF_ANY);
    if(ret){
        KFK_ERROR("write kafka port into xdp_port_map fail, exit\n");
        return -1;                
    }

    return 0;
}

static int reload_kfk_bpf_prog(struct ipc_body_s *ipc_body)
{
    int ret;
    struct KafkaConfig *cfg = &g_kfk_probe.cfg;

    // 根据输入参数配置kafka监控工具
    memset(cfg, 0, sizeof(struct KafkaConfig));
    ret = set_kafka_config(cfg, &ipc_body->probe_param);
    if (ret != 0) {
        return -1;
    }

    if (g_kfk_probe.prog != NULL && !need_to_reload(ipc_body)) {
        return 0;
    }

    KFK_INFO("Start to reload kafka probe prog\n");
    ret = unpin_unlink_unload(cfg, g_kfk_probe.prog);
    if (ret) {
        return -1;
    }
    ret = load_kfk_bpf_prog();
    if (ret) {
        return -1;
    }
    ret = set_map_fds(cfg);
    if (ret) {
        return -1;
    }

    KFK_INFO("Succeed to reload kafka probe prog\n");
    return 0;
}

static void clean_kfk_probe(void)
{
    if (g_kfk_probe.btf_custom_path) {
        free(g_kfk_probe.btf_custom_path);
        g_kfk_probe.btf_custom_path = NULL;
    }
    if (unpin_unlink_unload(&g_kfk_probe.cfg, g_kfk_probe.prog)) {
        KFK_ERROR("unpin_unlink_unload fail, please clean by hand!\n");
    }
    destroy_ipc_body(&g_kfk_probe.ipc_body);
}

static void report(void)
{
    int ret;
    static struct KafkaData client_array[CLIENT_MAX_ITEM];
    static __u32 topic_num[CLIENT_MAX_ITEM];
    static struct KafkaData new_data;

    // 开始采集
    ret = collect(g_kfk_probe.ctrl_map_fd, g_kfk_probe.data_map_fd, &new_data);
    if(!ret){
        refresh_array(&new_data, client_array, topic_num);
    }
    output_array_terminal(client_array, topic_num);
    clean_array(client_array, topic_num);
}

int main(int argn, char** argv){
    int ret = 0;
    struct ipc_body_s ipc_body;
    int msq_id;

    if (signal(SIGINT, quit_handler) == SIG_ERR) {
        KFK_ERROR("Can't set signal handler\n");
        return -1;
    }

    msq_id = create_ipc_msg_queue(IPC_EXCL);
    if (msq_id < 0) {
        return -1;
    }

    INIT_BPF_APP(kafkaprobe, EBPF_RLIM_LIMITED);
    KFK_INFO("Kafka probe successfully started!\n");

    while (!stop) {
        ret = recv_ipc_msg(msq_id, (long)PROBE_KAFKA, &ipc_body);
        if (ret == 0) {
            ret = reload_kfk_bpf_prog(&ipc_body);
            if (ret) {
                destroy_ipc_body(&ipc_body);
                goto clean;
            }
            ret = refresh_port_map();
            if (ret) {
                destroy_ipc_body(&ipc_body);
                goto clean;
            }

            destroy_ipc_body(&g_kfk_probe.ipc_body);
            (void)memcpy(&g_kfk_probe.ipc_body, &ipc_body, sizeof(struct ipc_body_s));
        }

        if (g_kfk_probe.prog == NULL) {
            sleep(DEFAULT_PERIOD);
            continue;
        }

        report();
        sleep(g_kfk_probe.ipc_body.probe_param.period);
    }

    ret = 0;
clean:
    clean_kfk_probe();
    KFK_INFO("Kafka probe stopped, ret=%d\n", ret);
    return ret;
}
