/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: sky
 * Create: 2021-06-21
 * Description: nginx_probe user prog
 ******************************************************************************/
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/resource.h>
#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "args.h"
#include "nginx_probe.skel.h"
#include "nginx_probe.h"

static struct probe_params params = {.period = DEFAULT_PERIOD,
                                     .elf_path = {0}};
static volatile bool stop = false;
static void sig_handler(int sig)
{
    stop = true;
}

static void update_statistic_map(int map_fd, const struct ngx_metric *data)
{
    struct ngx_statistic_key k = {0};
    struct ngx_statistic v = {0};

    /* build key */
    memcpy(&k.cip, &(data->src_ip.ipaddr), sizeof(struct ip));
    k.family = data->src_ip.family;
    k.is_l7 = data->is_l7;
    memcpy(k.sip_str, data->dst_ip_str, INET6_ADDRSTRLEN);

    (void)bpf_map_lookup_elem(map_fd, &k, &v);
    if (v.link_count == 0)
        memcpy(&(v.ngx_ip), &(data->ngx_ip), sizeof(struct ip_addr));

    v.link_count++;

    (void)bpf_map_update_elem(map_fd, &k, &v, BPF_ANY);
    return;
}

static void pull_probe_data(int map_fd, int statistic_map_fd)
{
    int ret = -1;
    struct ip_addr key = {0};
    struct ip_addr next_key = {0};
    struct ngx_metric data;
    unsigned char c_ip_str[INET6_ADDRSTRLEN];
    unsigned char c_local_ip_str[INET6_ADDRSTRLEN];

    while (bpf_map_get_next_key(map_fd, &key, &next_key) != -1) {
        ret = bpf_map_lookup_elem(map_fd, &next_key, &data);
        if (ret == 0) {
            ip_str(data.src_ip.family, (unsigned char *)&data.src_ip, c_ip_str, INET6_ADDRSTRLEN);
            ip_str(data.ngx_ip.family, (unsigned char *)&data.ngx_ip, c_local_ip_str, INET6_ADDRSTRLEN);

            DEBUG("===ngx[%s]: %s:%d --> %s:%d --> %s\n",
                (data.is_l7 == 1 ? "7 LB" : "4 LB"),
                c_ip_str,
                ntohs(data.src_ip.port),
                c_local_ip_str,
                ntohs(data.ngx_ip.port),
                data.dst_ip_str);

            update_statistic_map(statistic_map_fd, &data);
        }

        if (data.is_finish) {
            (void)bpf_map_delete_elem(map_fd, &next_key);
        } else {
            key = next_key;
        }
    }

    return;
}

#define METRIC_STATISTIC_NAME "nginx_link"
static void print_statistic_map(int fd)
{
    int ret = 0;
    struct ngx_statistic_key k = {0};
    struct ngx_statistic_key nk = {0};
    struct ngx_statistic d = {0};

    unsigned char cip_str[INET6_ADDRSTRLEN];
    unsigned char ngxip_str[INET6_ADDRSTRLEN];
    // unsigned char sip_str[INET6_ADDRSTRLEN];

    char *colon = NULL;

    while (bpf_map_get_next_key(fd, &k, &nk) != -1) {
        ret = bpf_map_lookup_elem(fd, &nk, &d);
        if (ret == 0) {
            ip_str(nk.family, (unsigned char *)&(nk.cip), cip_str, INET6_ADDRSTRLEN);
            ip_str(d.ngx_ip.family, (unsigned char *)&(d.ngx_ip.ipaddr), ngxip_str, INET6_ADDRSTRLEN);

            colon = strrchr(nk.sip_str, ':');
            if (colon != NULL)
                *colon = '\0';

            fprintf(stdout,
                "|%s|%s|%s|%s|%u|%s|%u|%u|\n",
                METRIC_STATISTIC_NAME,
                cip_str,
                ngxip_str,
                nk.sip_str,
                ntohs(d.ngx_ip.port),
                (colon ? (colon + 1) : "0"),
                nk.is_l7,
                d.link_count);

            if (colon != NULL)
                *colon = ':';
        }
        (void)bpf_map_delete_elem(fd, &nk);
    }
    (void)fflush(stdout);
    return;
}

int main(int argc, char **argv)
{
    int err = -1;
    int map_fd = -1;
    char *elf[PATH_NUM] = {0};
    int elf_num = -1;
    int attach_flag = 0;

    err = args_parse(argc, argv, &params);
    if (err != 0)
        return -1;

    printf("arg parse interval time:%us  \n", params.period);

    /* Find elf's abs_path */
    ELF_REAL_PATH(nginx, params.elf_path, NULL, elf, elf_num);
    if (elf_num <= 0) {
        printf("get proc:nginx abs_path error \n");
        return -1;
    }

    INIT_BPF_APP(nginx_probe, EBPF_RLIM_LIMITED);
    LOAD(nginx_probe, err);

    /* Clean handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Attach tracepoint handler for each elf_path */
    for (int i = 0; i < elf_num; i++) {
        int ret = 0;
        int ret1 = 0;
        UBPF_ATTACH(nginx_probe, ngx_stream_proxy_init_upstream, elf[i], ngx_stream_proxy_init_upstream, ret1);
        UBPF_RET_ATTACH(nginx_probe, ngx_stream_proxy_init_upstream, elf[i], ngx_stream_proxy_init_upstream, ret1);
        UBPF_ATTACH(nginx_probe, ngx_http_upstream_handler, elf[i], ngx_http_upstream_handler, ret);
        if (ret <= 0 && ret1 <= 0)
            continue;

        UBPF_ATTACH(nginx_probe, ngx_close_connection, elf[i], ngx_close_connection, ret);
        if (ret <= 0)
            continue;

        attach_flag = 1;
    }
    free_exec_path_buf(elf, elf_num);
    if (attach_flag == 0)
        goto err;

    /* create ngx statistic map_fd */
    map_fd = bpf_create_map(
        BPF_MAP_TYPE_HASH, sizeof(struct ngx_statistic_key), sizeof(struct ngx_statistic), STATISTIC_MAX_ENTRIES, 0);
    if (map_fd < 0) {
        printf("Failed to create statistic map fd.\n");
        goto err;
    }
    printf("Successfully started!\n");

    /* try to hit probe info */
    while (!stop) {
        pull_probe_data(GET_MAP_FD(nginx_probe, hs), map_fd);
        print_statistic_map(map_fd);
        sleep(params.period);
    }
err:
    if (map_fd > 0)
        close(map_fd);

    UNLOAD(nginx_probe);
    return 0;
}
