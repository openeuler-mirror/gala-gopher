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
#include "ipc.h"
#include "nginx_probe.skel.h"
#include "nginx_probe.h"

#define LOG_NGINX_PREFIX "[NGINXPROBE]"

struct nginx_probe_s {
    struct ipc_body_s ipc_body;
    struct bpf_prog_s *prog;
    int stats_map_fd;
};

static struct nginx_probe_s g_nginx_probe = {0};
static volatile sig_atomic_t g_stop;

static void sig_handler(int sig)
{
    g_stop = 1;
}

static void update_statistic_map(int map_fd, const struct ngx_metric *data)
{
    struct ngx_statistic_key k = {0};
    struct ngx_statistic v = {0};

    /* build key */
    memcpy(&k.cip, &(data->src_ip.ipaddr), sizeof(struct ip));
    k.cport = data->src_ip.port;
    k.family = data->src_ip.family;
    k.is_l7 = data->is_l7;
    memcpy(k.sip_str, data->dst_ip_str, INET6_ADDRSTRLEN);

    (void)bpf_map_lookup_elem(map_fd, &k, &v);
    if (v.link_count == 0) {
        memcpy(&(v.ngx_ip), &(data->ngx_ip), sizeof(struct ip_addr));
    }
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

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        ret = bpf_map_lookup_elem(map_fd, &next_key, &data);
        if (ret == 0) {
            ip_str(data.src_ip.family, (unsigned char *)&data.src_ip, c_ip_str, INET6_ADDRSTRLEN);
            ip_str(data.ngx_ip.family, (unsigned char *)&data.ngx_ip, c_local_ip_str, INET6_ADDRSTRLEN);

            DEBUG("%s nginx[%s]: %s:%d --> %s:%d --> %s\n",
                LOG_NGINX_PREFIX,
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
    char *colon = NULL;

    while (bpf_map_get_next_key(fd, &k, &nk) == 0) {
        ret = bpf_map_lookup_elem(fd, &nk, &d);
        if (ret == 0) {
            ip_str(nk.family, (unsigned char *)&(nk.cip), cip_str, INET6_ADDRSTRLEN);
            ip_str(d.ngx_ip.family, (unsigned char *)&(d.ngx_ip.ipaddr), ngxip_str, INET6_ADDRSTRLEN);

            colon = strrchr(nk.sip_str, ':');
            if (colon != NULL) {
                *colon = '\0';
            }

            fprintf(stdout,
                "|%s|%s|%s|%s|%u|%u|%s|%u|%u|\n",
                METRIC_STATISTIC_NAME,
                cip_str,
                ngxip_str,
                nk.sip_str,
                ntohs(nk.cport),
                ntohs(d.ngx_ip.port),
                (colon ? (colon + 1) : "0"),
                nk.is_l7,
                d.link_count);

            if (colon != NULL) {
                *colon = ':';
            }
        }
        (void)bpf_map_delete_elem(fd, &nk);
    }
    (void)fflush(stdout);
    return;
}

int load_bpf_prog_each_elf(struct bpf_prog_s *prog, const char *elf_path)
{
    int succeed;
    int link_num = 0;

    if (prog->num >= SKEL_MAX_NUM) {
        WARN("[NGINXPROBE] Failed to load %s: exceed the maximum number of skeletons\n", elf_path);
        return -1;
    }

    INIT_OPEN_OPTS(nginx_probe);
    PREPARE_CUSTOM_BTF(nginx_probe);
    OPEN_OPTS(nginx_probe, err, 1);

    LOAD_ATTACH(nginx_probe, nginx_probe, err, 1);

    UBPF_ATTACH(nginx_probe, ngx_stream_proxy_init_upstream, elf_path, ngx_stream_proxy_init_upstream, succeed);
    if (!succeed) {
        goto err;
    }
    UBPF_RET_ATTACH(nginx_probe, ngx_stream_proxy_init_upstream, elf_path, ngx_stream_proxy_init_upstream, succeed);
    if (!succeed) {
        goto err;
    }
    UBPF_ATTACH(nginx_probe, ngx_http_upstream_handler, elf_path, ngx_http_upstream_handler, succeed);
    if (!succeed) {
        goto err;
    }
    UBPF_ATTACH(nginx_probe, ngx_close_connection, elf_path, ngx_close_connection, succeed);
    if (!succeed) {
        goto err;
    }

    prog->custom_btf_paths[prog->num] = nginx_probe_open_opts.btf_custom_path;
    prog->skels[prog->num].skel = (void *)nginx_probe_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)nginx_probe_bpf__destroy;
    for (int i = 0; i < nginx_probe_link_current; i++) {
        prog->skels[prog->num]._link[link_num++] = (void *)nginx_probe_link[i];
    }
    prog->skels[prog->num]._link_num = link_num;
    prog->num++;

    return 0;
err:
    UNLOAD(nginx_probe);
    CLEANUP_CUSTOM_BTF(nginx_probe);
    return -1;
}

int load_bpf_prog(struct ipc_body_s *ipc_body)
{
    struct bpf_prog_s *prog;
    char *elfs[PATH_NUM] = {0};
    int elf_num = -1;
    int ret;

    prog = alloc_bpf_prog();
    if (prog == NULL) {
        ERROR("%s Failed to allocate bpf prog\n", LOG_NGINX_PREFIX);
        return -1;
    }

    /* Find elf's abs_path */
    elf_num = get_exec_file_path("nginx", (const char *)ipc_body->probe_param.elf_path, NULL, elfs, PATH_NUM);
    if (elf_num <= 0 || elf_num > PATH_NUM) {
        ERROR("%s Failed to get execute path of nginx program. elf_num is %d\n", LOG_NGINX_PREFIX, elf_num);
        free_exec_path_buf(elfs, elf_num);
        free_bpf_prog(prog);
        return -1;
    }

    for (int i = 0; i < elf_num; i++) {
        ret = load_bpf_prog_each_elf(prog, elfs[i]);
        if (ret) {
            ERROR("%s Failed to load bpf program from path: %s\n", LOG_NGINX_PREFIX, elfs[i]);
            continue;
        }
        INFO("%s Succeed to load bpf program from path: %s\n", LOG_NGINX_PREFIX, elfs[i]);
    }
    free_exec_path_buf(elfs, elf_num);

    if (prog->num == 0) {
        ERROR("%s No available bpf program loaded successfully.\n", LOG_NGINX_PREFIX);
        free_bpf_prog(prog);
        return -1;
    }

    g_nginx_probe.prog = prog;

    return 0;
}

static int reload_bpf_prog(struct ipc_body_s *ipc_body)
{
    int ret;

    if (strcmp(ipc_body->probe_param.elf_path, g_nginx_probe.ipc_body.probe_param.elf_path)) {
        unload_bpf_prog(&g_nginx_probe.prog);
        ret = load_bpf_prog(ipc_body);
        if (ret) {
            return -1;
        }
    }

    destroy_ipc_body(&g_nginx_probe.ipc_body);
    (void)memcpy(&g_nginx_probe.ipc_body, ipc_body, sizeof(struct ipc_body_s));

    return 0;
}

static void pull_all_probe_data(void)
{
    int i;
    struct bpf_prog_s *prog = g_nginx_probe.prog;

    for (i = 0; i < prog->num; i++) {
        pull_probe_data(GET_MAP_FD_BY_SKEL(prog->skels[i].skel, nginx_probe, hs), g_nginx_probe.stats_map_fd);
    }
}

static void clean_nginx_probe(void)
{
    unload_bpf_prog(&g_nginx_probe.prog);

    if (g_nginx_probe.stats_map_fd > 0) {
        close(g_nginx_probe.stats_map_fd);
    }

    destroy_ipc_body(&g_nginx_probe.ipc_body);
}

int main(int argc, char **argv)
{
    int err = -1;
    int msq_id;
    struct ipc_body_s ipc_body;

    /* Clean handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    msq_id = create_ipc_msg_queue(IPC_EXCL);
    if (msq_id < 0) {
        ERROR("[NGINXPROBE] Get ipc msg queue failed.\n");
        return -1;
    }

    INIT_BPF_APP(nginx_probe, EBPF_RLIM_LIMITED);

    /* create ngx statistic map_fd */
    g_nginx_probe.stats_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, NULL, sizeof(struct ngx_statistic_key),
        sizeof(struct ngx_statistic), STATISTIC_MAX_ENTRIES, NULL);
    if (g_nginx_probe.stats_map_fd < 0) {
        ERROR("%s Failed to create statistic map fd.\n", LOG_NGINX_PREFIX);
        goto err;
    }
    INFO("%s Nginx probe started Successfully.\n", LOG_NGINX_PREFIX);

    /* try to hit probe info */
    while (!g_stop) {
        err = recv_ipc_msg(msq_id, (long)PROBE_NGINX, &ipc_body);
        if (err == 0) {
            err = reload_bpf_prog(&ipc_body);
            if (err) {
                destroy_ipc_body(&ipc_body);
                goto err;
            }
        }

        if (g_nginx_probe.prog != NULL) {
            pull_all_probe_data();
            print_statistic_map(g_nginx_probe.stats_map_fd);
            sleep(g_nginx_probe.ipc_body.probe_param.period);
        } else {
            sleep(DEFAULT_PERIOD);
        }
    }

    err = 0;
err:
    clean_nginx_probe();
    return err;
}
