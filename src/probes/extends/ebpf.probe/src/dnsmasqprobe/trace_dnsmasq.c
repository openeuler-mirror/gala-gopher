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
 * Author: dowzyx
 * Create: 2021-06-10
 * Description: dnsmasq_probe user prog
 ******************************************************************************/
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "args.h"
#include "trace_dnsmasq.skel.h"
#include "trace_dnsmasq.h"

#define METRIC_NAME_DNSMASQ_LINK    "dnsmasq_link"

static struct probe_params params = {.period = DEFAULT_PERIOD,
                                     .elf_path = {0}};
static volatile bool g_stop = false;
static void sig_handler(int sig)
{
    g_stop = true;
}

static void update_collect_map(struct link_key *k, struct link_value *v, int map_fd)
{
    struct collect_key      key = {0};
    struct collect_value    value = {0};

    /* build key */
    memcpy((char *)&key.c_addr, (char *)&k->c_addr, sizeof(struct ip));
    memcpy((char *)&key.dns_addr, (char *)&k->dns_addr, sizeof(struct ip));
    key.family = k->family;

    /* lookup value */
    (void)bpf_map_lookup_elem(map_fd, &key, &value);

    /* update value */
    value.link_count++;
    value.pid = v->pid;
    (void)snprintf(value.comm, TASK_COMM_LEN, v->comm);

    /* update hash map */
    (void)bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);

    return;
}

static void pull_probe_data(int fd, int collect_fd)
{
    int ret = 0;
    struct link_key     key = {0};
    struct link_key     next_key = {0};
    struct link_value   value = {0};
    unsigned char cli_ip_str[INET6_ADDRSTRLEN];
    unsigned char dns_ip_str[INET6_ADDRSTRLEN];

    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        ret = bpf_map_lookup_elem(fd, &next_key, &value);
        if (ret == 0) {
            ip_str(next_key.family, (unsigned char *)&(next_key.c_addr), cli_ip_str, INET6_ADDRSTRLEN);
            ip_str(next_key.family, (unsigned char *)&(next_key.dns_addr), dns_ip_str, INET6_ADDRSTRLEN);
            DEBUG("---- new connect c[%s:%d]--dns[%s:53], pid[%u] comm[%s]. \n",
                cli_ip_str,
                ntohs(next_key.c_port),
                dns_ip_str,
                value.pid,
                value.comm);
            /* update collect map */
            update_collect_map(&next_key, &value, collect_fd);
        }
        (void)bpf_map_delete_elem(fd, &next_key);
        key = next_key;
    }
}

static void print_dnsmasq_collect(int map_fd)
{
    int ret = 0;
    struct collect_key      key = {0};
    struct collect_key      next_key = {0};
    struct collect_value    value = {0};
    unsigned char cli_ip_str[INET6_ADDRSTRLEN];
    unsigned char dns_ip_str[INET6_ADDRSTRLEN];

    while (bpf_map_get_next_key(map_fd, &key, &next_key) != -1) {
        ret = bpf_map_lookup_elem(map_fd, &next_key, &value);
        if (ret == 0) {
            ip_str(next_key.family, (unsigned char *)&(next_key.c_addr), cli_ip_str, INET6_ADDRSTRLEN);
            ip_str(next_key.family, (unsigned char *)&(next_key.dns_addr), dns_ip_str, INET6_ADDRSTRLEN);
            (void)fprintf(stdout,
                "|%s|%s|%s|%d|%u|%u|%s|\n",
                METRIC_NAME_DNSMASQ_LINK,
                cli_ip_str,
                dns_ip_str,
                next_key.family,
                value.link_count,
                value.pid,
                value.comm);
        }
        (void)bpf_map_delete_elem(map_fd, &next_key);
    }
    (void)fflush(stdout);
    return;
}

int main(int argc, char **argv)
{
    int err = -1;
    int collect_map_fd = -1;
    char *elf[PATH_NUM] = {0};
    int elf_num = -1;
    int attach_flag = 0;

    err = args_parse(argc, argv, &params);
    if (err != 0)
        return -1;
    printf("arg parse interval time:%us\n", params.period);

    /* Find elf's abs_path */
    ELF_REAL_PATH(dnsmasq, params.elf_path, NULL, elf, elf_num);
    if (elf_num <= 0) {
        printf("get proc:dnsmasq abs_path error \n");
        return -1;
    }

    INIT_BPF_APP(trace_dnsmasq, EBPF_RLIM_LIMITED);
    LOAD(trace_dnsmasq, err);

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Attach tracepoint handler for each elf_path */
    for (int i = 0; i < elf_num; i++) {
        int ret = 0;
        UBPF_ATTACH(trace_dnsmasq, send_from, elf[i], send_from, ret);
        if (ret <= 0)
            continue;

		attach_flag = 1;
    }
    free_exec_path_buf(elf, elf_num);
    if (attach_flag == 0)
        goto err;

    /* create collect hash map */
    collect_map_fd =
        bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(struct collect_key), sizeof(struct collect_value), METRIC_ENTRIES, 0);

    while (!g_stop) {
        pull_probe_data(GET_MAP_FD(trace_dnsmasq, dns_query_link_map), collect_map_fd);
        print_dnsmasq_collect(collect_map_fd);
        sleep(params.period);
    }

err:
/* Clean up */
    UNLOAD(trace_dnsmasq);
    return -err;
}
