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
 * Create: 2021-06-08
 * Description: haproxy_probe user prog
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
#include "trace_haproxy.skel.h"
#include "trace_haproxy.h"

#define METRIC_NAME_HAPROXY_LINK "haproxy_link"

static struct probe_params params = {.period = DEFAULT_PERIOD,
                                     .elf_path = {0}};
static volatile bool g_stop = false;
static void sig_handler(int sig)
{
    g_stop = true;
}

static void get_host_ip(const unsigned char *value, unsigned short family)
{
    FILE *fp = NULL;
    char buffer[INET6_ADDRSTRLEN] = {0};
    char cmd[COMMAND_LEN] = {""};
    int num = -1;

    if (family == AF_INET) {
        (void)snprintf(cmd, COMMAND_LEN, "/sbin/ifconfig | grep inet | grep -v 127.0.0.1 | grep -v inet6 | awk '{print $2}'");
    } else {
        (void)snprintf(cmd, COMMAND_LEN, "/sbin/ifconfig | grep inet6 | grep -v ::1 | awk '{print $2}'");
    }

    fp = popen(cmd, "r");
    if (fgets(buffer, INET6_ADDRSTRLEN, fp) == NULL) {
        printf("Fail get_host_ip.\n");
        return ;
    }
    (void)pclose(fp);
    num = sscanf(buffer, "%47s", (char *)value);
    if (num < 1)
        printf("failed get hostip [%d]", errno);

    return ;
}

static void update_collect_count(struct collect_value *dd)
{
    dd->link_count++;
    return;
}

static void update_haproxy_collect_map(struct link_key *k, struct link_value *v, int map_fd)
{
    struct collect_key      key = {0};
    struct collect_value    val = {0};

    /* build key */
    memcpy((char *)&key.c_addr, (char *)&k->c_addr, sizeof(struct ip));
    memcpy((char *)&key.p_addr, (char *)&k->p_addr, sizeof(struct ip));
    memcpy((char *)&key.s_addr, (char *)&k->s_addr, sizeof(struct ip));
    key.p_port = k->p_port;
    key.s_port = k->s_port;
    /* lookup value */
    (void)bpf_map_lookup_elem(map_fd, &key, &val);
    /* update value */
    update_collect_count(&val);
    val.family = v->family;
    val.protocol = v->type;
    val.pid = v->pid;
    /* update hash map */
    (void)bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);

    return;
}

static void pull_probe_data(int fd, int collect_fd)
{
    int ret = 0;
    struct link_key     key = {0};
    struct link_key     next_key = {0};
    struct link_value   value = {0};
    unsigned char cli_ip_str[INET6_ADDRSTRLEN];
    unsigned char lb_ip_str[INET6_ADDRSTRLEN];
    unsigned char src_ip_str[INET6_ADDRSTRLEN];

    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        ret = bpf_map_lookup_elem(fd, &next_key, &value);
        if (ret == 0) {
            ip_str(value.family, (unsigned char *)&(next_key.c_addr), cli_ip_str, INET6_ADDRSTRLEN);
            ip_str(value.family, (unsigned char *)&(next_key.p_addr), lb_ip_str, INET6_ADDRSTRLEN);
            ip_str(value.family, (unsigned char *)&(next_key.s_addr), src_ip_str, INET6_ADDRSTRLEN);
            if (next_key.p_addr.ip4 == 0x0) {
                get_host_ip(lb_ip_str, value.family);
            }
        DEBUG("---- new connect protocol[%s] type[%s] c[%s:%d]--lb[%s:%d]--s[%s:%d] state[%d]. \n",
                (value.type == PR_MODE_TCP) ? "TCP" : "HTTP",
                (value.family == AF_INET) ? "IPv4" : "IPv6",
                cli_ip_str,
                ntohs(next_key.c_port),
                lb_ip_str,
                ntohs(next_key.p_port),
                src_ip_str,
                ntohs(next_key.s_port),
                value.state);
            /* update collect map */
            update_haproxy_collect_map(&next_key, &value, collect_fd);
        }
        if (value.state == SI_ST_CLO) {
            (void)bpf_map_delete_elem(fd, &next_key);
        } else {
            key = next_key;
        }
    }
}

static void print_haproxy_collect(int map_fd)
{
    int ret = 0;
    struct collect_key  key = {0};
    struct collect_key  next_key = {0};
    struct collect_value    value = {0};
    unsigned char cli_ip_str[INET6_ADDRSTRLEN];
    unsigned char lb_ip_str[INET6_ADDRSTRLEN];
    unsigned char src_ip_str[INET6_ADDRSTRLEN];

    while (bpf_map_get_next_key(map_fd, &key, &next_key) != -1) {
        ret = bpf_map_lookup_elem(map_fd, &next_key, &value);
        if (ret == 0) {
            ip_str(value.family, (unsigned char *)&(next_key.c_addr), cli_ip_str, INET6_ADDRSTRLEN);
            ip_str(value.family, (unsigned char *)&(next_key.p_addr), lb_ip_str, INET6_ADDRSTRLEN);
            ip_str(value.family, (unsigned char *)&(next_key.s_addr), src_ip_str, INET6_ADDRSTRLEN);
        fprintf(stdout,
                "|%s|%s|%s|%s|%u|%u|%u|%llu|\n",
                METRIC_NAME_HAPROXY_LINK,
                cli_ip_str,
                lb_ip_str,
                src_ip_str,
                ntohs(next_key.p_port),
                ntohs(next_key.s_port),
                value.protocol,
                value.link_count);
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
    ELF_REAL_PATH(haproxy, params.elf_path, NULL, elf, elf_num);
    if (elf_num <= 0) {
        printf("get proc:haproxy abs_path error \n");
        return -1;
    }
    INIT_BPF_APP(trace_haproxy, EBPF_RLIM_LIMITED);
    LOAD(trace_haproxy, trace_haproxy, err);

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Attach tracepoint handler for each elf_path */
    for (int i = 0; i < elf_num; i++) {
        int ret = 0;
        UBPF_ATTACH(trace_haproxy, back_establish, elf[i], back_establish, ret);
        if (ret <= 0)
            continue;

        UBPF_ATTACH(trace_haproxy, stream_free, elf[i], stream_free, ret);
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
    if (collect_map_fd < 0) {
        fprintf(stderr, "Haproxy Failed to create map.\n");
        goto err;
    }

    while (!g_stop) {
        pull_probe_data(GET_MAP_FD(trace_haproxy, haproxy_link_map), collect_map_fd);
        print_haproxy_collect(collect_map_fd);
        sleep(params.period);
    }

err:
/* Clean up */
    UNLOAD(trace_haproxy);
    return 0;
}
