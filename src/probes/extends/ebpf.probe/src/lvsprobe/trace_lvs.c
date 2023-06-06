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
 * Create: 2021-05-24
 * Description: ipvs_probe user prog
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
#include "trace_lvs.h"

#ifdef KERNEL_SUPPORT_LVS
#include "trace_lvs.skel.h"

#define METRIC_NAME_LVS_LINK "ipvs_link"

static volatile sig_atomic_t stop;
static struct probe_params params = {.period = DEFAULT_PERIOD};

static void sig_int(int signo)
{
    stop = 1;
}

static void ippro_to_str(unsigned short protocol, unsigned char *type_str)
{
    switch (protocol) {
        case IPPROTO_IP:
            memcpy(type_str, "IP", INET6_ADDRSTRLEN * sizeof(char));
            break;
        case IPPROTO_TCP:
            memcpy(type_str, "TCP", INET6_ADDRSTRLEN * sizeof(char));
            break;
        case IPPROTO_UDP:
            memcpy(type_str, "UDP", INET6_ADDRSTRLEN * sizeof(char));
            break;
        case IPPROTO_IPV6:
            memcpy(type_str, "IPV6", INET6_ADDRSTRLEN * sizeof(char));
            break;
        default:
            memcpy(type_str, "Err", INET6_ADDRSTRLEN * sizeof(char));
    }
    return;
}

static void update_ipvs_collect_data(struct collect_value *dd)
{
    dd->link_count++;
    return;
}

static void update_ipvs_collect_map(const struct link_key *k, unsigned short protocol, const struct ip *laddr, int map_fd)
{
    struct collect_key      key = {0};
    struct collect_value    val = {0};

    /* build key */
    key.family = k->family;
    memcpy((char *)&key.c_addr, (char *)&k->c_addr, sizeof(struct ip));
    memcpy((char *)&key.v_addr, (char *)&k->v_addr, sizeof(struct ip));
    memcpy((char *)&key.s_addr, (char *)&k->s_addr, sizeof(struct ip));
    memcpy((char *)&key.l_addr, (char *)laddr, sizeof(struct ip));
    key.v_port = k->v_port;
    key.s_port = k->s_port;

    (void)bpf_map_lookup_elem(map_fd, &key, &val);
    update_ipvs_collect_data(&val);
    val.protocol = protocol;
    (void)bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);

    return;
}

static void pull_probe_data(int fd, int collect_fd)
{
    int ret = 0;
    struct link_key   key = {0};
    struct link_key   next_key = {0};
    struct link_value value;
    unsigned char ip_pro_str[INET6_ADDRSTRLEN];
    unsigned char cli_ip_str[INET6_ADDRSTRLEN];
    unsigned char vir_ip_str[INET6_ADDRSTRLEN];
    unsigned char loc_ip_str[INET6_ADDRSTRLEN];
    unsigned char src_ip_str[INET6_ADDRSTRLEN];

    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        ret = bpf_map_lookup_elem(fd, &next_key, &value);
        if (ret == 0) {
            ippro_to_str(value.protocol, ip_pro_str);
            ip_str(next_key.family, (unsigned char *)&(next_key.c_addr), cli_ip_str, INET6_ADDRSTRLEN);
            ip_str(next_key.family, (unsigned char *)&(next_key.v_addr), vir_ip_str, INET6_ADDRSTRLEN);
            ip_str(next_key.family, (unsigned char *)&(value.l_addr), loc_ip_str, INET6_ADDRSTRLEN);
            ip_str(next_key.family, (unsigned char *)&(next_key.s_addr), src_ip_str, INET6_ADDRSTRLEN);
            printf("LVS new connect protocol[%s] type[%s] c[%s:%d]--v[%s:%d]--l[%s:%d]--s[%s:%d] state[%d]. \n",
                ip_pro_str,
                (next_key.family == AF_INET) ? "IPv4" : "IPv6",
                cli_ip_str,
                ntohs(next_key.c_port),
                vir_ip_str,
                ntohs(next_key.v_port),
                loc_ip_str,
                ntohs(value.l_port),
                src_ip_str,
                ntohs(next_key.s_port),
                value.state);
            /* update collect map */
            update_ipvs_collect_map(&next_key, value.protocol, &value.l_addr, collect_fd);
        }
        if (value.state == IP_VS_TCP_S_CLOSE) {
            (void)bpf_map_delete_elem(fd, &next_key);
        } else {
            key = next_key;
        }
    }
}

static void print_ipvs_collect(int map_fd)
{
    int ret = 0;
    struct collect_key  key = {0};
    struct collect_key  next_key = {0};
    struct collect_value    value = {0};

    unsigned char cli_ip_str[INET6_ADDRSTRLEN];
    unsigned char vir_ip_str[INET6_ADDRSTRLEN];
    unsigned char loc_ip_str[INET6_ADDRSTRLEN];
    unsigned char src_ip_str[INET6_ADDRSTRLEN];

    while (bpf_map_get_next_key(map_fd, &key, &next_key) != -1) {
        ret = bpf_map_lookup_elem(map_fd, &next_key, &value);
        if (ret == 0) {
            ip_str(next_key.family, (unsigned char *)&(next_key.c_addr), cli_ip_str, INET6_ADDRSTRLEN);
            ip_str(next_key.family, (unsigned char *)&(next_key.v_addr), vir_ip_str, INET6_ADDRSTRLEN);
            ip_str(next_key.family, (unsigned char *)&(next_key.s_addr), src_ip_str, INET6_ADDRSTRLEN);
            ip_str(next_key.family, (unsigned char *)&(next_key.l_addr), loc_ip_str, INET6_ADDRSTRLEN);
            fprintf(stdout,
                "|%s|%s|%s|%s|%s|%s|%u|%u|%u|%llu|\n",
                METRIC_NAME_LVS_LINK,
                "ipvs",
                cli_ip_str,
                vir_ip_str,
                loc_ip_str,
                src_ip_str,
                ntohs(next_key.v_port),
                ntohs(next_key.s_port),
                value.protocol,
                value.link_count);

            DEBUG("collect c_ip[%s], v_ip[%s:%d] l_ip[%s] s_ip[%s:%d] link_count[%lld]. \n",
                cli_ip_str,
                vir_ip_str,
                ntohs(next_key.v_port),
                loc_ip_str,
                src_ip_str,
                ntohs(next_key.s_port),
                value.link_count);
        }
        (void)bpf_map_delete_elem(map_fd, &next_key);
    }
    (void)fflush(stdout);
    return;
}
#endif
int main(int argc, char **argv)
{
#ifdef KERNEL_SUPPORT_LVS
    int err = args_parse(argc, argv, &params);
    if (err != 0)
        return -1;

    printf("arg parse interval time:%us\n", params.period);

    INIT_BPF_APP(trace_lvs, EBPF_RLIM_LIMITED);
    LOAD(trace_lvs, trace_lvs, err);

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        goto err;
    }

    /* create collect hash map */
    int collect_map_fd =
        bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(struct collect_key),
                        sizeof(struct collect_value), IPVS_MAX_ENTRIES, 0);
    if (collect_map_fd < 0) {
        fprintf(stderr, "bpf_create_map collect map fd failed.\n");
        goto err;
    }

    printf("Successfully started! \n");

    while (stop == 0) {
        pull_probe_data(GET_MAP_FD(trace_lvs, lvs_link_map), collect_map_fd);
        print_ipvs_collect(collect_map_fd);
        sleep(params.period);
    }

err:
    UNLOAD(trace_lvs);
#else
    printf("Kernel not support lvs.\n");
#endif
    return 0;
}
