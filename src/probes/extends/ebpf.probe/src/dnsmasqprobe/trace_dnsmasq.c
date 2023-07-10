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
#include "ipc.h"
#include "trace_dnsmasq.skel.h"
#include "trace_dnsmasq.h"

#define METRIC_NAME_DNSMASQ_LINK    "dnsmasq_link"

struct dnsmasq_probe_s {
    struct ipc_body_s ipc_body;
    struct bpf_prog_s *prog;
    int collect_map_fd;
};

static struct dnsmasq_probe_s g_dnsmasq_probe = {0};
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

static int create_collect_map(void)
{
    int collect_map_fd;

#if (CURRENT_LIBBPF_VERSION  >= LIBBPF_VERSION(0, 8))
    collect_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, NULL, sizeof(struct collect_key),
                                    sizeof(struct collect_value), METRIC_ENTRIES, NULL);
#else
    collect_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(struct collect_key),
                                    sizeof(struct collect_value), METRIC_ENTRIES, 0);
#endif
    if (collect_map_fd < 0) {
        DNS_ERROR("Failed to create collect map.\n");
        return -1;
    }

    g_dnsmasq_probe.collect_map_fd = collect_map_fd;
    return 0;
}

static int need_to_reload(struct ipc_body_s *ipc_body)
{
    if (strcmp(ipc_body->probe_param.elf_path, g_dnsmasq_probe.ipc_body.probe_param.elf_path) != 0) {
        return 1;
    }
    return 0;
}

int load_bpf_prog_each_elf(struct bpf_prog_s *prog, const char *elf_path)
{
    int succeed;
    int link_num = 0;
    int i;

    if (prog->num >= SKEL_MAX_NUM) {
        DNS_WARN("Failed to load %s: exceed the maximum number of skeletons\n", elf_path);
        return -1;
    }

    LOAD(trace_dnsmasq, trace_dnsmasq, err);

    UBPF_ATTACH(trace_dnsmasq, send_from, elf_path, send_from, succeed);
    if (!succeed) {
        goto err;
    }

    prog->skels[prog->num].skel = (void *)trace_dnsmasq_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)trace_dnsmasq_bpf__destroy;
    for (i = 0; i < trace_dnsmasq_link_current; i++) {
        prog->skels[prog->num]._link[link_num++] = (void *)trace_dnsmasq_link[i];
    }
    prog->num++;

    return 0;
err:
    UNLOAD(trace_dnsmasq);
    return -1;
}

int load_dnsmasq_bpf_prog(struct ipc_body_s *ipc_body)
{
    struct bpf_prog_s *prog;
    char *elfs[PATH_NUM] = {0};
    int elf_num = -1;
    int ret;

    prog = alloc_bpf_prog();
    if (prog == NULL) {
        DNS_ERROR("Failed to allocate bpf prog\n");
        return -1;
    }

    /* Find elf's abs_path */
    elf_num = get_exec_file_path("dnsmasq", (const char *)ipc_body->probe_param.elf_path, NULL, elfs, PATH_NUM);
    if (elf_num <= 0) {
        DNS_ERROR("Failed to get execute path of dnsmasq program.\n");
        free_exec_path_buf(elfs, elf_num);
        free_bpf_prog(prog);
        return -1;
    }

    for (int i = 0; i < elf_num; i++) {
        ret = load_bpf_prog_each_elf(prog, elfs[i]);
        if (ret) {
            DNS_ERROR("Failed to load bpf program from path: %s\n", elfs[i]);
            continue;
        }
        DNS_INFO("Succeed to load bpf program from path: %s\n", elfs[i]);
    }
    free_exec_path_buf(elfs, elf_num);

    if (prog->num == 0) {
        DNS_ERROR("No available bpf program loaded successfully.\n");
        free_bpf_prog(prog);
        return -1;
    }

    g_dnsmasq_probe.prog = prog;
    return 0;
}

static int reload_dnsmasq_bpf_prog(struct ipc_body_s *ipc_body)
{
    int ret;

    if (g_dnsmasq_probe.prog != NULL && !need_to_reload(ipc_body)) {
        return 0;
    }

    DNS_INFO("Start to reload dnsmasq bpf program...\n");
    unload_bpf_prog(&g_dnsmasq_probe.prog);
    ret = load_dnsmasq_bpf_prog(ipc_body);
    if (ret) {
        return -1;
    }
    DNS_INFO("Succeed to reload dnsmasq bpf program.\n");

    return 0;
}

static void pull_all_probe_data(void)
{
    int i;
    struct bpf_prog_s *prog = g_dnsmasq_probe.prog;

    for (i = 0; i < prog->num; i++) {
        pull_probe_data(GET_MAP_FD_BY_SKEL(prog->skels[i].skel, trace_dnsmasq, dns_query_link_map),
                        g_dnsmasq_probe.collect_map_fd);
    }
}

static void clean_dnsmasq_probe(void)
{
    unload_bpf_prog(&g_dnsmasq_probe.prog);

    if (g_dnsmasq_probe.collect_map_fd > 0) {
        close(g_dnsmasq_probe.collect_map_fd);
    }

    destroy_ipc_body(&g_dnsmasq_probe.ipc_body);
}

int main(int argc, char **argv)
{
    int err = -1;
    struct ipc_body_s ipc_body;
    int msq_id;

    msq_id = create_ipc_msg_queue(IPC_EXCL);
    if (msq_id < 0) {
        return -1;
    }

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    INIT_BPF_APP(trace_dnsmasq, EBPF_RLIM_LIMITED);

    if (create_collect_map()) {
        return -1;
    }
    DNS_INFO("Dnsmasq probe started Successfully.\n");

    while (!g_stop) {
        err = recv_ipc_msg(msq_id, (long)PROBE_DNSMASQ, &ipc_body);
        if (err == 0) {
            err = reload_dnsmasq_bpf_prog(&ipc_body);
            if (err) {
                destroy_ipc_body(&ipc_body);
                goto err;
            }

            destroy_ipc_body(&g_dnsmasq_probe.ipc_body);
            (void)memcpy(&g_dnsmasq_probe.ipc_body, &ipc_body, sizeof(struct ipc_body_s));
        }

        if (g_dnsmasq_probe.prog == NULL) {
            sleep(DEFAULT_PERIOD);
            continue;
        }

        pull_all_probe_data();
        print_dnsmasq_collect(g_dnsmasq_probe.collect_map_fd);
        sleep(g_dnsmasq_probe.ipc_body.probe_param.period);
    }

    err = 0;
err:
    clean_dnsmasq_probe();
    return err;
}
