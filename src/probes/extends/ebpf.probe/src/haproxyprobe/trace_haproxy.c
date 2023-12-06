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
#include "ipc.h"
#include "trace_haproxy.skel.h"
#include "trace_haproxy.h"

#define METRIC_NAME_HAPROXY_LINK "haproxy_link"

struct haproxy_probe_s {
    struct ipc_body_s ipc_body;
    struct bpf_prog_s *prog;
    int collect_map_fd;
};

static struct haproxy_probe_s g_haproxy_probe = {0};
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
    if (fp == NULL) {
        return;
    }
    if (fgets(buffer, INET6_ADDRSTRLEN, fp) == NULL) {
        HAP_ERROR("Fail get_host_ip.\n");
        (void)pclose(fp);
        return;
    }
    (void)pclose(fp);
    num = sscanf(buffer, "%47s", (char *)value);
    if (num < 1)
        HAP_ERROR("failed get hostip [%d]", errno);

    return;
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

static int create_collect_map(void)
{
    int collect_map_fd;

    collect_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, NULL, sizeof(struct collect_key),
                                    sizeof(struct collect_value), METRIC_ENTRIES, NULL);
    if (collect_map_fd < 0) {
        HAP_ERROR("Failed to create collect map.\n");
        return -1;
    }

    g_haproxy_probe.collect_map_fd = collect_map_fd;
    return 0;
}

static int need_to_reload(struct ipc_body_s *ipc_body)
{
    if (strcmp(ipc_body->probe_param.elf_path, g_haproxy_probe.ipc_body.probe_param.elf_path) != 0) {
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
        HAP_WARN("Failed to load %s: exceed the maximum number of skeletons\n", elf_path);
        return -1;
    }

    INIT_OPEN_OPTS(trace_haproxy);
    PREPARE_CUSTOM_BTF(trace_haproxy);
    OPEN_OPTS(trace_haproxy, err, 1);

    LOAD_ATTACH(trace_haproxy, trace_haproxy, err, 1);

    UBPF_ATTACH(trace_haproxy, back_establish, elf_path, back_establish, succeed);
    if (!succeed) {
        goto err;
    }
    UBPF_ATTACH(trace_haproxy, stream_free, elf_path, stream_free, succeed);
    if (!succeed) {
        goto err;
    }

    prog->custom_btf_paths[prog->num] = trace_haproxy_open_opts.btf_custom_path;
    prog->skels[prog->num].skel = (void *)trace_haproxy_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)trace_haproxy_bpf__destroy;
    for (i = 0; i < trace_haproxy_link_current; i++) {
        prog->skels[prog->num]._link[link_num++] = (void *)trace_haproxy_link[i];
    }
    prog->num++;

    return 0;
err:
    UNLOAD(trace_haproxy);
    CLEANUP_CUSTOM_BTF(trace_haproxy);
    return -1;
}

int load_haproxy_bpf_prog(struct ipc_body_s *ipc_body)
{
    struct bpf_prog_s *prog;
    char *elfs[PATH_NUM] = {0};
    int elf_num = -1;
    int ret;

    prog = alloc_bpf_prog();
    if (prog == NULL) {
        HAP_ERROR("Failed to allocate bpf prog\n");
        return -1;
    }

    /* Find elf's abs_path */
    elf_num = get_exec_file_path("haproxy", (const char *)ipc_body->probe_param.elf_path, NULL, elfs, PATH_NUM);
    if (elf_num <= 0) {
        HAP_ERROR("Failed to get execute path of haproxy program.\n");
        free_exec_path_buf(elfs, elf_num);
        free_bpf_prog(prog);
        return -1;
    }

    for (int i = 0; i < elf_num; i++) {
        ret = load_bpf_prog_each_elf(prog, elfs[i]);
        if (ret) {
            HAP_ERROR("Failed to load bpf program from path: %s\n", elfs[i]);
            continue;
        }
        HAP_INFO("Succeed to load bpf program from path: %s\n", elfs[i]);
    }
    free_exec_path_buf(elfs, elf_num);

    if (prog->num == 0) {
        HAP_ERROR("No available bpf program loaded successfully.\n");
        free_bpf_prog(prog);
        return -1;
    }

    g_haproxy_probe.prog = prog;
    return 0;
}

static int reload_haproxy_bpf_prog(struct ipc_body_s *ipc_body)
{
    int ret;

    if (g_haproxy_probe.prog != NULL && !need_to_reload(ipc_body)) {
        return 0;
    }

    HAP_INFO("Start to reload haproxy bpf program...\n");
    unload_bpf_prog(&g_haproxy_probe.prog);
    ret = load_haproxy_bpf_prog(ipc_body);
    if (ret) {
        return -1;
    }
    HAP_INFO("Succeed to reload haproxy bpf program.\n");

    return 0;
}

static void pull_all_probe_data(void)
{
    int i;
    struct bpf_prog_s *prog = g_haproxy_probe.prog;

    for (i = 0; i < prog->num; i++) {
        pull_probe_data(GET_MAP_FD_BY_SKEL(prog->skels[i].skel, trace_haproxy, haproxy_link_map),
                        g_haproxy_probe.collect_map_fd);
    }
}

static void clean_haproxy_probe(void)
{
    unload_bpf_prog(&g_haproxy_probe.prog);

    if (g_haproxy_probe.collect_map_fd > 0) {
        close(g_haproxy_probe.collect_map_fd);
    }

    destroy_ipc_body(&g_haproxy_probe.ipc_body);
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

    INIT_BPF_APP(trace_haproxy, EBPF_RLIM_LIMITED);

    if (create_collect_map()) {
        return -1;
    }
    HAP_INFO("Haproxy probe started Successfully.\n");

    while (!g_stop) {
        err = recv_ipc_msg(msq_id, (long)PROBE_HAPROXY, &ipc_body);
        if (err == 0) {
            err = reload_haproxy_bpf_prog(&ipc_body);
            if (err) {
                destroy_ipc_body(&ipc_body);
                goto err;
            }

            destroy_ipc_body(&g_haproxy_probe.ipc_body);
            (void)memcpy(&g_haproxy_probe.ipc_body, &ipc_body, sizeof(struct ipc_body_s));
        }

        if (g_haproxy_probe.prog == NULL) {
            sleep(DEFAULT_PERIOD);
            continue;
        }

        pull_all_probe_data();
        print_haproxy_collect(g_haproxy_probe.collect_map_fd);
        sleep(g_haproxy_probe.ipc_body.probe_param.period);
    }

    err = 0;
err:
    clean_haproxy_probe();
    return err;
}
