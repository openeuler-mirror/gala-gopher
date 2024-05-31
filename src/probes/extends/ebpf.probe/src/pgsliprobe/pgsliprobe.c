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
 * Author: wo_cow
 * Create: 2022-7-29
 * Description: pgsliprobe probe user prog
 ******************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "args.h"
#include "event.h"
#include "ipc.h"
#include "hash.h"
#include "pgsli_kprobe.skel.h"
#include "pgsli_uprobe.skel.h"
#include "tc_loader.h"
#include "container.h"
#include "feat_probe.h"
#include "pgsliprobe.h"

#define OO_NAME "sli"
#define SLI_TBL_NAME "pg_sli"
#define MAX_SLI_TBL_NAME "pg_max_sli"
#define GUASSDB_COMM "gaussdb"

#define PID_COMM_COMMAND "ps -e -o pid,comm | grep %s | awk '{print $1}'"

#define R_OK    4

#define PGSLI_ARGS_PATH          "/sys/fs/bpf/gala-gopher/__pgsli_args"
#define PGSLI_CONN_PATH          "/sys/fs/bpf/gala-gopher/__pgsli_conn"
#define PGSLI_CONN_SAMP_PATH     "/sys/fs/bpf/gala-gopher/__pgsli_conn_samp"
#define PGSLI_OUTPUT_PATH        "/sys/fs/bpf/gala-gopher/__pgsli_output"

#define RM_PGSLI_PATH "/usr/bin/rm -rf /sys/fs/bpf/gala-gopher/__pgsli*"

#define OPEN_PROBE(probe_name, end, load) \
        INIT_OPEN_OPTS(probe_name); \
        PREPARE_CUSTOM_BTF(probe_name); \
        OPEN_OPTS(probe_name, end, load); \
        MAP_SET_PIN_PATH(probe_name, args_map, PGSLI_ARGS_PATH, load); \
        MAP_SET_PIN_PATH(probe_name, conn_map, PGSLI_CONN_PATH, load); \
        MAP_SET_PIN_PATH(probe_name, conn_samp_map, PGSLI_CONN_SAMP_PATH, load); \
        MAP_SET_PIN_PATH(probe_name, output, PGSLI_OUTPUT_PATH, load);

struct pgsli_probe_s {
    struct ipc_body_s ipc_body;
    struct bpf_prog_s* kern_prog;
    struct bpf_prog_s* libssl_prog;
    int args_map_fd;
};

static struct pgsli_probe_s g_pgsli_probe = {0};
static volatile sig_atomic_t stop;
static struct bpf_link_hash_t *head = NULL;
static int noDependLibssl;

enum pid_state_t {
    PID_NOEXIST,
    PID_ELF_TOBE_ATTACHED,
    PID_ELF_ATTACHED
};

#define __ENTITY_ID_LEN 128

struct bpf_link_hash_value {
    enum pid_state_t pid_state;
    char elf_path[MAX_PATH_LEN];
    struct bpf_link *bpf_link_read;
    struct bpf_link *bpf_link_read_ret;
    struct bpf_link *bpf_link_write;
};

struct bpf_link_hash_t {
    H_HANDLE;
    unsigned int pid; // key
    struct bpf_link_hash_value v; // value
};

static void sig_int(int signo)
{
    stop = 1;
}

static void report_sli_event(struct msg_event_data_t *msg_evt_data)
{
#ifdef ENABLE_REPORT_EVENT
    char entityId[__ENTITY_ID_LEN];
    u64 latency_thr_ns = MS2NS(g_pgsli_probe.ipc_body.probe_param.latency_thr);
    unsigned char ser_ip_str[INET6_ADDRSTRLEN];
    unsigned char cli_ip_str[INET6_ADDRSTRLEN];
    struct event_info_s evt = {0};

    entityId[0] = 0;
    (void)snprintf(entityId, __ENTITY_ID_LEN, "%d_%d",
        msg_evt_data->tgid,
        msg_evt_data->fd);

    if ((latency_thr_ns > 0) && (latency_thr_ns < msg_evt_data->latency.rtt_nsec)) {
        ip_str(msg_evt_data->conn_info.server_ip_info.family, (unsigned char *)&(msg_evt_data->conn_info.server_ip_info.ipaddr),
            ser_ip_str, INET6_ADDRSTRLEN);
        ip_str(msg_evt_data->conn_info.client_ip_info.family, (unsigned char *)&(msg_evt_data->conn_info.client_ip_info.ipaddr),
            cli_ip_str, INET6_ADDRSTRLEN);

        evt.entityName = OO_NAME;
        evt.entityId = entityId;
        evt.metrics = "rtt_nsec";
        evt.pid = (int)msg_evt_data->tgid;
        (void)snprintf(evt.ip, EVT_IP_LEN, "CIP(%s:%u), SIP(%s:%u)",
                       cli_ip_str,
                       ntohs(msg_evt_data->conn_info.client_ip_info.port),
                       ser_ip_str,
                       msg_evt_data->conn_info.server_ip_info.port);

        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "Process(TID:%d, CIP(%s:%u), SIP(%s:%u)) SLI(%s:%llu) exceed the threshold.",
                    msg_evt_data->tgid,
                    cli_ip_str,
                    ntohs(msg_evt_data->conn_info.client_ip_info.port),
                    ser_ip_str,
                    msg_evt_data->conn_info.server_ip_info.port,
                    msg_evt_data->latency.req_cmd,
                    msg_evt_data->latency.rtt_nsec);
    }
#endif
    return;
}

static int msg_event_handler(void *ctx, void *data, unsigned int size)
{
    struct msg_event_data_t *msg_evt_data = (struct msg_event_data_t *)data;
    unsigned char ser_ip_str[INET6_ADDRSTRLEN];
    unsigned char cli_ip_str[INET6_ADDRSTRLEN];

    report_sli_event(msg_evt_data);

    ip_str(msg_evt_data->conn_info.server_ip_info.family, (unsigned char *)&(msg_evt_data->conn_info.server_ip_info.ipaddr),
        ser_ip_str, INET6_ADDRSTRLEN);
    ip_str(msg_evt_data->conn_info.client_ip_info.family, (unsigned char *)&(msg_evt_data->conn_info.client_ip_info.ipaddr),
        cli_ip_str, INET6_ADDRSTRLEN);
    fprintf(stdout,
            "|%s|%d|%d|%s|%c|%s|%u|%s|%u|%llu|\n",
            SLI_TBL_NAME,
            msg_evt_data->tgid,
            msg_evt_data->fd,
            "POSTGRE",
            msg_evt_data->latency.req_cmd,
            ser_ip_str,
            msg_evt_data->conn_info.server_ip_info.port,
            cli_ip_str,
            ntohs(msg_evt_data->conn_info.client_ip_info.port),
            msg_evt_data->latency.rtt_nsec);
    fprintf(stdout,
            "|%s|%d|%d|%s|%c|%s|%u|%s|%u|%llu|\n",
            MAX_SLI_TBL_NAME,
            msg_evt_data->tgid,
            msg_evt_data->fd,
            "POSTGRE",
            msg_evt_data->max.req_cmd,
            ser_ip_str,
            msg_evt_data->conn_info.server_ip_info.port,
            cli_ip_str,
            ntohs(msg_evt_data->conn_info.client_ip_info.port),
            msg_evt_data->max.rtt_nsec);
    (void)fflush(stdout);

    return 0;
}

static void *msg_event_receiver(void *arg)
{
    if (g_pgsli_probe.kern_prog->buffer == NULL) {
        goto err;
    }

    int ret;
    while ((ret = bpf_buffer__poll(g_pgsli_probe.kern_prog->buffer, THOUSAND)) >= 0 || ret == -EINTR) {
        ;
    }
err:
    stop = 1;
    PGSLI_INFO("msg_event_receiver out\n");
    return NULL;
}

static int init_conn_mgt_process()
{
    int err;
    pthread_t msg_evt_hdl_thd;

    err = pthread_create(&msg_evt_hdl_thd, NULL, msg_event_receiver, NULL);
    if (err != 0) {
        PGSLI_ERROR("Failed to create connection read/write message event handler thread.\n");
        return -1;
    }
    (void)pthread_detach(msg_evt_hdl_thd);
    PGSLI_INFO("Connection read/write message event handler thread successfully started!\n");

    return 0;
}

static void load_args(int args_fd, struct probe_params* params)
{
    __u32 key = 0;
    struct ogsli_args_s args = {0};

    args.period = NS(params->period);

    (void)bpf_map_update_elem(args_fd, &key, &args, BPF_ANY);
}


static struct bpf_link_hash_t* find_bpf_link(unsigned int pid)
{
    struct bpf_link_hash_t *item = NULL;

    if (head == NULL) {
        return NULL;
    }
    H_FIND(head, &pid, sizeof(unsigned int), item);
    if (item == NULL) {
        return NULL;
    }

    if (item->v.bpf_link_read == NULL) {
        item->v.pid_state = PID_ELF_TOBE_ATTACHED;
    } else {
        item->v.pid_state = PID_ELF_ATTACHED;
    }

    return item;
}


static int add_bpf_link(unsigned int pidd)
{
    struct bpf_link_hash_t *item = malloc(sizeof(struct bpf_link_hash_t));
    if (item == NULL) {
        PGSLI_ERROR("malloc bpf link %u failed\n", pidd);
        return SLI_ERR;
    }
    (void)memset(item, 0, sizeof(struct bpf_link_hash_t));
    int ret = get_elf_path(pidd, item->v.elf_path, MAX_PATH_LEN, "libssl");
    if (ret == CONTAINER_ERR) {
        free(item);
        return SLI_ERR;
    } else if (ret == CONTAINER_NOTOK) {
        noDependLibssl = 1;
        free(item);
        return SLI_ERR;
    }

    item->pid = pidd;
    item->v.pid_state = PID_ELF_TOBE_ATTACHED;
    H_ADD(head, pid, sizeof(unsigned int), item);

    return SLI_OK;
}

/*
[root@localhost ~]# ps -e -o pid,comm | grep gaussdb | awk '{print $1}'
*/
static int add_bpf_link_by_search_pids()
{
    unsigned int pid = 0;
    char cmd[COMMAND_LEN] = {0};
    char line[LINE_BUF_LEN] = {0};
    FILE *f;
    int ret = SLI_OK;

    (void)snprintf(cmd, COMMAND_LEN, PID_COMM_COMMAND, GUASSDB_COMM);
    f = popen(cmd, "r");
    if (f == NULL) {
        PGSLI_ERROR("get pid of gaussdb failed.\n");
        return SLI_ERR;
    }

    // Traverse the gaussdb process to attach libssl
    while (!feof(f)) {
        line[0] = 0;
        if (fgets(line, LINE_BUF_LEN, f) == NULL) {
            continue;
        }
        pid = strtoul(line, NULL, 10);
        if (pid <= 0) {
            continue;
        }
        // find_bpf_link and add_bpf_link will set bpf_link status
        if (!find_bpf_link(pid)) {
            if (add_bpf_link(pid) != SLI_OK) {
                if (noDependLibssl) {
                    goto out;
                }
                PGSLI_ERROR("add_bpf_link of pid %u failed\n", pid);
            } else {
                PGSLI_INFO("add_bpf_link of pid %u success\n", pid);
            }
        }
    }
out:
    (void)pclose(f);
    return ret;
}

static void set_bpf_link_inactive()
{
    struct bpf_link_hash_t *item, *tmp;
    if (head == NULL) {
        return;
    }

    H_ITER(head, item, tmp) {
        item->v.pid_state = PID_NOEXIST;
    }
}

static void clear_invalid_bpf_link()
{
    struct bpf_link_hash_t *item, *tmp;
    if (head == NULL) {
        return;
    }
    H_ITER(head, item, tmp) {
        if (item->v.pid_state == PID_NOEXIST) {
            PGSLI_INFO("clear bpf link of pid %u\n", item->pid);
            H_DEL(head, item);
            (void)free(item);
        }
    }
}

static void clear_all_bpf_link()
{
    struct bpf_link_hash_t *item, *tmp;
    if (head == NULL) {
        return;
    }
    H_ITER(head, item, tmp) {
        UNATTACH_ONELINK(pgsli_uprobe, item->v.bpf_link_read);
        UNATTACH_ONELINK(pgsli_uprobe, item->v.bpf_link_read_ret);
        UNATTACH_ONELINK(pgsli_uprobe, item->v.bpf_link_write);
        H_DEL(head, item);
        (void)free(item);
    }
}

static void reload_tc_bpf(struct ipc_body_s* ipc_body)
{
    if (strcmp(g_pgsli_probe.ipc_body.probe_param.target_dev, ipc_body->probe_param.target_dev) != 0) {
        offload_tc_bpf(TC_TYPE_INGRESS);
        load_tc_bpf(ipc_body->probe_param.target_dev, TC_TSTAMP_PROG, TC_TYPE_INGRESS);
    }
    return;
}

static void clean_map_files()
{
    FILE *fp = NULL;

    fp = popen(RM_PGSLI_PATH, "r");
    if (fp != NULL) {
        (void)pclose(fp);
    }
}

static int bpf_attach_to_libssl(struct pgsli_uprobe_bpf *pgsli_uprobe_skel)
{
    struct bpf_link_hash_t *item, *tmp;
    int ret;

    H_ITER(head, item, tmp) {
        if (item->v.pid_state == PID_ELF_TOBE_ATTACHED) {
            UBPF_ATTACH_ONELINK(pgsli_uprobe, SSL_read, item->v.elf_path, SSL_read,
                item->v.bpf_link_read, ret);
            if (ret <= 0) {
                PGSLI_ERROR("Can't attach function SSL_read at elf_path %s.\n", item->v.elf_path);
                return -1;
            }
            UBPF_RET_ATTACH_ONELINK(pgsli_uprobe, SSL_read, item->v.elf_path, SSL_read,
                item->v.bpf_link_read_ret, ret);
            if (ret <= 0) {
                PGSLI_ERROR("Can't attach ret function SSL_read at elf_path %s.\n", item->v.elf_path);
                return -1;
            }
            UBPF_ATTACH_ONELINK(pgsli_uprobe, SSL_write, item->v.elf_path, SSL_write,
                item->v.bpf_link_write, ret);
            if (ret <= 0) {
                PGSLI_ERROR("Can't attach function SSL_write at elf_path %s.\n", item->v.elf_path);
                return -1;
            }
            item->v.pid_state = PID_ELF_ATTACHED;
        }
    }

    return 0;
}

static int load_pgsli_libssl_prog(void)
{
    struct bpf_prog_s *prog;
    struct bpf_buffer *buffer = NULL;
    prog = alloc_bpf_prog();
    if (prog == NULL) {
        return -1;
    }

    OPEN_PROBE(pgsli_uprobe, err, 1);
    prog->skels[prog->num].skel = pgsli_uprobe_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)pgsli_uprobe_bpf__destroy;
    prog->custom_btf_paths[prog->num] = pgsli_uprobe_open_opts.btf_custom_path;

    MAP_INIT_BPF_BUFFER(pgsli_uprobe, output, buffer, 1);
    LOAD_ATTACH(pgsliprobe, pgsli_uprobe, err, 1);
    prog->buffer = buffer;

    prog->num++;
    g_pgsli_probe.libssl_prog = prog;

    return 0;
err:
    bpf_buffer__free(buffer);
    UNLOAD(pgsli_uprobe);
    CLEANUP_CUSTOM_BTF(pgsli_uprobe);
    if (prog) {
        free_bpf_prog(prog);
    }
    return -1;
}

static int load_pgsli_kern_prog(void)
{
    struct bpf_prog_s *prog;
    int ret, args_map_fd;
    struct bpf_buffer *buffer = NULL;

    prog = alloc_bpf_prog();
    if (prog == NULL) {
        return -1;
    }

    OPEN_PROBE(pgsli_kprobe, err, 1);
    prog->skels[prog->num].skel = pgsli_kprobe_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)pgsli_kprobe_bpf__destroy;
    prog->custom_btf_paths[prog->num] = pgsli_kprobe_open_opts.btf_custom_path;

    bool is_load = probe_kernel_version() > KERNEL_VERSION(5, 12, 0);
    PROG_ENABLE_ONLY_IF(pgsli_kprobe, bpf_constprop_tcp_clean_rtx_queue, is_load);
    PROG_ENABLE_ONLY_IF(pgsli_kprobe, bpf_tcp_clean_rtx_queue, !is_load);

    is_load = probe_kernel_version() >= KERNEL_VERSION(5, 11, 0);
    PROG_ENABLE_ONLY_IF(pgsli_kprobe, bpf_close_fd, is_load);
    PROG_ENABLE_ONLY_IF(pgsli_kprobe, bpf___close_fd, !is_load);

    PROG_ENABLE_ONLY_IF(pgsli_kprobe, bpf_tcp_recvmsg, probe_tstamp());

    MAP_INIT_BPF_BUFFER(pgsli_kprobe, output, buffer, 1);

    LOAD_ATTACH(pgsliprobe, pgsli_kprobe, err, 1);

    ret = bpf_buffer__open(buffer, msg_event_handler, NULL, NULL);
    if (ret) {
        ERROR("[PGSLIPROBE] Open 'PGSLI' bpf_buffer failed.\n");
        goto err;
    }

    args_map_fd = GET_MAP_FD(pgsli_kprobe, args_map);
    if (args_map_fd <= 0) {
        PGSLI_ERROR("Failed to get bpf prog args map fd.\n");
        goto err;
    }

    prog->buffer = buffer;
    prog->num++;
    g_pgsli_probe.kern_prog = prog;
    g_pgsli_probe.args_map_fd = args_map_fd;

    return 0;
err:
    bpf_buffer__free(buffer);
    UNLOAD(pgsli_kprobe);
    CLEANUP_CUSTOM_BTF(pgsli_kprobe);
    if (prog) {
        free_bpf_prog(prog);
    }
    return -1;
}

static void clean_pgsli_probe(void)
{
    unload_bpf_prog(&g_pgsli_probe.kern_prog);
    unload_bpf_prog(&g_pgsli_probe.libssl_prog);
    destroy_ipc_body(&g_pgsli_probe.ipc_body);
}

static int init_probe_first_load(bool is_first_load)
{
    int err;

    if (!is_first_load) {
        return 0;
    }

    err = load_pgsli_kern_prog();
    if (err) {
        return err;
    }
    err = load_pgsli_libssl_prog();
    if (err) {
        return err;
    }

    return 0;
}

static int init_conn_mgt_first_load(bool is_first_load)
{
    int err;

    if (!is_first_load) {
        return 0;
    }

    err = init_conn_mgt_process();
    if (err != 0) {
        return err;
    }

    return 0;
}

static int update_bpf_link()
{
    int ret;

    set_bpf_link_inactive();
    if (add_bpf_link_by_search_pids() != SLI_OK) {
        if (!noDependLibssl) {
            return -1;
        }
    } else {
        ret = bpf_attach_to_libssl((struct pgsli_uprobe_bpf *)g_pgsli_probe.libssl_prog->skels[0].skel);
        if (ret) {
            return -1;
        }
        clear_invalid_bpf_link();
    }

    return 0;
}

int main(int argc, char **argv)
{
    int err;
    struct ipc_body_s ipc_body;
    int msq_id;
    bool is_first_load = true;
    bool supports_tstamp;

    supports_tstamp = probe_tstamp();

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        PGSLI_ERROR("Can't set signal handler\n");
        return -1;
    }

    msq_id = create_ipc_msg_queue(IPC_EXCL);
    if (msq_id < 0) {
        ERROR("[PGSLIPROBE] Get ipc msg queue failed.\n");
        return -1;
    }

    clean_map_files();
    INIT_BPF_APP(pgsliprobe, EBPF_RLIM_LIMITED);
    if (!supports_tstamp) {
        PGSLI_INFO("The kernel version does not support loading the tc tstamp program\n");
    }

    PGSLI_INFO("pgsliprobe probe successfully started!\n");

    while (!stop) {
        err = recv_ipc_msg(msq_id, (long)PROBE_POSTGRE_SLI, &ipc_body);
        if (err == 0) {
            if (supports_tstamp) {
                reload_tc_bpf(&ipc_body);
            }

            err = init_probe_first_load(is_first_load);
            if (err) {
                PGSLI_ERROR("init_probe_first_load err\n");
                destroy_ipc_body(&ipc_body);
                goto err;
            }

            load_args(g_pgsli_probe.args_map_fd, &ipc_body.probe_param);
            destroy_ipc_body(&g_pgsli_probe.ipc_body);
            (void)memcpy(&g_pgsli_probe.ipc_body, &ipc_body, sizeof(struct ipc_body_s));

            err = init_conn_mgt_first_load(is_first_load);
            if (err) {
                PGSLI_ERROR("init_conn_mgt_first_load err\n");
                goto err;
            }
            is_first_load = false;
        }

        if (g_pgsli_probe.kern_prog == NULL || g_pgsli_probe.libssl_prog == NULL) {
            sleep(DEFAULT_PERIOD);
            continue;
        }

        if (!noDependLibssl) {
            err = update_bpf_link();
            if (err) {
                PGSLI_ERROR("update_bpf_link err\n");
                goto err;
            }
        }
        sleep(g_pgsli_probe.ipc_body.probe_param.period);
    }

    err = 0;
err:
    PGSLI_INFO("pgsliprobe probe end\n");
    clear_all_bpf_link();
    clean_pgsli_probe();
    if (supports_tstamp) {
        offload_tc_bpf(TC_TYPE_INGRESS);
    }
    clean_map_files();
    return err;
}
