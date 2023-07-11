/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wo_cow
 * Create: 2023-02-20
 * Description: l7probe probe main program
 ******************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sched.h>
#include <fcntl.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "ipc.h"
#include "syscall.h"
#include "tcp.h"

#include "container.h"
#include "l7_common.h"
#include "include/bpf_mng.h"
#include "include/java_mng.h"

volatile sig_atomic_t g_stop;
static struct l7_mng_s g_l7_mng;

static void sig_int(int signo)
{
    g_stop = 1;
}

static void __do_l7_load_tcp_fd(int fd)
{
    int i, j;
    int role;
    struct tcp_listen_ports* tlps;
    struct tcp_estabs* tes = NULL;
    struct conn_id_s k;

    tlps = get_listen_ports();
    if (tlps == NULL) {
        goto err;
    }

    tes = get_estab_tcps(tlps);
    if (tes == NULL) {
        goto err;
    }

    /* create established tcp item */
    for (i = 0; i < tes->te_num; i++) {
        role = tes->te[i]->is_client == 1 ? 0 : 1;
        for (j = 0; j < tes->te[i]->te_comm_num; j++) {
            k.tgid = (u32)tes->te[i]->te_comm[j]->pid;
            k.fd = (u32)tes->te[i]->te_comm[j]->fd;
            (void)bpf_map_update_elem(fd, &k, &role, BPF_ANY);
        }
    }

err:
    if (tlps) {
        free_listen_ports(&tlps);
    }

    if (tes) {
        free_estab_tcps(&tes);
    }

    return;
}

static int do_l7_load_tcp_fd(int fd, const char *container_id, int netns_fd)
{
    int ret;

    if (container_id) {
        ret = enter_container_netns(container_id);
        if (ret) {
            ERROR("[L7PROBE]: Enter container netns failed.(%s, ret = %d)\n",
                container_id, ret);
            return ret;
        }
    }

    __do_l7_load_tcp_fd(fd);

    if (container_id) {
        (void)exit_container_netns(netns_fd);
    }
    return 0;
}

static int get_netns_fd(pid_t pid)
{
    const char *fmt = "/proc/%u/ns/net";
    char path[PATH_LEN];

    path[0] = 0;
    (void)snprintf(path, PATH_LEN, fmt, pid);
    return open(path, O_RDONLY);
}

static void l7_unload_tcp_fd(struct l7_mng_s *l7_mng)
{
    struct conn_id_s connect_id = {0}, next_connect_id = {0};
    while (bpf_map_get_next_key(l7_mng->bpf_progs.l7_tcp_fd, &connect_id, &next_connect_id) == 0) {
        bpf_map_delete_elem(l7_mng->bpf_progs.l7_tcp_fd, &next_connect_id);
        connect_id = next_connect_id;
    }
}

static int l7_load_tcp_fd(struct l7_mng_s *l7_mng)
{
    char *container_id;
    int netns_fd = 0;
    struct ipc_body_s *ipc_body = &(l7_mng->ipc_body);

    netns_fd = get_netns_fd(getpid());
    if (netns_fd <= 0) {
        ERROR("[L7PROBE]: Get netns fd failed.\n");
        return -1;
    }

    for (int i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        if (ipc_body->snooper_objs[i].type == SNOOPER_OBJ_CON) {
            container_id = ipc_body->snooper_objs[i].obj.con_info.con_id;
            if (!container_id) {
                continue;
            }

            do_l7_load_tcp_fd(l7_mng->bpf_progs.l7_tcp_fd, container_id, netns_fd);
        }
    }

    (void)do_l7_load_tcp_fd(l7_mng->bpf_progs.l7_tcp_fd, NULL, netns_fd);
    (void)close(netns_fd);
    return 0;
}

static int __add_libssl_prog(struct l7_mng_s *l7_mng, struct bpf_prog_s *prog, const char *libssl)
{
    for (int i = 0; i < LIBSSL_EBPF_PROG_MAX; i++) {
        if (l7_mng->bpf_progs.libssl_progs[i].prog == NULL) {
            l7_mng->bpf_progs.libssl_progs[i].prog = prog;
            l7_mng->bpf_progs.libssl_progs[i].libssl_path = strdup(libssl);
            return 0;
        }
    }
    return -1;
}

static char __is_exist_libssl_prog(struct l7_mng_s *l7_mng, const char *libssl)
{
    for (int i = 0; i < LIBSSL_EBPF_PROG_MAX; i++) {
        if (l7_mng->bpf_progs.libssl_progs[i].libssl_path
            && !strcmp(libssl, l7_mng->bpf_progs.libssl_progs[i].libssl_path)) {
            return 1;
        }
    }
    return 0;
}

static void unload_l7_prog(struct l7_mng_s *l7_mng)
{
    unload_bpf_prog(&(l7_mng->bpf_progs.kern_sock_prog));

    for (int i = 0; i < LIBSSL_EBPF_PROG_MAX; i++) {
        unload_bpf_prog(&(l7_mng->bpf_progs.libssl_progs[i].prog));
        if (l7_mng->bpf_progs.libssl_progs[i].libssl_path != NULL) {
            (void)free(l7_mng->bpf_progs.libssl_progs[i].libssl_path);
            l7_mng->bpf_progs.libssl_progs[i].libssl_path = NULL;
        }
    }
    return;
}

static int load_l7_prog(struct l7_mng_s *l7_mng)
{
    int ret;
    struct bpf_prog_s *prog;
    struct ipc_body_s *ipc_body = &(l7_mng->ipc_body);
    char libssl[PATH_LEN];
    char *path;

    prog = alloc_bpf_prog();
    if (prog == NULL) {
        goto err;
    }

    ret = l7_load_probe_kern_sock(l7_mng, prog);
    if (ret) {
        goto err;
    }
    l7_mng->bpf_progs.kern_sock_prog = prog;

    for (int i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        path = NULL;
        if (ipc_body->snooper_objs[i].type == SNOOPER_OBJ_CON) {
            path = ipc_body->snooper_objs[i].obj.con_info.libssl_path;
        }
        if (ipc_body->snooper_objs[i].type == SNOOPER_OBJ_PROC) {
            u32 proc_id = ipc_body->snooper_objs[i].obj.proc.proc_id;
            libssl[0] = 0;
            ret = get_elf_path(proc_id, libssl, PATH_LEN, "libc\\.so");
            if (ret) {
                continue;
            }
            path = libssl;
        }

        if (path) {
            if (__is_exist_libssl_prog(l7_mng, (const char *)path)) {
                continue;
            }
        }

        if (path) {
            prog = alloc_bpf_prog();
            if (prog == NULL) {
                goto err;
            }
            ret = l7_load_probe_libssl(l7_mng, prog, (const char*)path);
            if (ret) {
                goto err;
            }
            ret = __add_libssl_prog(l7_mng, prog, (const char*)path);
            if (ret) {
                goto err;
            }
        }
    }

    l7_mng->last_report = (time_t)time(NULL);
    return 0;
err:
    unload_bpf_prog(&prog);
    return -1;
}

static void load_l7_snoopers(int fd, struct ipc_body_s *ipc_body)
{
    struct proc_s proc = {0};
    struct obj_ref_s ref = {.count = 1};

    if (fd <= 0) {
        return;
    }

    for (int i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        if (ipc_body->snooper_objs[i].type == SNOOPER_OBJ_PROC) {
            proc.proc_id = ipc_body->snooper_objs[i].obj.proc.proc_id;
            (void)bpf_map_update_elem(fd, &proc, &ref, BPF_ANY);
        }
    }
}

static void unload_l7_snoopers(int fd, struct ipc_body_s *ipc_body)
{
    struct proc_s proc = {0};

    if (fd <= 0) {
        return;
    }

    for (int i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        if (ipc_body->snooper_objs[i].type == SNOOPER_OBJ_PROC) {
            proc.proc_id = ipc_body->snooper_objs[i].obj.proc.proc_id;
            (void)bpf_map_delete_elem(fd, &proc);
        }
    }
}

static int __poll_l7_pb(struct bpf_prog_s* prog)
{
    int ret;

#ifdef __USE_RING_BUF
    for (int i = 0; i < prog->num && i < SKEL_MAX_NUM; i++) {
        if (prog->rbs[i]) {
            ret = ring_buffer__poll(prog->rbs[i], THOUSAND);
            if (ret) {
                return ret;
            }
        }
    }
#else
    for (int i = 0; i < prog->num && i < SKEL_MAX_NUM; i++) {
        if (prog->pbs[i]) {
            ret = perf_buffer__poll(prog->pbs[i], THOUSAND);
            if (ret) {
                return ret;
            }
        }
    }
#endif

    return 0;
}

static int poll_l7_pb(struct l7_ebpf_prog_s* ebpf_progs)
{
    int ret;
    struct libssl_prog_s *libssl_prog;

    if (ebpf_progs->kern_sock_prog) {
        ret = __poll_l7_pb(ebpf_progs->kern_sock_prog);
        if (ret) {
            return ret;
        }
    }

    for (int i = 0; i < LIBSSL_EBPF_PROG_MAX; i++) {
        libssl_prog = &(ebpf_progs->libssl_progs[i]);
        if (libssl_prog && libssl_prog->prog) {
            ret = __poll_l7_pb(libssl_prog->prog);
            if (ret) {
                return ret;
            }
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    int ret = 0, is_load_prog = 0;
    struct l7_mng_s *l7_mng = &g_l7_mng;
    struct ipc_body_s ipc_body;

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        ERROR("[L7PROBE]: Can't set signal handler: %d\n", errno);
        return -1;
    }

    (void)memset(l7_mng, 0, sizeof(struct l7_mng_s));

    int msq_id = create_ipc_msg_queue(IPC_EXCL);
    if (msq_id < 0) {
        fprintf(stderr, "Create ipc msg que failed.\n");
        goto err;
    }

    INIT_BPF_APP(l7probe, EBPF_RLIM_LIMITED);
    printf("Successfully started!\n");

    while (!g_stop) {
        ret = recv_ipc_msg(msq_id, (long)PROBE_L7, &ipc_body);
        if (ret == 0) {
            unload_l7_prog(l7_mng);
            ret = load_l7_prog(l7_mng);
            if (ret) {
                destroy_ipc_body(&ipc_body);
                break;
            }

            unload_l7_snoopers(l7_mng->bpf_progs.proc_obj_map_fd, &(l7_mng->ipc_body));
            destroy_ipc_body(&(l7_mng->ipc_body));

            (void)memcpy(&(l7_mng->ipc_body), &ipc_body, sizeof(ipc_body));
            l7_unload_tcp_fd(l7_mng);
            (void)l7_load_tcp_fd(l7_mng);
            load_l7_snoopers(l7_mng->bpf_progs.proc_obj_map_fd, &(l7_mng->ipc_body));

            l7_unload_probe_jsse(l7_mng);
            if (l7_load_probe_jsse(l7_mng) < 0) {
                break;
            }

            is_load_prog = 1;
        }

        if (is_load_prog) {
            ret = poll_l7_pb(&(l7_mng->bpf_progs));
            if (ret) {
                ERROR("[L7Probe]: perf poll failed(%d).\n", ret);
                break;
            }
            l7_parser(l7_mng);
            report_l7(l7_mng);
        } else {
            sleep(1);
        }
    }

err:
    destroy_trackers(l7_mng);
    destroy_links(l7_mng);
    l7_unload_probe_jsse(l7_mng);
    unload_l7_prog(l7_mng);
    destroy_ipc_body(&(l7_mng->ipc_body));
    return 0;
}
