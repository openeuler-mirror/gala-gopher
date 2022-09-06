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
 * Author: luzhihao
 * Create: 2022-07-26
 * Description: tcp establish fd
 ******************************************************************************/
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
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
#include "tcp.h"
#include "args.h"
#include "hash.h"
#include "object.h"
#include "container.h"
#include "tcpprobe.h"

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434     // System call # on most architectures
#endif

#define MAX_TRY_LOAD    (120)   // 2 min

struct estab_tcp_key {
    u32 proc_id;
};

struct estab_tcp_fd {
    int fd;
    int role;                   // 1: client; 0: server
};

struct estab_tcp_val {
    int num;
    u32 try_load_cnt;           // Maximum number of loading attempts
    struct estab_tcp_fd fds[TCP_ESTAB_MAX];
};

struct estab_tcp_hash_t {
    H_HANDLE;
    struct estab_tcp_key k;
    struct estab_tcp_val v;
};

static struct estab_tcp_hash_t *head = NULL;

static struct estab_tcp_hash_t* create_estab_tcp(const struct estab_tcp_key *k, struct estab_tcp_hash_t **pphead)
{
    struct estab_tcp_hash_t *item;
    size_t malloc_size = sizeof(struct estab_tcp_hash_t);
    item = (struct estab_tcp_hash_t *)malloc(malloc_size);
    if (item == NULL) {
        return NULL;
    }

    (void)memset(item, 0, malloc_size);

    (void)memcpy(&item->k, k, sizeof(struct estab_tcp_key));

    H_ADD_KEYPTR(*pphead, &item->k, sizeof(struct estab_tcp_key), item);
    return item;
}

static struct estab_tcp_hash_t* find_estab_tcp(const struct estab_tcp_key *k, struct estab_tcp_hash_t **pphead)
{
    struct estab_tcp_hash_t *item = NULL;

    H_FIND(*pphead, k, sizeof(struct estab_tcp_key), item);
    return item;
}

static int add_estab_tcp_fd(const struct estab_tcp_key *k,
                            int fd, int role, struct estab_tcp_hash_t **pphead)
{
    struct estab_tcp_hash_t *item;

    item = find_estab_tcp(k, pphead);
    if (!item) {
        item = create_estab_tcp(k, pphead);
    }

    if (!item) {
        return -1;
    }

    if (item->v.num >= TCP_ESTAB_MAX || item->v.num < 0) {
        ERROR("[TCPPROBE]: Add established tcp fd failed.(proc_id = %u)\n", k->proc_id);
        return -1;
    }
    item->v.fds[item->v.num].fd = fd;
    item->v.fds[item->v.num].role = role;
    item->v.num++;
    INFO("[TCPPROBE]: Load established tcp(proc = %u, fd = %d)\n", k->proc_id, fd);
    return 0;
}

#if 1

static int get_netns_fd(pid_t pid)
{
    const char *fmt = "/proc/%u/ns/net";
    char path[PATH_LEN];

    path[0] = 0;
    (void)snprintf(path, PATH_LEN, fmt, pid);
    return open(path, O_RDONLY);
}

static __maybe_unused int pidfd_open(pid_t pid, unsigned int flags)
{
    return syscall(__NR_pidfd_open, pid, flags);
}

static int set_netns_by_pid(pid_t pid)
{
    int fd = -1;
#if (CURRENT_KERNEL_VERSION < KERNEL_VERSION(5, 3, 0))
    fd = get_netns_fd(pid);
#else
    fd = pidfd_open(pid, 0);
#endif
    if (fd == -1) {
        ERROR("[TCPPROBE] Get tgid(%d)'s pidfd failed.\n", pid);
        return -1;
    }
    return setns(fd, CLONE_NEWNET);
}

static int set_netns_by_fd(int fd)
{
    return setns(fd, CLONE_NEWNET);
}

static int enter_container_netns(const char *container_id)
{
    int ret;
    u32 pid;

    ret = get_container_pid(container_id, &pid);
    if (ret) {
        ERROR("[TCPPROBE]: Get container pid failed.(%s, ret = %d)\n", container_id, ret);
        return ret;
    }

    return set_netns_by_pid((pid_t)pid);
}

static int exit_container_netns(int current_netns)
{
    return set_netns_by_fd(current_netns);
}

static void do_lkup_established_tcp_info(void)
{
    int i, j;
    u8 role;
    struct tcp_listen_ports* tlps;
    struct tcp_estabs* tes = NULL;
    struct estab_tcp_key k;

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
        role = tes->te[i]->is_client == 1 ? LINK_ROLE_CLIENT : LINK_ROLE_SERVER;
        for (j = 0; j < tes->te[i]->te_comm_num; j++) {
            k.proc_id = (u32)tes->te[i]->te_comm[j]->pid;
            (void)add_estab_tcp_fd((const struct estab_tcp_key *)&k,
                (int)tes->te[i]->te_comm[j]->fd, (int)role, &head);
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

static int do_lkup_established_tcp(const char *container_id, int current_netns)
{
    int ret;

    if (container_id) {
        ret = enter_container_netns(container_id);
        if (ret) {
            ERROR("[TCPPROBE]: Enter container netns failed.(%s, ret = %d)\n",
                container_id, ret);
            return ret;
        }
    }

    do_lkup_established_tcp_info();

    if (container_id) {
        (void)exit_container_netns(current_netns);
    }
    return 0;
}

void lkup_established_tcp(void)
{
    int i;
    int netns_fd = 0;

    netns_fd = get_netns_fd(getpid());
    if (netns_fd <= 0) {
        ERROR("[TCPPROBE]: Get netns fd failed.\n");
        return;
    }

    container_tbl* cstbl = get_all_container();
    if (cstbl != NULL) {
        container_info *p = cstbl->cs;
        for (i = 0; i < cstbl->num; i++) {
            (void)do_lkup_established_tcp((const char *)p->abbrContainerId, netns_fd);
            p++;
        }
        free_container_tbl(&cstbl);
    }

    (void)do_lkup_established_tcp(NULL, netns_fd);
    (void)close(netns_fd);
}

#endif
#if 1
static int is_need_load_established_tcp(struct probe_params *args, struct estab_tcp_hash_t *item)
{
    if (args->filter_task_probe) {
        struct proc_s obj = {.proc_id = item->k.proc_id};
        return is_proc_exist(&obj);
    }

    if (args->filter_pid != 0) {
        return (item->k.proc_id == args->filter_pid);
    }
    return 1;
}


static char is_invalid_established_tcp(struct estab_tcp_hash_t *item)
{
    return (item->v.try_load_cnt >= MAX_TRY_LOAD);
}

static int do_load_established_tcp(int map_fd, struct estab_tcp_hash_t *item, int *loaded)
{
    int ret = 0, load_num = 0;
    struct tcp_fd_info tcp_fd_s = {0};

    *loaded = 0;
    (void)bpf_map_lookup_elem(map_fd, &(item->k.proc_id), &tcp_fd_s);

    for (int i = item->v.num - 1; i >= 0; i--) {
        if (tcp_fd_s.cnt >= TCP_FD_PER_PROC_MAX) {
            ret = -1;
            break;
        }
        tcp_fd_s.fds[tcp_fd_s.cnt] = item->v.fds[i].fd;
        tcp_fd_s.fd_role[tcp_fd_s.cnt] = (u8)item->v.fds[i].role;
        tcp_fd_s.cnt++;
        load_num++;
    }

    if (load_num > 0) {
        INFO("Update establish(proc_id = %u, fd_count = %u).\n", (item->k.proc_id), tcp_fd_s.cnt);

        (void)bpf_map_update_elem(map_fd, &(item->k.proc_id), &tcp_fd_s, BPF_ANY);
    }
    *loaded = load_num;
    return ret;
}

/*
* retcode 0: succeed; -1: no need load; -2: load failed(upper to limit)
*/
#define LOAD_ESTAB_TCP_SUCCEED  0
#define LOAD_ESTAB_TCP_NO_NEED  (-1)
#define LOAD_ESTAB_TCP_LIMIT    (-2)
static int load_established_tcp(struct probe_params *args, int map_fd, struct estab_tcp_hash_t *item)
{
    int ret, loaded;
    if (!is_need_load_established_tcp(args, item)) {
        item->v.try_load_cnt++;
        return LOAD_ESTAB_TCP_NO_NEED;
    }

    ret = do_load_established_tcp(map_fd, item, &loaded);
    item->v.num -= loaded;
    if (ret) {
        return LOAD_ESTAB_TCP_LIMIT;
    }
    return LOAD_ESTAB_TCP_SUCCEED;
}

void load_established_tcps(struct probe_params *args, int map_fd)
{
    struct estab_tcp_hash_t *item, *tmp;
    if (head == NULL) {
        return;
    }

    H_ITER(head, item, tmp) {
        if (is_invalid_established_tcp(item)) {
            H_DEL(head, item);
            (void)free(item);
            continue;
        }

        if (load_established_tcp(args, map_fd, item) == LOAD_ESTAB_TCP_SUCCEED) {
            H_DEL(head, item);
            (void)free(item);
        }
    }
}

#endif

void destroy_established_tcps(void)
{
    struct estab_tcp_hash_t *item, *tmp;
    if (head == NULL) {
        return;
    }

    H_ITER(head, item, tmp) {
        H_DEL(head, item);
        (void)free(item);
    }
}

