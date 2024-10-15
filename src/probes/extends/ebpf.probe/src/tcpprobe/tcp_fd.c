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
#include "ipc.h"
#include "hash.h"
#include "container.h"
#include "tcpprobe.h"


#define MAX_TRY_LOAD    (120)   // 2 min

struct estab_tcp_key {
    u32 proc_id;
};

struct estab_tcp_fd {
    int fd;
    int role;                   // 1: client; 0: server
};

enum estab_tcp_flag_t {
    ESTAB_TCP_FLAG_INIT = 0,
    ESTAB_TCP_FLAG_RESET,
    ESTAB_TCP_FLAG_FINISHED
};

struct estab_tcp_val {
    int num;
    u32 try_load_cnt;           // Maximum number of loading attempts
    enum estab_tcp_flag_t flag;
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
    item->v.flag = ESTAB_TCP_FLAG_INIT;

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
    return 0;
}

static void set_estab_tcps_reset_flag(struct estab_tcp_hash_t **pphead)
{
    struct estab_tcp_hash_t *estab_tcp, *tmp;

    if (*pphead == NULL) {
        return;
    }

    H_ITER(*pphead, estab_tcp, tmp) {
        estab_tcp->v.flag = ESTAB_TCP_FLAG_RESET;
    }
}

static void set_estab_tcps_finished_flag(struct estab_tcp_hash_t **pphead)
{
    struct estab_tcp_hash_t *estab_tcp, *tmp;

    if (*pphead == NULL) {
        return;
    }

    H_ITER(*pphead, estab_tcp, tmp) {
        if (estab_tcp->v.flag == ESTAB_TCP_FLAG_INIT) {
            estab_tcp->v.flag = ESTAB_TCP_FLAG_FINISHED;
        }
    }
}

#if 1

static void do_lkup_established_tcp_info(void)
{
    int i, j;
    u8 role;
    struct tcp_listen_ports* tlps;
    struct tcp_estabs* tes = NULL;
    struct estab_tcp_key k;
    struct estab_tcp_hash_t *item;

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

            item = find_estab_tcp(&k, &head);
            if (item && item->v.flag == ESTAB_TCP_FLAG_RESET) {
                item->v.num = 0;
                item->v.flag = ESTAB_TCP_FLAG_INIT;
            }
            if (item && item->v.flag == ESTAB_TCP_FLAG_FINISHED) {
                continue;
            }

            (void)add_estab_tcp_fd((const struct estab_tcp_key *)&k,
                (int)tes->te[i]->te_comm[j]->fd, (int)role, &head);
        }
    }
    /* Ensure that container processes with the same netns(eg. in k8s scenario)
     * do not repeatedly set established tcp connections.
     */
    set_estab_tcps_finished_flag(&head);

err:
    if (tlps) {
        free_listen_ports(&tlps);
    }

    if (tes) {
        free_estab_tcps(&tes);
    }

    return;
}

static int get_netns_fd(pid_t pid)
{
    const char *fmt = "/proc/%d/ns/net";
    char path[PATH_LEN];

    path[0] = 0;
    (void)snprintf(path, PATH_LEN, fmt, pid);
    return open(path, O_RDONLY);
}

/*
 * 查询tcp探针启动前系统中已创建的tcp连接信息
 *   1. 全局只获取一次主机netns下的tcp连接信息
 *   2. 只对新增的容器进程查询对应容器netns下的tcp连接信息
 */
void lkup_established_tcp(int proc_map_fd, struct ipc_body_s *ipc_body)
{
    int netns_fd = 0;
    struct proc_s key = {0};
    struct obj_ref_s val = {0};
    static char host_netns_flag = 0;   // 全局只获取一次主机netns下的tcp连接信息
    int ret;
    int i;

    /* Ensure that newly added TCP connections of the process overwrites the existing TCP connections. */
    set_estab_tcps_reset_flag(&head);

    if (!host_netns_flag) {
        INFO("[TCPPROBE]: Lookup established tcp for host netns...\n");
        do_lkup_established_tcp_info();
        host_netns_flag = 1;
    }

    netns_fd = get_netns_fd(getpid());
    if (netns_fd <= 0) {
        ERROR("[TCPPROBE]: Get netns fd failed.\n");
        return;
    }

    for (i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        if (ipc_body->snooper_objs[i].type != SNOOPER_OBJ_PROC) {
            continue;
        }

        key.proc_id = ipc_body->snooper_objs[i].obj.proc.proc_id;
        if (bpf_map_lookup_elem(proc_map_fd, &key, &val) == 0) {
            continue;
        }

        if (is_container_proc(key.proc_id)) {
            ret = enter_proc_netns(key.proc_id);
            if (ret) {
                ERROR("[TCPPROBE]: Enter container netns failed.(%u, ret = %d)\n", key.proc_id, ret);
                continue;
            }
            INFO("[TCPPROBE]: Lookup established tcp for container netns of proc:%u ...\n", key.proc_id);
            do_lkup_established_tcp_info();
            (void)exit_container_netns(netns_fd);
        }
    }

    (void)close(netns_fd);
}

#endif
#if 1
static int is_need_load_established_tcp(int proc_obj_map_fd, struct estab_tcp_hash_t *item)
{
    struct proc_s key = {0};
    struct obj_ref_s val = {0};

    key.proc_id = item->k.proc_id;
    if (bpf_map_lookup_elem(proc_obj_map_fd, &key, &val) == 0) {
        return 1;
    }
    return 0;
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
static int load_established_tcp(int proc_obj_map_fd, int map_fd, struct estab_tcp_hash_t *item, int *loaded)
{
    int ret;
    if (!is_need_load_established_tcp(proc_obj_map_fd, item)) {
        item->v.try_load_cnt++;
        return LOAD_ESTAB_TCP_NO_NEED;
    }

    ret = do_load_established_tcp(map_fd, item, loaded);
    item->v.num -= *loaded;
    if (ret) {
        return LOAD_ESTAB_TCP_LIMIT;
    }
    return LOAD_ESTAB_TCP_SUCCEED;
}

int load_established_tcps(int proc_obj_map_fd, int map_fd)
{
    struct estab_tcp_hash_t *item, *tmp;
    int total_loaded = 0;
    int loaded = 0;

    if (head == NULL) {
        return 0;
    }

    H_ITER(head, item, tmp) {
        if (is_invalid_established_tcp(item)) {
            H_DEL(head, item);
            (void)free(item);
            continue;
        }

        loaded = 0;
        if (load_established_tcp(proc_obj_map_fd, map_fd, item, &loaded) == LOAD_ESTAB_TCP_SUCCEED) {
            H_DEL(head, item);
            (void)free(item);
        }
        total_loaded += loaded;
    }

    return total_loaded;
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

