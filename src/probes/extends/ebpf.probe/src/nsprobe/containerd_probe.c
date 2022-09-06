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
 * Create: 2022-06-6
 * Description: container traceing
 ******************************************************************************/
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/stat.h>
#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "args.h"
#include "hash.h"
#include "object.h"
#include "container.h"
#include "bps.h"
#include "containerd_probe.h"

static void add_cgrp_obj(struct container_value *container)
{
    struct cgroup_s obj = {0};

    obj.knid = container->cpucg_inode;
    obj.type = CGP_TYPE_CPUACCT;
    (void)cgrp_add(&obj);

    obj.knid = container->memcg_inode;
    obj.type = CGP_TYPE_MEM;
    (void)cgrp_add(&obj);

    obj.knid = container->pidcg_inode;
    obj.type = CGP_TYPE_PIDS;
    (void)cgrp_add(&obj);
}

static void put_cgrp_obj(struct container_value *container)
{
    struct cgroup_s obj = {0};

    obj.knid = container->cpucg_inode;
    obj.type = CGP_TYPE_CPUACCT;
    (void)cgrp_put(&obj);

    obj.knid = container->memcg_inode;
    obj.type = CGP_TYPE_MEM;
    (void)cgrp_put(&obj);

    obj.knid = container->pidcg_inode;
    obj.type = CGP_TYPE_PIDS;
    (void)cgrp_put(&obj);
}

static void add_nm_obj(struct container_value *container)
{
    struct nm_s obj = {0};

    obj.id = container->mnt_ns_id;
    obj.type = NM_TYPE_MNT;
    (void)nm_add(&obj);

    obj.id = container->net_ns_id;
    obj.type = NM_TYPE_NET;
    (void)nm_add(&obj);
}

static void put_nm_obj(struct container_value *container)
{
    struct nm_s obj = {0};

    obj.id = container->mnt_ns_id;
    obj.type = NM_TYPE_MNT;
    (void)nm_put(&obj);

    obj.id = container->net_ns_id;
    obj.type = NM_TYPE_NET;
    (void)nm_put(&obj);
}

static int is_valid_tgid(struct probe_params *p, u32 pid)
{
    if (p->filter_task_probe) {
        struct proc_s obj = {.proc_id = pid};
        return is_proc_exist(&obj);
    }

    if (p->filter_pid != 0) {
        return (pid == p->filter_pid);
    }
    return 1;
}

static int filter_conatiner(const char *container_id, struct probe_params *params)
{
    u32 pid;
    int ret = get_container_pid(container_id, &pid);
    if (ret) {
        return 1;
    }

    if (is_valid_tgid(params, pid)) {
        return 0;
    }

    return 1;
}

static void init_container(const char *container_id, struct container_value *container)
{
    container->flags |= CONTAINER_FLAGS_VALID;

    if (container->proc_id == 0) {
        (void)get_container_pid(container_id, &container->proc_id);
    }

    if (container->name[0] == 0) {
        (void)get_container_name(container_id, container->name, CONTAINER_NAME_LEN);
    }

    if (container->cpucg_dir[0] == 0) {
        (void)get_container_cpucg_dir(container_id, container->cpucg_dir, PATH_LEN);
    }

    if (container->memcg_dir[0] == 0) {
        (void)get_container_memcg_dir(container_id, container->memcg_dir, PATH_LEN);
    }

    if (container->pidcg_dir[0] == 0) {
        (void)get_container_pidcg_dir(container_id, container->pidcg_dir, PATH_LEN);
    }

    if (container->netcg_dir[0] == 0) {
        (void)get_container_netcg_dir(container_id, container->netcg_dir, PATH_LEN);
    }

    if (container->cpucg_inode == 0) {
        (void)get_container_cpucg_inode(container_id, &container->cpucg_inode);
    }

    if (container->memcg_inode == 0) {
        (void)get_container_memcg_inode(container_id, &container->memcg_inode);
    }

    if (container->pidcg_inode == 0) {
        (void)get_container_pidcg_inode(container_id, &container->pidcg_inode);
    }

    if (container->mnt_ns_id == 0) {
        (void)get_container_mntns_id(container_id, &container->mnt_ns_id);
    }

    if (container->net_ns_id == 0) {
        (void)get_container_netns_id(container_id, &container->net_ns_id);
    }

    return;
}

static bool check_cg_path(const char *cgrpPath, char *trustedPath)
{
    struct stat st = {0};
    int ret = snprintf(trustedPath, MAX_PATH_LEN + 1, "%s/%s", cgrpPath, "net_cls.classid");
    if (ret < 0 || stat(trustedPath, &st) < 0 || (st.st_mode & S_IFMT) != S_IFREG) {
        DEBUG("CgrpV1Prio get realPath failed. ret: %d\n", ret);
        return false;
    }

    return true;
}

static int set_net_classid(u32 classid, const char *netcg_dir)
{
    int fd = -1;
    int ret;
    ssize_t size;
    char trustedPath[MAX_PATH_LEN + 1] = {0};

#define BUF_SIZE 64
    char buf[BUF_SIZE];

    if (!check_cg_path(netcg_dir, trustedPath)) {
        return -1;
    }

    fd = open(trustedPath, O_WRONLY);
    if (fd < 0) {
        DEBUG("set net classid open trustedPath[%s] failed. errno:%d\n", trustedPath, errno);
        return -1;
    }

    ret = snprintf(buf, BUF_SIZE, "%u\n", classid);
    if (ret < 0) {
        DEBUG("set net classid snprintf failed. ret: %d.\n", ret);
        (void)close(fd);
        return -1;
    }
    size = write(fd, buf, strlen(buf));
    ret = ((size_t)size != strlen(buf));

    (void)close(fd);

    if (ret != 0) {
        DEBUG("set pid[%u] net_cls.classid err %d\n", classid, ret);
    }

    return ret;
}

static void clean_bps_map(struct container_hash_t *item)
{
    int egress_map_fd = bpf_obj_get(EGRESS_MAP_PATH);
    if (egress_map_fd == 0) {
        return;
    }
    u64 classid = item->v.proc_id;
    (void)set_net_classid(0, (const char *)item->v.netcg_dir);
    (void)bpf_map_delete_elem(egress_map_fd, &classid);
}

static void clear_invalid_items(struct container_hash_t **pphead)
{
    struct container_hash_t *item, *tmp;
    if (*pphead == NULL) {
        return;
    }

    H_ITER(*pphead, item, tmp) {
        if (!(item->v.flags & CONTAINER_FLAGS_VALID)) {
            clean_bps_map(item);
            put_cgrp_obj(&(item->v));
            put_nm_obj(&(item->v));
            H_DEL(*pphead, item);
            (void)free(item);
        }
    }
}

static void set_container_invalid(struct container_hash_t **pphead)
{
    struct container_hash_t *item, *tmp;
    if (*pphead == NULL) {
        return;
    }

    H_ITER(*pphead, item, tmp) {
        item->v.flags &= ~CONTAINER_FLAGS_VALID;
    }
}

// set container proc_id as cgroup net_cls.classid
static void init_bps_map(struct container_hash_t *item)
{
    int egress_map_fd = bpf_obj_get(EGRESS_MAP_PATH);
    if (egress_map_fd == 0) {
        return;
    }
    u64 classid = item->v.proc_id;
    if (set_net_classid(item->v.proc_id, (const char *)item->v.netcg_dir) == 0) {
        struct egress_bandwidth_s bps = {0};
        (void)bpf_map_update_elem(egress_map_fd, &classid, &bps, BPF_ANY);
        printf("set net_cls classid of proc %llu success\n", classid);
    }
}

static struct container_hash_t* add_container(const char *container_id, struct container_hash_t **pphead)
{
    struct container_hash_t *item;

    item = malloc(sizeof(struct container_hash_t));
    if (item == NULL) {
        return NULL;
    }

    (void)memset(item, 0, sizeof(struct container_hash_t));
    (void)strncpy(item->k.container_id, container_id, CONTAINER_ABBR_ID_LEN);

    H_ADD_KEYPTR(*pphead, item->k.container_id, CONTAINER_ABBR_ID_LEN, item);

    init_container((const char *)item->k.container_id, &(item->v));

    init_bps_map(item);

    add_cgrp_obj(&(item->v));
    add_nm_obj(&(item->v));
    return item;
}

static struct container_hash_t* find_container(const char *container_id, struct container_hash_t **pphead)
{
    struct container_hash_t *item;

    H_FIND(*pphead, container_id, CONTAINER_ABBR_ID_LEN, item);
    return item;
}

#if 0
#ifdef COMMAND_LEN
#undef COMMAND_LEN
#define COMMAND_LEN 512
#endif

#ifndef __CAT_FILE
#define __CAT_FILE "/usr/bin/cat %s/%s"
#endif

#ifndef __TEN
#define __TEN 10
#endif
static void __get_container_memory_metrics(struct container_value *container)
{
    char command[COMMAND_LEN];
    char line[LINE_BUF_LEN];

    /* memory.usage_in_bytes */
    command[0] = 0;
    line[0] = 0;
    (void)snprintf(command, COMMAND_LEN, __CAT_FILE, container->memcg_dir, "memory.usage_in_bytes");
    if (exec_cmd(command, line, LINE_BUF_LEN) == -1) {
        return;
    }
    container->memory_usage_in_bytes = strtoull((char *)line, NULL, __TEN);

    /* memory.limit_in_bytes */
    command[0] = 0;
    line[0] = 0;
    (void)snprintf(command, COMMAND_LEN, __CAT_FILE, container->memcg_dir, "memory.limit_in_bytes");
    if (exec_cmd(command, line, LINE_BUF_LEN) == -1) {
        return;
    }
    container->memory_limit_in_bytes = strtoull((char *)line, NULL, __TEN);

    return;
}

static void __get_container_cpuaccet_metrics(struct container_value *container)
{
    char command[COMMAND_LEN];
    char line[LINE_BUF_LEN];

    /* cpuacct.usage */
    command[0] = 0;
    line[0] = 0;
    (void)snprintf(command, COMMAND_LEN, __CAT_FILE, container->cpucg_dir, "cpuacct.usage");
    if (exec_cmd(command, line, LINE_BUF_LEN) == -1) {
        return;
    }

    container->cpuacct_usage = strtoull((char *)line, NULL, __TEN);

    /* cpuacct.usage_sys */
    command[0] = 0;
    line[0] = 0;
    (void)snprintf(command, COMMAND_LEN, __CAT_FILE, container->cpucg_dir, "cpuacct.usage_sys");
    if (exec_cmd(command, line, LINE_BUF_LEN) == -1) {
        return;
    }

    container->cpuacct_usage_sys = strtoull((char *)line, NULL, __TEN);

    /* cpuacct.usage_user */
    command[0] = 0;
    line[0] = 0;
    (void)snprintf(command, COMMAND_LEN, __CAT_FILE, container->cpucg_dir, "cpuacct.usage_user");
    if (exec_cmd(command, line, LINE_BUF_LEN) == -1) {
        return;
    }

    container->cpuacct_usage_user = strtoull((char *)line, NULL, __TEN);

    return;
}

#ifndef PID_MAX_LIMIT
#define PID_MAX_LIMIT 2^22
#endif
static void __get_container_pids_metrics(struct container_value *container)
{
    char command[COMMAND_LEN];
    char line[LINE_BUF_LEN];

    /* pids.current */
    command[0] = 0;
    line[0] = 0;
    (void)snprintf(command, COMMAND_LEN, __CAT_FILE, container->pidcg_dir, "pids.current");
    if (exec_cmd(command, line, LINE_BUF_LEN) == -1) {
        return;
    }

    container->pids_current = strtoull((char *)line, NULL, __TEN);

    /* pids.limit */
    command[0] = 0;
    line[0] = 0;
    (void)snprintf(command, COMMAND_LEN, __CAT_FILE, container->pidcg_dir, "pids.max");
    if (exec_cmd(command, line, LINE_BUF_LEN) == -1) {
        return;
    }

    if (strcmp((char *)line, "max") == 0) {
        container->pids_limit = PID_MAX_LIMIT;
    } else {
        container->pids_limit = strtoull((char *)line, NULL, __TEN);
    }

    return;
}

static void print_container_metric(struct container_hash_t **pphead)
{
    struct container_hash_t *item, *tmp;

    H_ITER(*pphead, item, tmp) {
        __get_container_memory_metrics(&(item->v));
        __get_container_cpuaccet_metrics(&(item->v));
        __get_container_pids_metrics(&(item->v));

        (void)fprintf(stdout, "|%s|%s|%s|%u|%u|%u|%u|%u|%u|%llu|%llu|%llu|%llu|%llu|%llu|%llu|\n",
            METRIC_NAME_RUNC_TRACE,
            item->k.container_id,
            item->v.name,
            item->v.cpucg_inode,
            item->v.memcg_inode,
            item->v.pidcg_inode,
            item->v.mnt_ns_id,
            item->v.net_ns_id,
            item->v.proc_id,
            item->v.memory_usage_in_bytes,
            item->v.memory_limit_in_bytes,
            item->v.cpuacct_usage,
            item->v.cpuacct_usage_sys,
            item->v.cpuacct_usage_user,
            item->v.pids_current,
            item->v.pids_limit);
    }
    (void)fflush(stdout);
    return;
}
#endif

struct container_value* get_container_by_proc_id(struct container_hash_t **pphead,
                                                            u32 proc_id)
{
    struct container_hash_t *item, *tmp;
    if (*pphead == NULL) {
        return NULL;
    }

    H_ITER(*pphead, item, tmp) {
        if (item->v.proc_id == proc_id) {
            return &(item->v);
        }
    }
    return NULL;
}

void get_containers(struct container_hash_t **pphead, struct probe_params *params)
{
    int i;
    struct container_hash_t* item;

    set_container_invalid(pphead);

    container_tbl* cstbl = get_all_container();
    if (cstbl != NULL) {
        container_info *p = cstbl->cs;
        for (i = 0; i < cstbl->num; i++) {
            if (p->status != CONTAINER_STATUS_RUNNING) {
                p++;
                continue;
            }

            if (filter_conatiner((const char *)p->abbrContainerId, params)) {
                p++;
                continue;
            }

            item = find_container((const char *)p->abbrContainerId, pphead);
            if (item == NULL) {
                (void)add_container(p->abbrContainerId, pphead);
            } else {
                item->v.flags |= CONTAINER_FLAGS_VALID;
            }

            p++;
        }
        free_container_tbl(&cstbl);
    }

    clear_invalid_items(pphead);
}

void put_containers(struct container_hash_t **pphead)
{
    struct container_hash_t *item, *tmp;
    if (*pphead == NULL) {
        return;
    }

    H_ITER(*pphead, item, tmp) {
        clean_bps_map(item);
        put_cgrp_obj(&(item->v));
        put_nm_obj(&(item->v));
        H_DEL(*pphead, item);
        (void)free(item);
    }
}
