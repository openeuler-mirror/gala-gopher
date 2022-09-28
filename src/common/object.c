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
 * Create: 2022-06-22
 * Description: object module
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sched.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "common.h"
#include "object.h"

#define MAP_OBJS_DUMP "bpftool map list  | /usr/bin/grep -w %s"
struct __obj_s {
    int init;
    int proc_map_fd;
    int cgrp_map_fd;
    int nm_map_fd;
    pthread_rwlock_t rwlock;
};

static struct __obj_s __obj_module = {0};

int proc_put(struct proc_s *obj)
{
    int ret;
    struct obj_ref_s ref = {0};

    if (__obj_module.proc_map_fd <= 0) {
        return -1;
    }

    (void)pthread_rwlock_wrlock(&(__obj_module.rwlock));
    ret = bpf_map_lookup_elem(__obj_module.proc_map_fd, obj, &ref);
    if (ret < 0) {
        goto err;
    }

    if (ref.count > 0) {
        ref.count--;
    }

    if (ref.count == 0) {
        ret = bpf_map_delete_elem(__obj_module.proc_map_fd, obj);
    } else {
        ret = bpf_map_update_elem(__obj_module.proc_map_fd, obj, &ref, BPF_ANY);
    }

err:
    (void)pthread_rwlock_unlock(&(__obj_module.rwlock));
    return ret;
}

int proc_add(struct proc_s *obj)
{
    int ret;
    struct obj_ref_s ref = {0};

    if (__obj_module.proc_map_fd <= 0) {
        return -1;
    }

    (void)pthread_rwlock_wrlock(&(__obj_module.rwlock));
    ret = bpf_map_lookup_elem(__obj_module.proc_map_fd, obj, &ref);
    if (!ret) {
        ref.count = 1;
        ret = bpf_map_update_elem(__obj_module.proc_map_fd, obj, &ref, BPF_ANY);
    } else {
        ref.count++;
        ret = bpf_map_update_elem(__obj_module.proc_map_fd, obj, &ref, BPF_ANY);
    }

    (void)pthread_rwlock_unlock(&(__obj_module.rwlock));

    return ret;
}

int cgrp_put(struct cgroup_s *obj)
{
    int ret;
    struct obj_ref_s ref = {0};

    if (__obj_module.cgrp_map_fd <= 0) {
        return -1;
    }

    (void)pthread_rwlock_wrlock(&(__obj_module.rwlock));
    ret = bpf_map_lookup_elem(__obj_module.cgrp_map_fd, obj, &ref);
    if (ret < 0) {
        goto err;
    }

    if (ref.count > 0) {
        ref.count--;
    }

    if (ref.count == 0) {
        ret = bpf_map_delete_elem(__obj_module.cgrp_map_fd, obj);
    } else {
        ret = bpf_map_update_elem(__obj_module.cgrp_map_fd, obj, &ref, BPF_ANY);
    }

err:
    (void)pthread_rwlock_unlock(&(__obj_module.rwlock));
    return ret;
}

int cgrp_add(struct cgroup_s *obj)
{
    int ret;
    struct obj_ref_s ref = {0};

    if (__obj_module.cgrp_map_fd <= 0) {
        return -1;
    }

    (void)pthread_rwlock_wrlock(&(__obj_module.rwlock));
    ret = bpf_map_lookup_elem(__obj_module.cgrp_map_fd, obj, &ref);
    if (!ret) {
        ref.count = 1;
        ret = bpf_map_update_elem(__obj_module.cgrp_map_fd, obj, &ref, BPF_ANY);
    } else {
        ref.count++;
        ret = bpf_map_update_elem(__obj_module.cgrp_map_fd, obj, &ref, BPF_ANY);
    }

    (void)pthread_rwlock_unlock(&(__obj_module.rwlock));

    return ret;
}

int nm_put(struct nm_s *obj)
{
    int ret;
    struct obj_ref_s ref = {0};

    if (__obj_module.nm_map_fd <= 0) {
        return -1;
    }

    (void)pthread_rwlock_wrlock(&(__obj_module.rwlock));
    ret = bpf_map_lookup_elem(__obj_module.nm_map_fd, obj, &ref);
    if (ret < 0) {
        goto err;
    }

    if (ref.count > 0) {
        ref.count--;
    }

    if (ref.count == 0) {
        ret = bpf_map_delete_elem(__obj_module.nm_map_fd, obj);
    } else {
        ret = bpf_map_update_elem(__obj_module.nm_map_fd, obj, &ref, BPF_ANY);
    }

err:
    (void)pthread_rwlock_unlock(&(__obj_module.rwlock));
    return ret;
}

int nm_add(struct nm_s *obj)
{
    int ret;
    struct obj_ref_s ref = {0};

    if (__obj_module.nm_map_fd <= 0) {
        return -1;
    }

    (void)pthread_rwlock_wrlock(&(__obj_module.rwlock));
    ret = bpf_map_lookup_elem(__obj_module.nm_map_fd, obj, &ref);
    if (!ret) {
        ref.count = 1;
        ret = bpf_map_update_elem(__obj_module.nm_map_fd, obj, &ref, BPF_ANY);
    } else {
        ref.count++;
        ret = bpf_map_update_elem(__obj_module.nm_map_fd, obj, &ref, BPF_ANY);
    }

    (void)pthread_rwlock_unlock(&(__obj_module.rwlock));

    return ret;
}

char is_nm_exist(struct nm_s *obj)
{
    struct obj_ref_s ref = {0};

    if (__obj_module.nm_map_fd <= 0) {
        return 0;
    }
    int ret = bpf_map_lookup_elem(__obj_module.nm_map_fd, obj, &ref);
    return (ret == 0) ? 1 : 0;
}

char is_proc_exist(struct proc_s *obj)
{
    struct obj_ref_s ref = {0};

    if (__obj_module.proc_map_fd <= 0) {
        return 0;
    }
    int ret = bpf_map_lookup_elem(__obj_module.proc_map_fd, obj, &ref);
    return (ret == 0) ? 1 : 0;
}

char is_cgrp_exist(struct cgroup_s *obj)
{
    struct obj_ref_s ref = {0};

    if (__obj_module.cgrp_map_fd <= 0) {
        return 0;
    }
    int ret = bpf_map_lookup_elem(__obj_module.cgrp_map_fd, obj, &ref);
    return (ret == 0) ? 1 : 0;
}

static int get_id_by_name(const char* line, const char* map_name)
{
    char *p;
    size_t size;
    char ids[INT_LEN];
    if (!strstr(line, map_name)) {
        return 0;
    }

    p = strchr(line, ':');
    if (!p || (p <= line)) {
        return 0;
    }

    size = p - line;
    if (size >= INT_LEN) {
        return 0;
    }

    (void)memcpy(ids, line, size);
    ids[size] = 0;
    return atoi(ids);
}

static int find_map_id_by_name(const char* map_name)
{
    int id = 0;
    char cmd[COMMAND_LEN];
    char line[LINE_BUF_LEN];
    FILE *f;

    cmd[0] = 0;
    (void)snprintf(cmd, COMMAND_LEN, MAP_OBJS_DUMP, map_name);
    f = popen(cmd, "r");
    if (f == NULL) {
        return 0;
    }

    while (!feof(f)) {
        line[0] = 0;
        if (fgets(line, LINE_BUF_LEN, f) == NULL) {
            goto out;
        }
        SPLIT_NEWLINE_SYMBOL(line);
        id =  get_id_by_name((const char*)line, (const char*)map_name);
        if (id > 0) {
            goto out;
        }
    }

out:
    (void)pclose(f);
    return id;
}

static int get_map_fd_by_name(const char* map_name)
{
    u32 id;

    id = find_map_id_by_name(map_name);
    if (id == 0) {
        return 0;
    }
    return bpf_map_get_fd_by_id(id);
}

int obj_module_create_map(char *name)
{
    int map_fd = -1;
    char pin_path[PATH_LEN];
    int limit = 100 * 1024 * 1024;    // 100M

    struct rlimit rlim_new = {
        .rlim_cur   = limit,
        .rlim_max   = limit,
    };
    if (setrlimit(RLIMIT_MEMLOCK, (const struct rlimit *)&rlim_new) != 0) {
        ERROR("object module failed to increase RLIMIT_MEMLOCK limit!\n");
        return -1;
    }

    pin_path[0] = 0;
    if (!strcmp(name, "proc_obj_map")) {
        map_fd = bpf_create_map_name(BPF_MAP_TYPE_HASH, "proc_obj_map",
                                     sizeof(struct proc_s), sizeof(struct obj_ref_s), PROC_MAP_MAX_ENTRIES, 0);
        if (map_fd < 0) {
            ERROR("object module create %s failed.\n", name);
            return -1;
        }
        strncpy(pin_path, PROC_MAP_PATH, PATH_LEN - 1);
    }
    if (bpf_obj_pin(map_fd, pin_path) < 0) {
        ERROR("object module pin %s failed.\n", name);
        return -1;
    }

    return 0;
}

char obj_module_init_ok(void)
{
    int flag = 0;

    if (__obj_module.cgrp_map_fd > 0) {
        flag |= CGRP_MAP_INIT_OK;
    }
    if (__obj_module.nm_map_fd > 0) {
        flag |= NM_MAP_INIT_OK;
    }
    if (__obj_module.proc_map_fd > 0) {
        flag |= PROC_MAP_INIT_OK;
    }

    return flag;
}

void obj_module_set_maps_fd(void)
{
    if (__obj_module.cgrp_map_fd == 0) {
        __obj_module.cgrp_map_fd = get_map_fd_by_name("cgrp_obj_map");
    }
    if (__obj_module.nm_map_fd == 0) {
        __obj_module.nm_map_fd = get_map_fd_by_name("nm_obj_map");
    }
    if (__obj_module.proc_map_fd == 0) {
        __obj_module.proc_map_fd = get_map_fd_by_name("proc_obj_map");
    }
}

void obj_module_init(void)
{
    if (__obj_module.cgrp_map_fd == 0) {
        __obj_module.cgrp_map_fd = get_map_fd_by_name("cgrp_obj_map");
    }
    if (__obj_module.nm_map_fd == 0) {
        __obj_module.nm_map_fd = get_map_fd_by_name("nm_obj_map");
    }
    if (__obj_module.proc_map_fd == 0) {
        __obj_module.proc_map_fd = get_map_fd_by_name("proc_obj_map");
    }

    if (__obj_module.init == 0) {
        (void)pthread_rwlock_init(&(__obj_module.rwlock), NULL);
    }
    __obj_module.init = 1;
}

void obj_module_exit(void)
{
    if (__obj_module.cgrp_map_fd > 0) {
        (void)close(__obj_module.cgrp_map_fd);
    }

    if (__obj_module.proc_map_fd > 0) {
        (void)close(__obj_module.proc_map_fd);
    }

    if (__obj_module.nm_map_fd > 0) {
        (void)close(__obj_module.nm_map_fd);
    }

    (void)pthread_rwlock_destroy(&(__obj_module.rwlock));
    (void)memset(&__obj_module, 0, sizeof(__obj_module));
}