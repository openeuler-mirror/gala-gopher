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
 * Author: algorithmofdish
 * Create: 2023-04-03
 * Description: enriching process information of thread profiling event
 ******************************************************************************/
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <utlist.h>
#include "debug_elf_reader.h"
#include "elf_symb.h"
#include "container.h"
#include "tprofiling.h"
#include "proc_info.h"

void HASH_add_proc_info(proc_info_t **proc_table, proc_info_t *proc_info)
{
    HASH_ADD_INT(*proc_table, tgid, proc_info);
}

void HASH_del_proc_info(proc_info_t **proc_table, proc_info_t *proc_info)
{
    HASH_DEL(*proc_table, proc_info);
}

proc_info_t *HASH_find_proc_info(proc_info_t **proc_table, int tgid)
{
    proc_info_t *pi;

    HASH_FIND_INT(*proc_table, &tgid, pi);
    return pi;
}

void HASH_add_proc_info_with_LRU(proc_info_t **proc_table, proc_info_t *proc_info)
{
    proc_info_t *pi, *tmp;

    if (HASH_COUNT(*proc_table) >= MAX_CACHE_PROC_NUM) {
        HASH_ITER(hh, *proc_table, pi, tmp) {
            HASH_DEL(*proc_table, pi);
            free_proc_info(pi);
            break;
        }
    }

    HASH_add_proc_info(proc_table, proc_info);
}

proc_info_t *HASH_find_proc_info_with_LRU(proc_info_t **proc_table, int tgid)
{
    proc_info_t *pi;

    pi = HASH_find_proc_info(proc_table, tgid);
    if (pi) {
        HASH_del_proc_info(proc_table, pi);
        HASH_add_proc_info(proc_table, pi);
    }

    return pi;
}

unsigned int HASH_count_proc_table(proc_info_t **proc_table)
{
    return HASH_COUNT(*proc_table);
}

void HASH_add_thrd_info_with_LRU(thrd_info_t **thrd_table, thrd_info_t *thrd_info)
{
    thrd_info_t *ti, *tmp;

    if (HASH_COUNT(*thrd_table) >= MAX_CACHE_THRD_NUM) {
        HASH_ITER(hh, *thrd_table, ti, tmp) {
            HASH_DEL(*thrd_table, ti);
            free_thrd_info(ti);
            break;
        }
    }

    HASH_ADD_INT(*thrd_table, pid, thrd_info);
}

thrd_info_t *HASH_find_thrd_info_with_LRU(thrd_info_t **thrd_table, int pid)
{
    thrd_info_t *ti;

    HASH_FIND_INT(*thrd_table, &pid, ti);
    if (ti) {
        HASH_DEL(*thrd_table, ti);
        HASH_ADD_INT(*thrd_table, pid, ti);
    }

    return ti;
}

int set_proc_comm(int tgid, char *comm, int size)
{
    char cmd[MAX_CMD_SIZE];
    int ret;

    ret = snprintf(cmd, sizeof(cmd), CMD_CAT_PROC_COMM, tgid);
    if (ret < 0 || ret >= sizeof(cmd)) {
        TP_ERROR("Failed to set command.\n");
        return -1;
    }

    ret = exec_cmd(cmd, comm, size);
    if (ret) {
        TP_ERROR("Failed to execute command: %s.\n", cmd);
        return -1;
    }

    return 0;
}

int set_thrd_comm(int pid, int tgid, char *comm, int size)
{
    char cmd[MAX_CMD_SIZE];
    int ret;

    ret = snprintf(cmd, sizeof(cmd), CMD_CAT_THRD_COMM, tgid, pid);
    if (ret < 0 || ret >= sizeof(cmd)) {
        TP_ERROR("Failed to set command.\n");
        return -1;
    }

    ret = exec_cmd(cmd, comm, size);
    if (ret) {
        TP_ERROR("Failed to execute command: %s.\n", cmd);
        return -1;
    }

    return 0;
}

static int fill_container_info(proc_info_t *proc_info)
{
    container_info_t *ci = &proc_info->container_info;
    int ret;

    ret = get_container_id_by_pid(proc_info->tgid, ci->id, sizeof(ci->id));
    if (ret || ci->id[0] == '\0') {
        return -1;
    }

    ret = get_container_name(ci->id, ci->name, sizeof(ci->name));
    if (ret) {
        return -1;
    }

    return 0;
}

static int fill_proc_info(proc_info_t *proc_info)
{
    int ret;

    ret = set_proc_comm(proc_info->tgid, proc_info->comm, sizeof(proc_info->comm));
    if (ret) {
        return -1;
    }

    // process may be not a container, so failure is allowed.
    (void)fill_container_info(proc_info);

    return 0;
}

proc_info_t *add_proc_info(proc_info_t **proc_table, int tgid)
{
    proc_info_t *pi;
    int ret;

    pi = (proc_info_t *)calloc(1, sizeof(proc_info_t));
    if (pi == NULL) {
        TP_ERROR("Failed to allocate process info.\n");
        return NULL;
    }

    pi->tgid = tgid;
    ret = fill_proc_info(pi);
    if (ret) {
        free(pi);
        return NULL;
    }

    pi->fd_table = (fd_info_t **)malloc(sizeof(fd_info_t *));
    if (pi->fd_table == NULL) {
        TP_ERROR("Failed to allocate fd table.\n");
        free(pi);
        return NULL;
    }
    *(pi->fd_table) = NULL;

    pi->thrd_table = (thrd_info_t **)malloc(sizeof(thrd_info_t *));
    if (pi->thrd_table == NULL) {
        TP_ERROR("Failed to allocate thread table.\n");
        free(pi);
        return NULL;
    }
    *(pi->thrd_table) = NULL;

    HASH_add_proc_info_with_LRU(proc_table, pi);
    return pi;
}

proc_info_t *get_proc_info(proc_info_t **proc_table, int tgid)
{
    proc_info_t *pi;

    pi = HASH_find_proc_info_with_LRU(proc_table, tgid);
    if (pi == NULL) {
        pi = add_proc_info(proc_table, tgid);
    }

    return pi;
}

thrd_info_t *add_thrd_info(proc_info_t *proc_info, int pid)
{
    thrd_info_t *ti;

    ti = (thrd_info_t *)calloc(1, sizeof(thrd_info_t));
    if (ti == NULL) {
        TP_ERROR("Failed to allocate thread info.\n");
        return NULL;
    }

    ti->pid = pid;
    ti->proc_info = proc_info;

    HASH_add_thrd_info_with_LRU(proc_info->thrd_table, ti);
    return ti;
}

thrd_info_t *get_thrd_info(proc_info_t *proc_info, int pid)
{
    thrd_info_t *ti;

    ti = HASH_find_thrd_info_with_LRU(proc_info->thrd_table, pid);
    if (ti == NULL) {
        ti = add_thrd_info(proc_info, pid);
    }

    return ti;
}

// get fd info from `/proc/<tgid>/fd/<fd>`
fd_info_t *add_fd_info(proc_info_t *proc_info, int fd)
{
    fd_info_t *fi;
    int ret;

    fi = (fd_info_t *)malloc(sizeof(fd_info_t));
    if (fi == NULL) {
        TP_ERROR("Failed to allocate fd info.\n");
        return NULL;
    }
    memset(fi, 0, sizeof(fd_info_t));

    fi->fd = fd;
    ret = fill_fd_info(fi, proc_info->tgid);
    if (ret) {
        free(fi);
        return NULL;
    }

    HASH_add_fd_info_with_LRU(proc_info->fd_table, fi);
    return fi;
}

fd_info_t *get_fd_info(proc_info_t *proc_info, int fd)
{
    fd_info_t *fi;

    fi = HASH_find_fd_info_with_LRU(proc_info->fd_table, fd);
    if (fi == NULL) {
        fi = add_fd_info(proc_info, fd);
    }

    return fi;
}

#define SYMB_DEBUG_DIR "/usr/lib/debug"
static struct elf_reader_s gElfReader = {
    .global_dbg_dir = SYMB_DEBUG_DIR
};

struct proc_symbs_s *add_symb_info(proc_info_t *proc_info)
{
    struct proc_symbs_s *symbs;

    symbs = proc_load_all_symbs(&gElfReader, proc_info->tgid);
    proc_info->symbs = symbs;

    return symbs;
}

static void update_proc_symbs(struct proc_symbs_s *symbs)
{
    struct mod_s *mod;

    for (int i = 0; i < symbs->mods_count; i++) {
        mod = symbs->mods[i];
        if (mod && mod->mod_type == MODULE_JVM) {
            mod->mod_symbs = update_symb_from_jvm_sym_file((const char *)mod->__mod_info.name);
            break;
        }
    }
    time(&symbs->update_time);
}

#define SYMB_UPDATE_DURATION_SEC 300    // TODO: as a config?

struct proc_symbs_s *get_symb_info(proc_info_t *proc_info)
{
    struct proc_symbs_s *symbs;
    time_t now;

    symbs = proc_info->symbs;
    if (symbs == NULL) {
        symbs = add_symb_info(proc_info);
        if (symbs == NULL) {
            return NULL;
        }
    }

    time(&now);
    if (symbs->update_time + SYMB_UPDATE_DURATION_SEC < now) {
        update_proc_symbs(symbs);
    }

    return symbs;
}

void free_proc_info(proc_info_t *proc_info)
{
    if (proc_info == NULL) {
        return;
    }
    
    if (proc_info->fd_table != NULL) {
        free_fd_table(proc_info->fd_table);
        free(proc_info->fd_table);
    }

    if (proc_info->thrd_table != NULL) {
        free_thrd_table(proc_info->thrd_table);
        free(proc_info->thrd_table);
    }

    if (proc_info->symbs != NULL) {
        proc_delete_all_symbs(proc_info->symbs);
    }

    free(proc_info);
}

void free_proc_table(proc_info_t **proc_table)
{
    proc_info_t *pi, *tmp;

    if (*proc_table == NULL) {
        return;
    }

    HASH_ITER(hh, *proc_table, pi, tmp) {
        HASH_DEL(*proc_table, pi);
        free_proc_info(pi);
    }

    *proc_table = NULL;
}

static void free_cached_events(event_elem_t *cached_evts)
{
    event_elem_t *evt, *tmp;

    if (cached_evts == NULL) {
        return;
    }

    DL_FOREACH_SAFE(cached_evts, evt, tmp) {
        DL_DELETE(cached_evts, evt);
        free(evt);
    }
}

void clean_cached_events(thrd_info_t *thrd_info)
{
    free_cached_events(thrd_info->cached_evts);
    thrd_info->cached_evts = NULL;
    thrd_info->evt_num = 0;
}

void free_thrd_info(thrd_info_t *thrd_info)
{
    if (thrd_info == NULL) {
        return;
    }

    free_cached_events(thrd_info->cached_evts);

    free(thrd_info);
}

void free_thrd_table(thrd_info_t **thrd_table)
{
    thrd_info_t *ti, *tmp;

    if (*thrd_table == NULL) {
        return;
    }

    HASH_ITER(hh, *thrd_table, ti, tmp) {
        HASH_DEL(*thrd_table, ti);
        free_thrd_info(ti);
    }

    *thrd_table = NULL;
}

event_elem_t *create_event_elem(unsigned int data_size)
{
    event_elem_t *elem;

    if (data_size == 0) {
        TP_ERROR("Event data size must be non-zero.\n");
        return NULL;
    }

    elem = (event_elem_t *)calloc(1, sizeof(event_elem_t) + data_size);
    if (elem == NULL) {
        TP_ERROR("Failed to malloc event element memory.\n");
        return NULL;
    }
    elem->data = (void *)(elem + 1);

    return elem;
}

void delete_first_k_events(thrd_info_t *thrd_info, int k)
{
    event_elem_t *cached_evt, *tmp;
    int i = 0;

    DL_FOREACH_SAFE(thrd_info->cached_evts, cached_evt, tmp) {
        if (i == k) {
            break;
        }
        DL_DELETE(thrd_info->cached_evts, cached_evt);
        free(cached_evt);
        i++;
    }
    thrd_info->evt_num -= k;

    if (thrd_info->evt_num == 0) {
        thrd_info->cached_evts = NULL;
    }
}