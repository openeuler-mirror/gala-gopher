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
 * Description: header file for enriching process information of thread profiling event
 ******************************************************************************/
#ifndef __PROC_INFO_H__
#define __PROC_INFO_H__

#include <uthash.h>
#include "common.h"
#include "fd_info.h"
#include "symbol.h"

#define MAX_CACHE_PROC_NUM 64
#define MAX_CACHE_THRD_NUM 1024
#define MAX_CACHE_EVENT_NUM 100
#define MAX_PATH_SIZE 128

#define CMD_CAT_PROC_COMM "cat /proc/%d/comm"
#define CMD_CAT_THRD_COMM "cat /proc/%d/task/%d/comm"
#define MAX_CMD_SIZE 64

typedef struct {
    char id[CONTAINER_ABBR_ID_LEN + 1];
    char name[CONTAINER_NAME_LEN];
} container_info_t;

struct _event_elem;
struct _proc_info;
struct _thrd_info;
typedef struct _event_elem event_elem_t;
typedef struct _proc_info proc_info_t;
typedef struct _thrd_info thrd_info_t;

struct _event_elem {
    void *data;                 // 内存随 struct _event_elem 一起分配，挂在尾部
    thrd_info_t *thrd_info;
    event_elem_t *prev, *next;
};

struct _thrd_info {
    int pid;
    proc_info_t *proc_info;
    char comm[TASK_COMM_LEN];
    int evt_num;
    event_elem_t *cached_evts;
    time_t last_report_time;
    UT_hash_handle hh;
};

struct _proc_info {
    int tgid;
    char comm[TASK_COMM_LEN];
    container_info_t container_info;
    fd_info_t **fd_table;
    thrd_info_t **thrd_table;
    struct proc_symbs_s *symbs;
    UT_hash_handle hh;
};

void HASH_add_proc_info(proc_info_t **proc_table, proc_info_t *proc_info);
void HASH_del_proc_info(proc_info_t **proc_table, proc_info_t *proc_info);
proc_info_t *HASH_find_proc_info(proc_info_t **proc_table, int tgid);
unsigned int HASH_count_proc_table(proc_info_t **proc_table);

void HASH_add_proc_info_with_LRU(proc_info_t **proc_table, proc_info_t *proc_info);
proc_info_t *HASH_find_proc_info_with_LRU(proc_info_t **proc_table, int tgid);
void HASH_add_thrd_info_with_LRU(thrd_info_t **thrd_table, thrd_info_t *thrd_info);
thrd_info_t *HASH_find_thrd_info_with_LRU(thrd_info_t **thrd_table, int pid);

proc_info_t *add_proc_info(proc_info_t **proc_table, int tgid);
proc_info_t *get_proc_info(proc_info_t **proc_table, int tgid);
thrd_info_t *add_thrd_info(proc_info_t *proc_info, int pid);
thrd_info_t *get_thrd_info(proc_info_t *proc_info, int pid);
fd_info_t *add_fd_info(proc_info_t *proc_info, int fd);
fd_info_t *get_fd_info(proc_info_t *proc_info, int fd);
struct proc_symbs_s *add_symb_info(proc_info_t *proc_info);
struct proc_symbs_s *get_symb_info(proc_info_t *proc_info);

void free_proc_info(proc_info_t *proc_info);
void free_proc_table(proc_info_t **proc_table);
void free_thrd_info(thrd_info_t *thrd_info);
void free_thrd_table(thrd_info_t **thrd_table);
void clean_cached_events(thrd_info_t *thrd_info);

event_elem_t *create_event_elem(unsigned int data_size);
void delete_first_k_events(thrd_info_t *thrd_info, int k);

// util
int set_proc_comm(int tgid, char *comm, int size);
int set_thrd_comm(int pid, int tgid, char *comm, int size);

#endif