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

#define MAX_CACHE_PROC_NUM 1024
#define PROC_COMM_LEN 16
#define MAX_PATH_SIZE 128

#define CMD_CAT_PROC_COMM "cat /proc/%d/comm"
#define CMD_CAT_THRD_COMM "cat /proc/%d/task/%d/comm"
#define MAX_CMD_SIZE 64

typedef struct {
    char id[CONTAINER_ABBR_ID_LEN + 1];
    char name[CONTAINER_NAME_LEN];
} container_info_t;

typedef struct {
    int tgid;
    char comm[PROC_COMM_LEN];
    char proc_name[PROC_CMDLINE_LEN];
    container_info_t container_info;
    fd_info_t **fd_table;
    struct proc_symbs_s *symbs;
    UT_hash_handle hh;
} proc_info_t;

void HASH_add_proc_info(proc_info_t **proc_table, proc_info_t *proc_info);
void HASH_del_proc_info(proc_info_t **proc_table, proc_info_t *proc_info);
proc_info_t *HASH_find_proc_info(proc_info_t **proc_table, int tgid);
unsigned int HASH_count_proc_table(proc_info_t **proc_table);

void HASH_add_proc_info_with_LRU(proc_info_t **proc_table, proc_info_t *proc_info);
proc_info_t *HASH_find_proc_info_with_LRU(proc_info_t **proc_table, int tgid);

proc_info_t *add_proc_info(proc_info_t **proc_table, int tgid);
proc_info_t *get_proc_info(proc_info_t **proc_table, int tgid);
fd_info_t *add_fd_info(proc_info_t *proc_info, int fd);
fd_info_t *get_fd_info(proc_info_t *proc_info, int fd);
struct proc_symbs_s *add_symb_info(proc_info_t *proc_info);
struct proc_symbs_s *get_symb_info(proc_info_t *proc_info);

void free_proc_info(proc_info_t *proc_info);
void free_proc_table(proc_info_t **proc_table);

// util
int set_proc_comm(int tgid, char *comm, int size);
int set_thrd_comm(int pid, int tgid, char *comm, int size);

#endif