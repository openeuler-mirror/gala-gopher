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
 * Description: pod definitions
 ******************************************************************************/
#ifndef __POD_MNG_H__
#define __POD_MNG_H__

#include "hash.h"

#define MAX_CGRP_PATH 512

#define POD_NAME_LEN 64
#define FAKE_POD_ID "-no-pod" // fake pod id for host container

enum id_ret_t {
    ID_FAILED = -1,
    ID_CON_POD = 0, // pod with containers
    ID_CON_ONLY = 1, // host container
    ID_POD_ONLY = 2  // pod without containers for now
};

struct con_info_s {
    u32 flags;
    u32 cpucg_inode;
    struct pod_info_s *pod_info_ptr; // No need to free
    char con_id[CONTAINER_ABBR_ID_LEN + 1];
    char container_name[CONTAINER_NAME_LEN];
    char libc_path[PATH_LEN];
    char libssl_path[PATH_LEN];
};

struct containers_hash_t {
    H_HANDLE;
    char con_id[CONTAINER_ABBR_ID_LEN + 1]; // key
    struct con_info_s con_info; // value
};

struct pod_info_s {
    char pod_id[POD_ID_LEN + 1];
    char pod_name[POD_NAME_LEN];
    char pod_ip_str[INET6_ADDRSTRLEN];
    struct containers_hash_t *con_head; // TODO: This field is invalid during ipc communication. Change to an array?
};

struct pod_info_s *get_pod_info_from_pod_id(char *pod_id);
struct pod_info_s *get_pod_info_from_pod_name(char *pod_name_origin);
void existing_pod_mk_process(char *pod_name);
enum id_ret_t get_pod_container_id(char *cgrp_path, char *pod_id, char *con_id);
struct con_info_s *get_con_info(char *pod_id, char *con_id);
struct pod_info_s *get_pod_info(char *pod_id);
void del_pods();
void cgrp_mk_process(char *pod_id, char *con_id, enum id_ret_t id_ret);
void cgrp_rm_process(char *pod_id, char *con_id, enum id_ret_t id_ret);
struct con_info_s *get_and_add_con_info(char *pod_id, char *container_id);
struct pod_info_s *get_and_add_pod_info(char *pod_name);

enum filter_op_t {
    FILTER_OP_ADD,
    FILTER_OP_RM,
};

int filter_pod_op(const char *pod_id, enum filter_op_t op);
int filter_container_op(const char *container_id, enum filter_op_t op);

#endif