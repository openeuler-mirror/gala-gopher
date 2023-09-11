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
 * Author: Mr.lu
 * Create: 2021-07-26
 * Description: container header file
 ******************************************************************************/
#ifndef __CONTAINER_H__
#define __CONTAINER_H__

#include "common.h"

#define CONTAINER_OK       0
#define CONTAINER_ERR      (-1)
#define CONTAINER_NOTOK     (-2)

enum container_status_e {
    CONTAINER_STATUS_RUNNING = 0,
    CONTAINER_STATUS_RESTARTING,
    CONTAINER_STATUS_STOP
};

typedef struct container_info_s {
    enum container_status_e status;
    char abbrContainerId[CONTAINER_ID_LEN + 1];
} container_info;

typedef struct container_tbl_s {
    unsigned int num;
    container_info *cs;
} container_tbl;

container_tbl* get_all_container(void);
int get_container_id_by_pid_cpuset(const char *pid, char *container_id, unsigned int buf_len);
int get_elf_path(unsigned int pid, char elf_path[], int max_path_len, const char *comm);
int get_elf_path_by_con_id(char *container_id, char elf_path[], int max_path_len, const char *comm);
void free_container_tbl(container_tbl **pcstbl);
int get_container_merged_path(const char *abbr_container_id, char *path, unsigned int len);
int exec_container_command(const char *abbr_container_id, const char *exec, char *buf, unsigned int len);
int get_container_cpucg_dir(const char *abbr_container_id, char dir[], unsigned int dir_len);
int get_container_memcg_dir(const char *abbr_container_id, char dir[], unsigned int dir_len);
int get_container_pidcg_dir(const char *abbr_container_id, char dir[], unsigned int dir_len);
int get_container_netcg_dir(const char *abbr_container_id, char dir[], unsigned int dir_len);
int get_container_cpucg_inode(const char *abbr_container_id, unsigned int *inode);
int get_container_memcg_inode(const char *abbr_container_id, unsigned int *inode);
int get_container_pidcg_inode(const char *abbr_container_id, unsigned int *inode);
int get_container_netns_id(const char *abbr_container_id, unsigned int *id);
int get_container_mntns_id(const char *abbr_container_id, unsigned int *id);
int get_container_pid(const char *abbr_container_id, unsigned int *pid);
int get_container_name(const char *abbr_container_id, char name[], unsigned int len);
int get_container_pod(const char *abbr_container_id, char pod[], unsigned int len);
int get_container_pod_id(const char *abbr_container_id, char pod_id[], unsigned int len);
int get_container_pod_labels(const char *abbr_container_id, char pod_labels[], unsigned int len);
int get_pod_ip(const char *abbr_container_id, char *pod_ip_str, int len);
container_tbl* list_containers_by_pod_id(const char *pod_id);
int enter_container_netns(const char *container_id);
int exit_container_netns(int netns_fd);
int enter_proc_netns(u32 pid);
int is_container_proc(u32 pid);

#endif
