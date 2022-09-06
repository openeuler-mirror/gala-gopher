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

enum container_status_e {
    CONTAINER_STATUS_RUNNING = 0,
    CONTAINER_STATUS_RESTARTING,
    CONTAINER_STATUS_STOP
};

typedef struct container_info_s {
    enum container_status_e status;
    char abbrContainerId[CONTAINER_ID_LEN];
} container_info;

typedef struct container_tbl_s {
    unsigned int num;
    container_info *cs;
} container_tbl;

container_tbl* get_all_container(void);
int get_container_id_by_pid(unsigned int pid, char *container_id, unsigned int buf_len);
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

#endif
