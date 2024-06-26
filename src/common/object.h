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
 * Author: Mr.lu
 * Create: 2022-06-18
 * Description: object defined
 ******************************************************************************/
#ifndef __GOPHER_OBJ_H__
#define __GOPHER_OBJ_H__

#define GOPHER_MAP_DIR              "/sys/fs/bpf/gala-gopher"

#define CGRP_MAP_MAX_ENTRIES        100
#define NM_MAP_MAX_ENTRIES          100
#define PROC_MAP_MAX_ENTRIES        1000

enum cgp_type_e {
    CGP_TYPE_CPUACCT = 0,
    CGP_TYPE_MEM,
    CGP_TYPE_BLKIO,
    CGP_TYPE_PIDS,
    CGP_TYPE_NET,
    CGP_TYPE_HUGETLB,
    CGP_TYPE_MAX
};

struct proc_s {
    unsigned int proc_id;           // process id
};

struct cgroup_s {
    unsigned int knid;              // Inode id of cgroup
    enum cgp_type_e type;           // Type of cgroup
};

enum nm_type_e {
    NM_TYPE_CGRP = 0,
    NM_TYPE_MNT,
    NM_TYPE_NET,
    NM_TYPE_PID,
    NM_TYPE_MAX
};

struct nm_s {
    unsigned int id;                // namespace id
    enum nm_type_e type;            // Type of namespace
};

struct obj_ref_s {
    unsigned int count;             // References of object
};

#endif
