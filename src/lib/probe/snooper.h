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
 * Author: luzhihao
 * Create: 2023-04-06
 * Description: snooper managment
 ******************************************************************************/
#ifndef __GOPHER_SNOOPER__
#define __GOPHER_SNOOPER__

#pragma once

#include "base.h"
#include "ipc.h"
#include "probe_mng.h"

enum snooper_conf_e {
    SNOOPER_CONF_APP = 0,
    SNOOPER_CONF_PROC_ID,
    SNOOPER_CONF_POD_ID,
    SNOOPER_CONF_CONTAINER_ID,
    SNOOPER_CONF_FIXED_LABEL,
    SNOOPER_CONF_POD_LABELS,

    SNOOPER_CONF_MAX
};

struct snooper_app_s {
    char comm[TASK_COMM_LEN + 1];
    char *cmdline;
    char *debuging_dir;
};

struct snooper_conf_s {
    enum snooper_conf_e type;
    union {
        struct snooper_app_s app;
        u32 proc_id;
        char pod_id[POD_ID_LEN + 1];
        char container_id[CONTAINER_ABBR_ID_LEN + 1];
    } conf;
};

void print_snooper(struct probe_s *probe, void *json);
int parse_snooper(struct probe_s *probe, const void *json);
void free_snooper_conf(struct snooper_conf_s* snooper_conf);
void free_snooper_obj(struct snooper_obj_s* snooper_obj);
int load_snooper_bpf(struct probe_mng_s *probe_mng);
void unload_snooper_bpf(struct probe_mng_s *probe_mng);
void backup_snooper(struct probe_s *probe, struct probe_s *probe_backup);
void rollback_snooper(struct probe_s *probe, struct probe_s *probe_backup);
int send_snooper_obj(struct probe_s *probe);
#endif

