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
 * Create: 2022-07-18
 * Description: gopher logs
 ******************************************************************************/
#ifndef __GOPHER_LOGS_H__
#define __GOPHER_LOGS_H__

#ifdef __cplusplus
extern "C" {
#endif
#pragma once

#include <pthread.h>
#include "common.h"

#define LOGS_SWITCH_ON  1

struct file_node_s {
    size_t len;
    int file_id;
};

struct files_queue_s {
    pthread_rwlock_t rwlock;
    int next_file_id;
    size_t que_size;
    int front;
    int rear;
    struct file_node_s current;
    struct file_node_s queue[0];
};

typedef struct log_mgr_s {
    struct files_queue_s *metrics_files;
    struct files_queue_s *event_files;
    char app_name[PATH_LEN];
    char debug_path[PATH_LEN];
    char event_path[PATH_LEN];
    char metrics_path[PATH_LEN];
    char meta_path[PATH_LEN];
    char raw_path[PATH_LEN];
    char is_debug_log;
    char is_metric_out_log;
    char is_event_out_log;
    char is_meta_out_log;
} LogsMgr;

void wr_raw_logs(const char* format, ...);
int read_metrics_logs(char logs_file_name[], size_t size);
int wr_metrics_logs(const char* logs, size_t logs_len);

void wr_meta_logs(const char* logs);

int wr_event_logs(const char* logs, size_t logs_len);
int read_event_logs(char logs_file_name[], size_t size);

void rm_log_file(char full_path[]);

void destroy_log_mgr(struct log_mgr_s* mgr);
int init_log_mgr(struct log_mgr_s* mgr, int is_meta_out_log, char *logLevel);
struct log_mgr_s* create_log_mgr(const char *app_name, int is_metric_out_log, int is_event_out_log);

#ifdef __cplusplus
}
#endif

#endif

