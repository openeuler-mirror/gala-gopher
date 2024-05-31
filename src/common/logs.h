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

#pragma once

#include <pthread.h>
#include "common.h"

#if !defined(UTEST)
#define METRICS_LOGS_FILESIZE_MAX   (1024 * 1024 * 1024)
#define METRICS_LOGS_FILESIZE       (100 * 1024 * 1024) // 100mb
#define EVENT_LOGS_FILESIZE         (100 * 1024 * 1024)
#define DEBUG_LOGS_FILESIZE         (200 * 1024 * 1024)
#define META_LOGS_FILESIZE          (100 * 1024 * 1024)

#define METRICS_LOGS_MAXNUM         (100)
#define EVENT_LOGS_MAXNUM           (100)

#else

#define LOGS_FILE_SIZE              (1024)
#define METRICS_LOGS_FILESIZE_MAX   (2 * LOGS_FILE_SIZE)
#define METRICS_LOGS_FILESIZE       LOGS_FILE_SIZE
#define EVENT_LOGS_FILESIZE         LOGS_FILE_SIZE
#define DEBUG_LOGS_FILESIZE         LOGS_FILE_SIZE
#define META_LOGS_FILESIZE          LOGS_FILE_SIZE

#define METRICS_LOGS_MAXNUM         (5)
#define EVENT_LOGS_MAXNUM           (5)
#endif

#define LOGS_SWITCH_ON  1
#define PATTERN_META_LOGGER_STR "%s\n" // "%m%n"
#define PATTERN_DEBUG_LOGGER_STR "%02d/%02d/%02d %02d:%02d:%02d  - %s" // "%D{%m/%d/%y %H:%M:%S}  - %m"
#define PATTERN_METRICS_LOGGER_STR "%s" // "%m"
#define PATTERN_EVENT_LOGGER_STR "%s\n" // "%m%n"


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
    char is_debug_log;
    char is_metric_out_log;
    char is_event_out_log;
    char is_meta_out_log;
    long metrics_logs_filesize;
} LogsMgr;

enum logger_level_t {
    LOGGER_DEBUG = 0,
    LOGGER_INFO,
    LOGGER_WARN,
    LOGGER_ERROR,
    LOGGER_FATAL
};

struct logger {
    pthread_rwlock_t rwlock;
    char *pattern;
    enum logger_level_t level;
    char full_path_name[PATH_LEN];
    char base_path_name[PATH_LEN];
    char *name;
    int file_fd;
    size_t buf_len;
    size_t max_file_size;
    int max_backup_index; // for save max back up  fname.log.1, fname.log.2, fname.log.3
    int curr_backup_index; // record current back up index.
};

int read_metrics_logs(char logs_file_name[], size_t size);

int wr_metrics_logs(const char* logs, size_t logs_len);

void wr_meta_logs(const char* logs);

int wr_event_logs(const char* logs, size_t logs_len);

void rm_log_file(const char full_path[]);

void destroy_log_mgr(struct log_mgr_s* mgr);
void clear_log_dir(const char full_path[]);
int init_log_mgr(struct log_mgr_s* mgr, int is_meta_out_log, char *logLevel);

struct log_mgr_s* create_log_mgr(const char *app_name, int is_metric_out_log, int is_event_out_log);

#endif

