******************************************************************************
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
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include <log4cplus/logger.h>
#include <log4cplus/fileappender.h>
#include <log4cplus/loggingmacros.h>
#include <log4cplus/initializer.h>

#include "logs.h"

#define INVALID_FILE_ID         (-1)
#define IS_VALID_FILE_ID(id)    ((id) != INVALID_FILE_ID)

#if !defined(UTEST)
#define METRICS_LOGS_FILESIZE   (100 * 1024 * 1024)
#define EVENT_LOGS_FILESIZE     (100 * 1024 * 1024)
#define DEBUG_LOGS_FILESIZE     (100 * 1024 * 1024)
#define META_LOGS_FILESIZE      (100 * 1024 * 1024)

#define METRICS_LOGS_MAXNUM     (100)
#define EVENT_LOGS_MAXNUM       (100)
#else
#define LOGS_FILE_SIZE          (1024)
#define METRICS_LOGS_FILESIZE   LOGS_FILE_SIZE
#define EVENT_LOGS_FILESIZE     LOGS_FILE_SIZE
#define DEBUG_LOGS_FILESIZE     LOGS_FILE_SIZE
#define META_LOGS_FILESIZE      LOGS_FILE_SIZE

#define METRICS_LOGS_MAXNUM     (5)
#define EVENT_LOGS_MAXNUM       (5)
#endif

#define DEBUG_LOGS_FILE_NAME    "gopher_debug.log"
#define META_LOGS_FILE_NAME    "gopher_meta.log"

#define RM_COMMAND      "/usr/bin/rm -rf %s"

static struct log_mgr_s *local = NULL;

void rm_log_file(char full_path[])
{
    FILE *fp = NULL;
    char command[COMMAND_LEN];

    command[0] = 0;
    (void)snprintf(command, COMMAND_LEN, RM_COMMAND, full_path);
    fp = popen(command, "r");
    if (fp != NULL) {
        (void)pclose(fp);
        fp = NULL;
    }
    return;
}

static int get_file_name(struct log_mgr_s* mgr, char is_metrics, int file_id, char full_path[], size_t size)
{
    size_t path_len;
    char last_symbol;
    char ftype[COMMAND_LEN];

    ftype[0] = 0;
    if (is_metrics) {
        (void)strncpy(ftype, "metrics", COMMAND_LEN - 1);
    } else {
        (void)strncpy(ftype, "event", COMMAND_LEN - 1);
    }

    if (is_metrics) {
        path_len = strlen(mgr->metrics_path);
    } else {
        path_len = strlen(mgr->event_path);
    }

    if (path_len == 0) {
        ERROR("Get file_name failed, path is null.\n");
        return -1;
    }

    if (is_metrics) {
        last_symbol = mgr->metrics_path[path_len - 1];
    } else {
        last_symbol = mgr->event_path[path_len - 1];
    }

    full_path[0] = 0;
    if (last_symbol == '/') {
        (void)snprintf(full_path, size, "%sgopher_%s_%d",
            (is_metrics ? mgr->metrics_path : mgr->event_path), ftype, file_id);
    } else {
        (void)snprintf(full_path, size, "%s/gopher_%s_%d",
            (is_metrics ? mgr->metrics_path : mgr->event_path), ftype, file_id);
    }

    return 0;
}

#if 1
static char is_empty_queue(struct files_queue_s *files_que)
{
    return ((int)(files_que->rear % (int)files_que->que_size) == files_que->front);
}

static char is_full_queue(struct files_queue_s *files_que)
{
    return ((int)((files_que->rear + 1) % (int)files_que->que_size) == files_que->front);
}

static void init_files_queue(struct files_queue_s *files_que)
{
    files_que->rear = files_que->front = 0;
}

static int en_queue(struct files_queue_s *files_que, int file_id, size_t len)
{
    int pos;
    if (is_full_queue(files_que)) {
        ERROR("Files queue is full.(front = %d, rear = %d)\n", files_que->front, files_que->rear);
        return -1;
    }

    pos = files_que->rear % files_que->que_size;
    files_que->queue[pos].file_id = file_id;
    files_que->queue[pos].len = len;

    files_que->rear++;
    return 0;
}

static int de_queue(struct files_queue_s *files_que)
{
    int file_id, pos;
    if (is_empty_queue(files_que)) {
        return INVALID_FILE_ID;
    }

    pos = files_que->front;
    file_id = files_que->queue[pos].file_id;
    files_que->queue[pos].len = 0;
    files_que->queue[pos].file_id = INVALID_FILE_ID;

    files_que->front = (files_que->front + 1) % files_que->que_size;
    return file_id;
}

static struct files_queue_s* create_queue(size_t size)
{
    struct files_queue_s *files_que;
    size_t malloc_size = sizeof(struct files_queue_s) + size * sizeof(struct file_node_s);

    files_que = (struct files_queue_s *)malloc(malloc_size);
    if (files_que == NULL) {
        return NULL;
    }

    (void)memset(files_que, 0, malloc_size);
    files_que->que_size = size;
    files_que->current.file_id = INVALID_FILE_ID;

    init_files_queue(files_que);
    (void)pthread_rwlock_init(&(files_que->rwlock), NULL);
    return files_que;
}

static void destroy_queue(struct files_queue_s *files_que)
{
    if (files_que) {
        (void)pthread_rwlock_destroy(&(files_que->rwlock));
        (void)free(files_que);
    }
}

#endif

#if 1

static int que_remove_current(struct files_queue_s *files_que)
{
    int file_id;

    file_id = files_que->current.file_id;
    files_que->current.file_id = INVALID_FILE_ID;
    files_que->current.len = 0;
    return file_id;
}

static int que_pop_file(struct files_queue_s *files_que)
{
    int pop_file_id;

    (void)pthread_rwlock_wrlock(&(files_que->rwlock));

    pop_file_id = de_queue(files_que);

    if (!IS_VALID_FILE_ID(pop_file_id)) {
        pop_file_id = que_remove_current(files_que);
    }

    (void)pthread_rwlock_unlock(&(files_que->rwlock));
    return pop_file_id;
}

static int que_get_next_file(struct files_queue_s *files_que)
{
    (void)pthread_rwlock_wrlock(&(files_que->rwlock));

    size_t len = files_que->current.len;
    int current_file_id = files_que->current.file_id;

    if (IS_VALID_FILE_ID(current_file_id)) {
        if (en_queue(files_que, current_file_id, len)) {
            (void)pthread_rwlock_unlock(&(files_que->rwlock));
            return -1;
        }
    }
    files_que->current.file_id = files_que->next_file_id;
    files_que->current.len = 0;

    // Set to 0 if 'next_file_id' overflow occurs.
    files_que->next_file_id++;
    if (files_que->next_file_id < 0) {
        files_que->next_file_id = 0;
    }

    (void)pthread_rwlock_unlock(&(files_que->rwlock));
    return 0;
}

static char que_current_is_invalid(struct log_mgr_s *mgr, int is_metrics, int max_logs_len)
{
    struct files_queue_s *files_que = NULL;
    char invalid = 0;

    if (is_metrics) {
        files_que = mgr->metrics_files;
    } else {
        files_que = mgr->event_files;
    }

    (void)pthread_rwlock_wrlock(&(files_que->rwlock));

    //if (((int)files_que->current.len >= max_logs_len) || (files_que->current.len == 0)) {
    //    invalid = 1;
    //    goto out;
    //}

    char full_path[PATH_LEN];
    if (get_file_name(mgr, is_metrics, files_que->current.file_id, full_path, PATH_LEN)) {
        ERROR("is current invalid fail(get file name).\n");
        invalid = 1;
        goto out;
    }

    if (access(full_path, F_OK) == -1) {
        invalid = 1;
        goto out;
    }

out:
    (void)pthread_rwlock_unlock(&(files_que->rwlock));
    return invalid;
}

static void que_current_set_size(struct files_queue_s *files_que, size_t size)
{
    (void)pthread_rwlock_wrlock(&(files_que->rwlock));
    files_que->current.len += size;
    (void)pthread_rwlock_unlock(&(files_que->rwlock));
}

#endif

using namespace log4cplus;

Logger g_metrics_logger;
Logger g_event_logger;
Logger g_debug_logger;
Logger g_meta_logger;
Logger g_raw_logger;

static void init_all_logger(void)
{
    log4cplus::Initializer initalizer;
    g_metrics_logger = Logger::getInstance("prometheus.metrics");
    g_event_logger = Logger::getInstance("event");
    g_debug_logger = Logger::getInstance("debug");
    g_meta_logger = Logger::getInstance("meta");
    g_raw_logger = Logger::getInstance("raw");
}

#define __FULL_PATH_LEN (PATH_LEN * 2)

static char g_meta_abs_path[__FULL_PATH_LEN];
static int append_meta_logger(struct log_mgr_s * mgr)
{
    const char *fmt = "%s/%s", *fmt2 = "%s%s";

    size_t path_len = strlen(mgr->meta_path);
    if (path_len == 0) {
        ERROR("Meta path is null.\n");
        return -1;
    }

    g_meta_abs_path[0] = 0;
    if (mgr->meta_path[path_len - 1] == '/') {
        (void)snprintf(g_meta_abs_path, __FULL_PATH_LEN, fmt2, mgr->meta_path, META_LOGS_FILE_NAME);
    } else {
        (void)snprintf(g_meta_abs_path, __FULL_PATH_LEN, fmt, mgr->meta_path, META_LOGS_FILE_NAME);
    }

    g_meta_logger.removeAllAppenders();

    SharedAppenderPtr append(new RollingFileAppender(g_meta_abs_path, META_LOGS_FILESIZE, 1, true, true));

    log4cplus::tstring pattern = LOG4CPLUS_TEXT("%m%n");
    append->setLayout(std::unique_ptr<log4cplus::Layout>(new log4cplus::PatternLayout(pattern)));
    g_meta_logger.addAppender(append);
    return 0;
}

static int append_raw_logger(struct log_mgr_s * mgr)
{
    size_t path_len = strlen(mgr->raw_path);
    if (path_len == 0) {
        ERROR("Raw path is null.\n");
        return -1;
    }

    g_raw_logger.removeAllAppenders();

    SharedAppenderPtr append(new RollingFileAppender(mgr->raw_path, DEBUG_LOGS_FILESIZE, 1, true, true));

    log4cplus::tstring pattern = LOG4CPLUS_TEXT("%m");
    append->setLayout(std::unique_ptr<log4cplus::Layout>(new log4cplus::PatternLayout(pattern)));

    g_raw_logger.addAppender(append);
    return 0;
}

static char g_debug_abs_path[__FULL_PATH_LEN];
static int append_debug_logger(struct log_mgr_s * mgr)
{
    const char *app_name;
    const char *fmt = "%s/%s", *fmt2 = "%s%s";

    size_t path_len = strlen(mgr->debug_path);
    if (path_len == 0) {
        ERROR("Debug path is null.\n");
        return -1;
    }

    if (mgr->app_name[0] == 0) {
        app_name = DEBUG_LOGS_FILE_NAME;
    } else {
        app_name = mgr->app_name;
    }

    g_debug_abs_path[0] = 0;
    if (mgr->debug_path[path_len - 1] == '/') {
        (void)snprintf(g_debug_abs_path, __FULL_PATH_LEN, fmt2, mgr->debug_path, app_name);
    } else {
        (void)snprintf(g_debug_abs_path, __FULL_PATH_LEN, fmt, mgr->debug_path, app_name);
    }

    g_debug_logger.removeAllAppenders();

    SharedAppenderPtr append(new RollingFileAppender(g_debug_abs_path, DEBUG_LOGS_FILESIZE, 1, true, true));

    log4cplus::tstring pattern = LOG4CPLUS_TEXT("%D{%m/%d/%y %H:%M:%S}  - %m");
    append->setLayout(std::unique_ptr<log4cplus::Layout>(new log4cplus::PatternLayout(pattern)));

    g_debug_logger.addAppender(append);
    return 0;
}

static int append_metrics_logger(struct log_mgr_s * mgr)
{
    char full_path[PATH_LEN];

    if (que_get_next_file(mgr->metrics_files)) {
        ERROR("Append metrics logger failed(get next file).\n");
        return -1;
    }

    if (get_file_name(mgr, 1, mgr->metrics_files->current.file_id, full_path, PATH_LEN)) {
        ERROR("Append metrics logger failed(get file name).\n");
        return -1;
    }

    g_metrics_logger.removeAllAppenders();

    rm_log_file(full_path);
    SharedAppenderPtr append(new RollingFileAppender(full_path, METRICS_LOGS_FILESIZE, 1, true, true));
    log4cplus::tstring pattern = LOG4CPLUS_TEXT("%m");
    append->setLayout(std::unique_ptr<log4cplus::Layout>(new log4cplus::PatternLayout(pattern)));
    g_metrics_logger.addAppender(append);
    return 0;
}

static int append_event_logger(struct log_mgr_s * mgr)
{
    char full_path[PATH_LEN];

    if (que_get_next_file(mgr->event_files)) {
        ERROR("Append event logger failed(get next file).\n");
        return -1;
    }

    if (get_file_name(mgr, 0, mgr->event_files->current.file_id, full_path, PATH_LEN)) {
        ERROR("Append event logger failed(get file name).\n");
        return -1;
    }

    g_event_logger.removeAllAppenders();

    rm_log_file(full_path);
    SharedAppenderPtr append(new RollingFileAppender(full_path, EVENT_LOGS_FILESIZE, 1, true, true));
    log4cplus::tstring pattern = LOG4CPLUS_TEXT("%m%n");
    append->setLayout(std::unique_ptr<log4cplus::Layout>(new log4cplus::PatternLayout(pattern)));
    g_event_logger.addAppender(append);
    return 0;
}

struct log_mgr_s* create_log_mgr(const char *app_name, int is_metric_out_log, int is_event_out_log)
{
    struct log_mgr_s *mgr = NULL;
    mgr = (struct log_mgr_s *)malloc(sizeof(struct log_mgr_s));
    if (mgr == NULL) {
        return NULL;
    }
    (void)memset(mgr, 0, sizeof(struct log_mgr_s));

    if (is_metric_out_log == 1) {
        mgr->is_metric_out_log = LOGS_SWITCH_ON;
        mgr->metrics_files = create_queue(METRICS_LOGS_MAXNUM);
        if (mgr->metrics_files == NULL) {
            (void)free(mgr);
            return NULL;
        }
    }

    if (is_event_out_log == 1) {
        mgr->is_event_out_log = LOGS_SWITCH_ON;
        mgr->event_files = create_queue(EVENT_LOGS_MAXNUM);
        if (mgr->event_files == NULL) {
            destroy_queue(mgr->metrics_files);
            (void)free(mgr);
            return NULL;
        }
    }

    if (app_name) {
        (void)strncpy(mgr->app_name, app_name, PATH_LEN - 1);
    }

    return mgr;
}

int init_log_mgr(struct log_mgr_s* mgr, int is_meta_out_log)
{
    init_all_logger();

    if ((mgr->debug_path[0] != 0) && append_debug_logger(mgr)) {
        (void)fprintf(stderr, "Append debug logger failed.\n");
        return -1;
    }

    if (is_meta_out_log == 1) {
        mgr->is_meta_out_log = LOGS_SWITCH_ON;
        if ((mgr->meta_path[0] != 0) && append_meta_logger(mgr)) {
            (void)fprintf(stderr, "Append meta logger failed.\n");
            return -1;
        }
    }

    if ((mgr->raw_path[0] != 0) && append_raw_logger(mgr)) {
        (void)fprintf(stderr, "Append raw logger failed.\n");
        return -1;
    }

    local = mgr;
    return 0;
}

void destroy_log_mgr(struct log_mgr_s* mgr)
{
    destroy_queue(mgr->metrics_files);
    destroy_queue(mgr->event_files);
    (void)free(mgr);

    g_metrics_logger.removeAllAppenders();
    g_event_logger.removeAllAppenders();
    g_debug_logger.removeAllAppenders();
    g_meta_logger.removeAllAppenders();
    g_raw_logger.removeAllAppenders();

    local = NULL;
    return;
}

static void reappend_raw_logger(struct log_mgr_s * mgr)
{
    if (access(mgr->raw_path, 0)) {
        g_raw_logger.removeAllAppenders();
        (void)append_raw_logger(mgr);
    }
}

#if 1
#define __DEBUG_LEN     (2048)

#define __FMT_LOGS(buf, size) \
    do { \
        va_list args; \
        buf[0] = 0; \
        va_start(args, format); \
        (void)vsnprintf(buf, (const unsigned int)size, format, args); \
        va_end(args); \
    } while (0)

void wr_raw_logs(const char* format, ...)
{
    char buf[__DEBUG_LEN];

    __FMT_LOGS(buf, __DEBUG_LEN);
    if (local) {
        reappend_raw_logger(local);
        LOG4CPLUS_DEBUG(g_raw_logger, buf);
    } else {
        printf(buf);
    }
}

int wr_metrics_logs(const char* logs, size_t logs_len)
{
    struct log_mgr_s *mgr = local;
    if (!mgr) {
        return -1;
    }

    if (que_current_is_invalid(mgr, 1, METRICS_LOGS_FILESIZE)) {
        if (append_metrics_logger(mgr)) {
            return -1;
        }
    }

    LOG4CPLUS_DEBUG_FMT(g_metrics_logger, logs);
    que_current_set_size(mgr->metrics_files, logs_len);
    return 0;
}

int read_metrics_logs(char logs_file_name[], size_t size)
{
    int file_id;

    struct log_mgr_s *mgr = local;
    if (!mgr) {
        ERROR("Read metrics_logs failed, mgr is null.\n");
        return -1;
    }

    file_id = que_pop_file(mgr->metrics_files);
    if (!IS_VALID_FILE_ID(file_id)) {
        DEBUG("File id invalid(%d)!\n", file_id);
        return -1;
    }

    if (get_file_name(mgr, 1, file_id, logs_file_name, size)) {
        ERROR("Read metrics_logs failed, get log's file_name failed.\n");
        return -1;
    }
    return 0;
}

int wr_event_logs(const char* logs, size_t logs_len)
{
    struct log_mgr_s *mgr = local;
    if (!mgr) {
        return -1;
    }

    if (que_current_is_invalid(mgr, 0, EVENT_LOGS_FILESIZE)) {
        if (append_event_logger(mgr)) {
            return -1;
        }
    }

    LOG4CPLUS_DEBUG_FMT(g_event_logger, logs);
    que_current_set_size(mgr->event_files, logs_len);
    return 0;
}

int read_event_logs(char logs_file_name[], size_t size)
{
    int file_id;

    struct log_mgr_s *mgr = local;
    if (!mgr) {
        ERROR("Read event_logs failed, mgr is null.\n");
        return -1;
    }

    file_id = que_pop_file(mgr->event_files);
    if (!IS_VALID_FILE_ID(file_id)) {
        DEBUG("File id invalid(%d)!\n", file_id);
        return -1;
    }

    if (get_file_name(mgr, 0, file_id, logs_file_name, size)) {
        ERROR("Read event_logs failed, get log's file_name failed.\n");
        return -1;
    }
    return 0;
}

void wr_meta_logs(const char* logs)
{
    if (access(g_meta_abs_path, F_OK) == -1) {
        (void)append_meta_logger(local);
    }
    LOG4CPLUS_DEBUG_FMT(g_meta_logger, logs);
}

static void reappend_debug_logger(struct log_mgr_s *mgr)
{
    if (access(g_debug_abs_path, F_OK) == -1) {
        (void)append_debug_logger(mgr);
    }
}

void debug_logs(const char* format, ...)
{
    char buf[__DEBUG_LEN];

    __FMT_LOGS(buf, __DEBUG_LEN);
    if (!local) {
        printf("DEBUG: %s", buf);
    } else {
        reappend_debug_logger(local);
        LOG4CPLUS_DEBUG(g_debug_logger, buf);
    }
}

void info_logs(const char* format, ...)
{
    char buf[__DEBUG_LEN];

    __FMT_LOGS(buf, __DEBUG_LEN);
    if (!local) {
        printf("INFO: %s", buf);
    } else {
        reappend_debug_logger(local);
        LOG4CPLUS_INFO(g_debug_logger, buf);
    }
}

void warn_logs(const char* format, ...)
{
    char buf[__DEBUG_LEN];

    __FMT_LOGS(buf, __DEBUG_LEN);
    if (!local) {
        printf("WARN: %s", buf);
    } else {
        reappend_debug_logger(local);
        LOG4CPLUS_WARN(g_debug_logger, buf);
    }
}

void error_logs(const char* format, ...)
{
    char buf[__DEBUG_LEN];

    __FMT_LOGS(buf, __DEBUG_LEN);
    if (!local) {
        printf("ERROR: %s", buf);
    } else {
        reappend_debug_logger(local);
        LOG4CPLUS_ERROR(g_debug_logger, buf);
    }
}

#endif
