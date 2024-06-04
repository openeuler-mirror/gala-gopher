#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>
#include <sys/stat.h>
#include "logs.h"

#define INVALID_FILE_ID         (-1)
#define IS_VALID_FILE_ID(id)    ((id) != INVALID_FILE_ID)

#define DEBUG_LOGS_FILE_NAME    "gopher_debug.log"
#define META_LOGS_FILE_NAME    "gopher_meta.log"

#define RM_COMMAND          "/usr/bin/rm -rf %s && /usr/bin/rm -rf %s.[0-9]*"  // for back file will has more than 1
#define RM_DIR_COMMAND      "/usr/bin/rm -rf %s"

static struct log_mgr_s *local = NULL;

static int mkdirp(const char *path, mode_t mode)
{
    if (NULL == path) {
        return -1;
    }
    char path_copy[PATH_LEN];
    path_copy[0] = 0;
    snprintf(path_copy, sizeof(path_copy), "%s", path);

    char *p = dirname(path_copy);
    if ((strcmp(p, ".") == 0)) {
        return -1;
    }
    if ((strlen(p) > 1) && (mkdirp(p, mode) != 0)) {
        return -1;
    }
    int rc = mkdir(path, mode);

    return (rc == 0) || (errno == EEXIST) ? 0 : -1;
}

#define LOG_FILE_PERMISSION 0640
static int open_file(const char *filename)
{
    if (!filename) {
        return -1;
    }
    return open(filename, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, LOG_FILE_PERMISSION);
}

static int open_file_with_clear_file(const char *filename)
{
    if (!filename) {
        return -1;
    }
    int file_fd = open(filename, O_WRONLY | O_CREAT | O_CLOEXEC, LOG_FILE_PERMISSION);
    if (file_fd < 0) {
        return -1;
    }
    if (ftruncate(file_fd, 0)) {
        (void)close(file_fd);
        return -1;
    }
    lseek(file_fd, 0, SEEK_SET);
    return file_fd;
}

static int open_file_without_dir(const char *filename)
{
    if (!filename) {
        return -1;
    }

    char *base_dir;
    char path_copy[PATH_LEN];
    path_copy[0] = 0;
    snprintf(path_copy, sizeof(path_copy), "%s", filename);
    base_dir = dirname(path_copy);
    if (strcmp(base_dir, ".") == 0) {
        return -1;
    }
    u_char dir_exist = (access(base_dir, F_OK) == 0);
    if (dir_exist == 0) {
        int status = mkdirp(base_dir, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP);
        if (status != 0) {
            ERROR("popen mkdir %s failed, errno %d\n", base_dir, errno);
            return -1;
        }
    }
    return open_file(filename);
}

void rm_log_file(const char full_path[])
{
    FILE *fp = NULL;
    char command[COMMAND_LEN];
    if (full_path == NULL || full_path[0] == 0) {
        return;
    }

    command[0] = 0;
    (void)snprintf(command, COMMAND_LEN, RM_COMMAND, full_path, full_path);

    fp = popen(command, "r");
    if (fp != NULL) {
        (void)pclose(fp);
        fp = NULL;
    }
}

void clear_log_dir(const char full_path[])
{
    FILE *fp = NULL;
    char command[COMMAND_LEN];
    if (full_path == NULL || full_path[0] == 0) {
        return;
    }

    command[0] = 0;
    (void)snprintf(command, COMMAND_LEN, RM_DIR_COMMAND, full_path);

    fp = popen(command, "r");
    if (fp != NULL) {
        (void)pclose(fp);
        fp = NULL;
    }
}

static int get_file_name(const struct log_mgr_s* mgr, int is_metrics, int file_id, char full_path[], size_t size)
{
    size_t path_len;
    char last_symbol;
    const char *ftype = (is_metrics != 0) ? "metrics" : "event";
    const char *path = is_metrics ? mgr->metrics_path : mgr->event_path;

    path_len = strlen(path);
    if (path_len == 0) {
        ERROR("Get file_name failed, path is null.\n");
        return -1;
    }

    last_symbol = path[path_len - 1];
    full_path[0] = 0;
    const char *format = (last_symbol == '/') ? "%sgopher_%s_%d" : "%s/gopher_%s_%d";
    (void)snprintf(full_path, size, format, path, ftype, file_id);

    return 0;
}

static char is_empty_queue(const struct files_queue_s *files_que)
{
    return (char)((int)(files_que->rear % (int)files_que->que_size) == files_que->front);
}

static char is_full_queue(const struct files_queue_s *files_que)
{
    return (char)((int)((files_que->rear + 1) % (int)files_que->que_size) == files_que->front);
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

    pos = files_que->rear % ((int)files_que->que_size);
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

    files_que->front = (files_que->front + 1) % ((int)files_que->que_size);
    return file_id;
}

static struct files_queue_s *create_queue()
{
    struct files_queue_s *files_que;
    size_t malloc_size = sizeof(struct files_queue_s) + 100 * sizeof(struct file_node_s);

    files_que = (struct files_queue_s *)malloc(malloc_size);
    if (files_que == NULL) {
        return NULL;
    }

    (void)memset(files_que, 0, malloc_size);
    files_que->que_size = METRICS_LOGS_MAXNUM;
    files_que->current.file_id = INVALID_FILE_ID;

    init_files_queue(files_que);
    (void)pthread_rwlock_init(&(files_que->rwlock), NULL);
    return files_que;
}

static void destroy_queue(struct files_queue_s *files_que)
{
    if (files_que) {
        (void)pthread_rwlock_destroy(&(files_que->rwlock));
        free(files_que);
    }
}

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

static char que_current_is_invalid(struct log_mgr_s *mgr, int is_metrics)
{
    struct files_queue_s *files_que = NULL;
    char invalid = 0;

    files_que = is_metrics ? mgr->metrics_files : mgr->event_files;

    (void)pthread_rwlock_wrlock(&(files_que->rwlock));

    char full_path[PATH_LEN];
    if (get_file_name(mgr, is_metrics, files_que->current.file_id, full_path, PATH_LEN)) {
        ERROR("get file name by curr file_id: %d failed !\n", files_que->current.file_id);
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

struct logger g_metrics_logger;
struct logger g_event_logger;
struct logger g_debug_logger;
struct logger g_meta_logger;

static void init_logger(struct logger *logger, char *name, const int max_backup_index, const size_t max_file_size)
{
    logger->name = name;
    logger->level = LOGGER_INFO;       // set default print info INFO.
    logger->full_path_name[0] = 0;
    logger->base_path_name[0] = 0;
    logger->file_fd = -1;
    logger->max_backup_index = max_backup_index; // if zero, mean do not backup
    logger->curr_backup_index = 1;
    logger->buf_len = 0;
    logger->max_file_size = max_file_size / (logger->max_backup_index + 1);
    logger->pattern = NULL;
    (void)pthread_rwlock_init(&(logger->rwlock), NULL);
}

static void prep_init_logger(struct logger *logger, const size_t max_file_size)
{
    (void)pthread_rwlock_wrlock(&logger->rwlock);
    if (logger->file_fd > 0) {
        (void)close(logger->file_fd);
    }
    logger->buf_len = 0;
    logger->max_file_size = max_file_size / (logger->max_backup_index + 1);
    logger->curr_backup_index = 1;
    (void)pthread_rwlock_unlock(&logger->rwlock);
}

static int init_logger_path(struct logger *logger, const char *log_path)
{
    if ((logger == NULL) || (log_path == NULL)) {
        return -1;
    }
    (void)pthread_rwlock_wrlock(&logger->rwlock);
    logger->file_fd = open_file_without_dir(log_path);
    if (logger->file_fd < 0) {
        (void)pthread_rwlock_unlock(&logger->rwlock);
        ERROR("open %s for debug failed\n", log_path);
        return -1;
    }
    snprintf(logger->full_path_name, sizeof(logger->full_path_name), "%s", log_path);
    snprintf(logger->base_path_name, sizeof(logger->base_path_name), "%s", log_path);
    (void)pthread_rwlock_unlock(&logger->rwlock);
    return 0;
}

static void init_all_logger(void)
{
    init_logger(&g_metrics_logger, "metrics", 0, METRICS_LOGS_FILESIZE);
    init_logger(&g_event_logger, "event", 1, EVENT_LOGS_FILESIZE);
    init_logger(&g_debug_logger, "debug", 1, DEBUG_LOGS_FILESIZE);
    init_logger(&g_meta_logger, "meta", 0, META_LOGS_FILESIZE);
}

#define FULL_PATH_LEN (PATH_LEN * 2)
static char g_meta_abs_path[FULL_PATH_LEN];
static int append_meta_logger(struct log_mgr_s * mgr)
{
    const char *fmt = "%s/%s", *fmt2 = "%s%s";
    size_t path_len = strlen(mgr->meta_path);
    if (path_len == 0) {
        ERROR("Meta path is null.\n");
        return -1;
    }
    g_meta_abs_path[0] = 0;
    (void)snprintf(g_meta_abs_path, FULL_PATH_LEN, (mgr->meta_path[path_len - 1] == '/') ?
        fmt2 : fmt, mgr->meta_path, META_LOGS_FILE_NAME);
    prep_init_logger(&g_meta_logger, META_LOGS_FILESIZE);
    int path_state = init_logger_path(&g_meta_logger, g_meta_abs_path);
    if (path_state < 0) {
        return -1;
    }
    (void)pthread_rwlock_wrlock(&g_meta_logger.rwlock);
    g_meta_logger.pattern = PATTERN_META_LOGGER_STR; // "%m%n"
    (void)pthread_rwlock_unlock(&g_meta_logger.rwlock);
    return 0;
}

static char g_debug_abs_path[FULL_PATH_LEN];
static int append_debug_logger(struct log_mgr_s * mgr)
{
    const char *app_name;
    const char *fmt = "%s/%s", *fmt2 = "%s%s";

    size_t path_len = strlen(mgr->debug_path);
    if (path_len == 0) {
        ERROR("Debug path is null.\n");
        return -1;
    }
    app_name = (mgr->app_name[0] == 0) ? (DEBUG_LOGS_FILE_NAME) : mgr->app_name;
    g_debug_abs_path[0] = 0;
    (void)snprintf(g_debug_abs_path, FULL_PATH_LEN,
        (mgr->debug_path[path_len - 1] == '/') ? fmt2 : fmt, mgr->debug_path, app_name);
    prep_init_logger(&g_debug_logger, DEBUG_LOGS_FILESIZE);
    int path_state = init_logger_path(&g_debug_logger, g_debug_abs_path);
    if (path_state < 0) {
        return -1;
    }
    (void)pthread_rwlock_wrlock(&g_debug_logger.rwlock);
    g_debug_logger.pattern = PATTERN_DEBUG_LOGGER_STR;
    (void)pthread_rwlock_unlock(&g_debug_logger.rwlock);
    return 0;
}

static int append_metrics_logger(struct log_mgr_s *mgr)
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

    rm_log_file(full_path);
    prep_init_logger(&g_metrics_logger, mgr->metrics_logs_filesize);
    int path_state = init_logger_path(&g_metrics_logger, full_path);
    if (path_state < 0) {
        return -1;
    }
    (void)pthread_rwlock_wrlock(&g_metrics_logger.rwlock);
    g_metrics_logger.pattern = PATTERN_METRICS_LOGGER_STR;
    (void)pthread_rwlock_unlock(&g_metrics_logger.rwlock);
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

    rm_log_file(full_path);
    prep_init_logger(&g_meta_logger, META_LOGS_FILESIZE);
    int path_state = init_logger_path(&g_event_logger, full_path);
    if (path_state < 0) {
        return -1;
    }
    (void)pthread_rwlock_wrlock(&g_event_logger.rwlock);
    g_event_logger.pattern = PATTERN_EVENT_LOGGER_STR;
    (void)pthread_rwlock_unlock(&g_event_logger.rwlock);
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
        mgr->metrics_files = create_queue();
        if (mgr->metrics_files == NULL) {
            (void)free(mgr);
            return NULL;
        }
    }

    if (is_event_out_log == 1) {
        mgr->is_event_out_log = LOGS_SWITCH_ON;
        mgr->event_files = create_queue();
        if (mgr->event_files == NULL) {
            destroy_queue(mgr->metrics_files);
            (void)free(mgr);
            return NULL;
        }
    }

    if (app_name) {
        (void)snprintf(mgr->app_name, sizeof(mgr->app_name), "%s", app_name);
    }
    return mgr;
}

static void set_debug_log_level(char *logLevel)
{
    g_debug_logger.level = LOGGER_DEBUG;

    if (logLevel == NULL) {
        return;
    }

    if (strcmp(logLevel, "debug") == 0) {
        g_debug_logger.level = LOGGER_DEBUG;
    } else if (strcmp(logLevel, "info") == 0) {
        g_debug_logger.level = LOGGER_INFO;
    } else if (strcmp(logLevel, "warn") == 0) {
        g_debug_logger.level = LOGGER_WARN;
    } else if (strcmp(logLevel, "error") == 0) {
        g_debug_logger.level = LOGGER_ERROR;
    } else if (strcmp(logLevel, "fatal") == 0) {
        g_debug_logger.level = LOGGER_FATAL;
    }
}

int init_log_mgr(struct log_mgr_s* mgr, int is_meta_out_log, char *logLevel)
{
    clear_log_dir(mgr->metrics_path);
    init_all_logger();

    if (mgr->metrics_logs_filesize <= 0) {
        mgr->metrics_logs_filesize = METRICS_LOGS_FILESIZE;
        (void)fprintf(stderr, "metric_total_size is invalid. metrics_logs_filesize will reset to %ld MB.\n", mgr->metrics_logs_filesize);
    }

    if (mgr->metrics_logs_filesize > METRICS_LOGS_FILESIZE_MAX) {
        mgr->metrics_logs_filesize = METRICS_LOGS_FILESIZE_MAX;
        (void)fprintf(stderr, "metric_total_size is too large. metrics_logs_filesize will reset to %ld MB.\n", mgr->metrics_logs_filesize);
    }
    g_metrics_logger.max_file_size = mgr->metrics_logs_filesize / (g_metrics_logger.max_backup_index + 1);  // update metrics size special.
    if ((mgr->debug_path[0] != 0) && (append_debug_logger(mgr) != 0)) {
        (void)fprintf(stderr, "Append debug logger failed.\n");
        return -1;
    }

    if (is_meta_out_log == 1) {
        mgr->is_meta_out_log = LOGS_SWITCH_ON;
        if ((mgr->meta_path[0] != 0) && (append_meta_logger(mgr) != 0)) {
            (void)fprintf(stderr, "Append meta logger failed.\n");
            return -1;
        }
    }

    set_debug_log_level(logLevel);
    local = mgr;
    return 0;
}

static void destroy_logger_instance(struct logger *logger)
{
    if (logger == NULL) {
        return;
    }
    if (logger->file_fd >= 0) {
        (void)close(logger->file_fd);
    }
    (void)pthread_rwlock_destroy(&(logger->rwlock));
}

void destroy_log_mgr(struct log_mgr_s* mgr)
{
    if (mgr == NULL) {
        return;
    }

    destroy_queue(mgr->metrics_files);
    destroy_queue(mgr->event_files);
    clear_log_dir(mgr->metrics_path);
    (void)free(mgr);
    mgr = NULL;

    destroy_logger_instance(&g_metrics_logger);
    destroy_logger_instance(&g_event_logger);
    destroy_logger_instance(&g_debug_logger);
    destroy_logger_instance(&g_meta_logger);

    local = NULL;
}

#define __DEBUG_LEN    (2048)

#define __FMT_LOGS(buf, size, format) \
    do { \
        va_list args; \
        buf[0] = 0; \
        va_start(args, format); \
        (void)vsnprintf(buf, (const unsigned int)size, format, args); \
        va_end(args); \
    } while (0)

// function has lock by user.
static void log_rollover(struct logger *logger)
{
    if ((logger == NULL) || (strlen(logger->full_path_name) == 0)) {
        return;
    }
    (void)pthread_rwlock_wrlock(&logger->rwlock);
    int ret = faccessat(0, logger->full_path_name, F_OK, 0);
    (void)close(logger->file_fd);
    if (ret != 0) {
        (void)pthread_rwlock_unlock(&logger->rwlock);
        return;
    }
    if (strncmp(logger->name, "metrics", 7) == 0) { // if metrics logger, we do not rollover bak, only clean it.
        logger->file_fd = open_file_with_clear_file(logger->full_path_name);
        if (logger->file_fd < 0) {
            (void)pthread_rwlock_unlock(&logger->rwlock);
            return;
        }
        logger->buf_len = 0; // re-count buf_len.
        (void)pthread_rwlock_unlock(&logger->rwlock);
        return;
    }
    // rollover files and get new filename.
    logger->curr_backup_index = (logger->curr_backup_index) % (logger->max_backup_index + 1);
    if (logger->curr_backup_index == 0) {
        ++logger->curr_backup_index;
    }
    (void)snprintf(logger->full_path_name, sizeof(logger->full_path_name), "%s.%d",
                       logger->base_path_name, logger->curr_backup_index);
    ret = rename(logger->base_path_name, logger->full_path_name);
    if (ret < 0) {
        (void)printf("[ERROR] rename file %s to %s failed\n", logger->base_path_name, logger->full_path_name);
    }
    logger->file_fd = open_file_with_clear_file(logger->base_path_name);
    logger->buf_len = 0; // re-count buf_len.
    ++logger->curr_backup_index; // next backup index.
    (void)pthread_rwlock_unlock(&logger->rwlock);
    if (logger->file_fd < 0) {
	(void)printf("[ERROR] failed open filename: %s\n", logger->base_path_name);
    }
}

/***
 * check file state, if it is more than max_file_size
 * @ return
 *      0 : normal no buffer overflow.
 *      1 : has buffer overflow need write by truncate.
 *      -1 : invalid param.
***/
static void check_file_state(struct logger *logger)
{
    if (logger == NULL) {
        return;
    }
    if (logger->buf_len >= logger->max_file_size) {
        log_rollover(logger);
        return;
    }
}

static void write_log(const char *msg, struct logger *logger)
{
    if (logger == NULL) {
        return;
    }
    // check file if overflowed
    check_file_state(logger);
    ssize_t write_ret;

    (void)pthread_rwlock_wrlock(&logger->rwlock);
    int ret = faccessat(0, logger->full_path_name, F_OK, 0);
    if ((ret != 0) && (logger->file_fd >= 0)) {
        (void)close(logger->file_fd);
        logger->file_fd = -1;
    }
    if (logger->file_fd < 0) {
        logger->file_fd = open_file(logger->full_path_name);
        if (logger->file_fd < 0) {
            (void)pthread_rwlock_unlock(&logger->rwlock);
            return;
        }
    }
    (void)lseek(logger->file_fd, 0, SEEK_END);
    const size_t buffer_length = strlen(msg);
    write_ret = write(logger->file_fd, msg, buffer_length);
    if (write_ret == -1) {
        (void)printf("[ERROR]: write to log file failed, errno[%d].\n", errno);
    }
    logger->buf_len += buffer_length;
    (void)pthread_rwlock_unlock(&logger->rwlock);
}

static void log_without_date(struct logger *logger, const char *detail)
{
    if ((detail == NULL) || (!logger) || (!logger->pattern) || (strlen(logger->pattern) == 0)) {
        return;
    }

    size_t len = strlen(detail) + 2;    // metric logger pattern contains extra "\n"
    char *msg = (char *)calloc(1, len);
    if (msg == NULL) {
        return;
    }

    int ret = snprintf(msg, len, logger->pattern, detail);
    if (ret < 0) {
        free(msg);
        return;
    }
    write_log(msg, logger);
    free(msg);
}

int wr_metrics_logs(const char* logs, size_t logs_len)
{
    struct log_mgr_s *mgr = local;
    if (!mgr) {
        return -1;
    }

    if (que_current_is_invalid(mgr, 1)) {
        if (append_metrics_logger(mgr)) {
            return -1;
        }
    }
    log_without_date(&g_metrics_logger, logs);
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
    if (mgr->metrics_files == NULL) {
        DEBUG("Read metrics_logs failed, metrics_files is null.\n");
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
    (void)pthread_rwlock_wrlock(&(g_metrics_logger.rwlock));
    g_metrics_logger.buf_len = 0; // if delete file by curl, should reset it buf_len
    (void)pthread_rwlock_unlock(&(g_metrics_logger.rwlock));
    return 0;
}

int wr_event_logs(const char* logs, size_t logs_len)
{
    struct log_mgr_s *mgr = local;
    if (!mgr) {
        return -1;
    }

    if (que_current_is_invalid(mgr, 0)) {
        if (append_event_logger(mgr)) {
            return -1;
        }
    }

    log_without_date(&g_event_logger, logs);
    que_current_set_size(mgr->event_files, logs_len);
    return 0;
}

void wr_meta_logs(const char* logs)
{
    if (access(g_meta_abs_path, F_OK) == -1) {
        (void)append_meta_logger(local);
    }

    log_without_date(&g_meta_logger, logs);
}

static void reappend_debug_logger(struct log_mgr_s *mgr)
{
    if (access(g_debug_abs_path, F_OK) == -1) {
        (void)append_debug_logger(mgr);
    }
}

static int get_log_time(struct tm *t)
{
    time_t now;
    struct tm *ret_t = NULL;
    now = time((time_t *)(0));
    memset(t, 0, sizeof(struct tm));
    ret_t = localtime_r(&now, t);
    if (ret_t == NULL) {
        return -1;
    }
    return 0;
}

#define MAX_PATTERN_STR 200
#define TM_YEAR_BEGIN 1900
#define TM_YEAR_SHOW_OFFSET 2000
static void log_with_date(struct logger *logger, const char *detail)
{
    if ((detail == NULL) || (!logger) || (!logger->pattern) || (strlen(logger->pattern) == 0)) {
        return;
    }
    struct tm t;

    if (get_log_time(&t) != 0) {
        return;
    }
    char msg[__DEBUG_LEN + MAX_PATTERN_STR] = {0};

    int ret = snprintf(msg, __DEBUG_LEN + MAX_PATTERN_STR, logger->pattern,
                       t.tm_mon + 1, t.tm_mday, t.tm_year + TM_YEAR_BEGIN - TM_YEAR_SHOW_OFFSET,
                       t.tm_hour, t.tm_min, t.tm_sec, detail);
    if (ret == -1) {
        return;
    }
    write_log(msg, logger);
}

void convert_output_to_log(char *buffer, int bufferSize)
{
    if (buffer == NULL || bufferSize < 1) {
        return;
    }

    buffer[bufferSize - 1] = 0;
    enum logger_level_t logger_level;
    if (strncmp(buffer, INFO_STR, sizeof(INFO_STR) - 1) == 0) {
        logger_level = LOGGER_INFO;
    } else if (strncmp(buffer, WARN_STR, sizeof(WARN_STR) - 1) == 0) {
        logger_level = LOGGER_WARN;
    } else if (strncmp(buffer, ERROR_STR, sizeof(ERROR_STR) - 1) == 0) {
        logger_level = LOGGER_ERROR;
    } else {
        logger_level = LOGGER_DEBUG;
    }
    if (g_debug_logger.level <= logger_level) {
        reappend_debug_logger(local);
        log_with_date(&g_debug_logger, buffer);
    }
}

void debug_logs(const char* format, ...)
{
    char buf[__DEBUG_LEN];

    __FMT_LOGS(buf, __DEBUG_LEN, format);
    if (!local) {
        printf("%s: %s", DEBUG_STR, buf);
        (void)fflush(stdout);
    } else {
        if (g_debug_logger.level <= LOGGER_DEBUG) {
            reappend_debug_logger(local);
            log_with_date(&g_debug_logger, buf);
        }
    }
}


void info_logs(const char* format, ...)
{
    char buf[__DEBUG_LEN];

    __FMT_LOGS(buf, __DEBUG_LEN, format);
    if (!local) {
        printf("%s: %s", INFO_STR, buf);
        (void)fflush(stdout);
    } else {
        if (g_debug_logger.level <= LOGGER_INFO) {
            reappend_debug_logger(local);
            log_with_date(&g_debug_logger, buf);
        }
    }
}

void warn_logs(const char* format, ...)
{
    char buf[__DEBUG_LEN];

    __FMT_LOGS(buf, __DEBUG_LEN, format);
    if (!local) {
        printf("%s: %s", WARN_STR, buf);
        (void)fflush(stdout);
    } else {
        if (g_debug_logger.level <= LOGGER_WARN) {
            reappend_debug_logger(local);
            log_with_date(&g_debug_logger, buf);
        }
    }
}

void error_logs(const char *format, ...) {
    char buf[__DEBUG_LEN];

    __FMT_LOGS(buf, __DEBUG_LEN, format);
    if (!local) {
        printf("%s: %s", ERROR_STR, buf);
        (void)fflush(stdout);
    } else {
        if (g_debug_logger.level <= LOGGER_ERROR) {
            reappend_debug_logger(local);
            log_with_date(&g_debug_logger, buf);
        }
    }
    fprintf(stderr, "%s", buf);
}


