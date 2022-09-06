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
 * Author: dowzyx
 * Create: 2022-08-22
 * Description: provide gala-gopher test for logs
 ******************************************************************************/
#include <stdint.h>
#include <CUnit/Basic.h>

#include "logs.h"
#include "test_logs.h"


#define TEST_METRICS_PATH   "/home/logs/metrics"
#define TEST_EVENT_PATH     "/home/logs/event/"
#define TEST_DEBUG_PATH     "/home/logs/debug"
#define TEST_META_PATH      "/home/logs/meta"

#define LOGS_FILE_SIZE      (1024)

#define WR_LOGS(count, id, func, txt) \
    do \
    { \
        for (int __index = 0; __index < count; __index++) { \
            if (func(txt, strlen(txt))) { \
                (void)fprintf(stderr, "Failed to write logs!\n"); \
            } \
        } \
        printf("Succeed to write file(%d)\n", id); \
    } while(0)

#define RE_LOGS(func) \
    do \
    { \
        char __logs[PATH_LEN]; \
        if (func(__logs, PATH_LEN)) { \
            (void)fprintf(stderr, "Failed to read logs!\n"); \
            return; \
        } \
        rm_log_file(__logs); \
        printf("Succeed to read logs(%s)\n", __logs); \
    } while(0)

static struct log_mgr_s *test_local = NULL;

static int is_logs_file_exist(char* log_path, char* ftype, int id)
{
    char cmd[COMMAND_LEN];
    char line[PATH_LEN];
    FILE* f;

    cmd[0] = 0;
    if (!strcmp(ftype, "metrics") || !strcmp(ftype, "event")) {
        (void)snprintf(cmd, COMMAND_LEN, "ls -l %s | grep gopher_%s_%d", log_path, ftype, id);
    } else {
        (void)snprintf(cmd, COMMAND_LEN, "ls -l %s | grep gopher_%s", log_path, ftype);
    }
    f = popen(cmd, "r");
    if (f == NULL) {
        return -1;
    }
    line[0] = 0;
    if (fgets(line, PATH_LEN, f) == NULL) {
        (void)pclose(f);
        return 0;
    }

    (void)pclose(f);
    return 1;
}

static void TestLogsMgrInit(void)
{
    int ret = 0;
    test_local = create_log_mgr(NULL, 1, 1);
    CU_ASSERT(test_local != NULL);
    CU_ASSERT(test_local->metrics_files != NULL);
    CU_ASSERT(test_local->event_files != NULL);

    (void)strncpy(test_local->debug_path, TEST_DEBUG_PATH, PATH_LEN - 1);
    (void)strncpy(test_local->metrics_path, TEST_METRICS_PATH, PATH_LEN - 1);
    (void)strncpy(test_local->event_path, TEST_EVENT_PATH, PATH_LEN - 1);
    (void)strncpy(test_local->meta_path, TEST_META_PATH, PATH_LEN - 1);

    ret = init_log_mgr(test_local, 1);
    CU_ASSERT(ret == 0);
    CU_ASSERT(test_local->is_meta_out_log == 1);
    return;
}

#define DEBUG_WR_COUNT      100
static void TestLogsWrDebugLogs(void)
{
    // TODO
    return;
}

static void TestLogsWrMetaLogs(void)
{
    for (int i = 0; i < DEBUG_WR_COUNT; i++) {
        wr_meta_logs("I'am a meta logs");
    }
    CU_ASSERT(is_logs_file_exist(TEST_META_PATH, "meta", 0) == 1);
}

#define EVENT_LOGS_TEXT   "I'am a event, len 20"
static void TestLogsWrEventLogs(void)
{
    int count = (LOGS_FILE_SIZE / strlen(EVENT_LOGS_TEXT) + 1);

    WR_LOGS(count, 0, wr_event_logs, EVENT_LOGS_TEXT);
    CU_ASSERT(is_logs_file_exist(TEST_EVENT_PATH, "event", 0) == 1);
    WR_LOGS(count, 1, wr_event_logs, EVENT_LOGS_TEXT);
    CU_ASSERT(is_logs_file_exist(TEST_EVENT_PATH, "event", 1) == 1);
    WR_LOGS(count, 2, wr_event_logs, EVENT_LOGS_TEXT);
    CU_ASSERT(is_logs_file_exist(TEST_EVENT_PATH, "event", 2) == 1);
    WR_LOGS(count, 3, wr_event_logs, EVENT_LOGS_TEXT);
    CU_ASSERT(is_logs_file_exist(TEST_EVENT_PATH, "event", 3) == 1);

    RE_LOGS(read_event_logs);
    CU_ASSERT(is_logs_file_exist(TEST_EVENT_PATH, "event", 0) == 0);
    RE_LOGS(read_event_logs);
    CU_ASSERT(is_logs_file_exist(TEST_EVENT_PATH, "event", 1) == 0);

    WR_LOGS(count, 4, wr_event_logs, EVENT_LOGS_TEXT);
    CU_ASSERT(is_logs_file_exist(TEST_EVENT_PATH, "event", 4) == 1);
    WR_LOGS(count, 5, wr_event_logs, EVENT_LOGS_TEXT);
    CU_ASSERT(is_logs_file_exist(TEST_EVENT_PATH, "event", 5) == 1);
    WR_LOGS(count, 6, wr_event_logs, EVENT_LOGS_TEXT);
    CU_ASSERT(is_logs_file_exist(TEST_EVENT_PATH, "event", 6) == 1);

    RE_LOGS(read_event_logs);
    CU_ASSERT(is_logs_file_exist(TEST_EVENT_PATH, "event", 2) == 0);
    RE_LOGS(read_event_logs);
    CU_ASSERT(is_logs_file_exist(TEST_EVENT_PATH, "event", 3) == 0);
    RE_LOGS(read_event_logs);
    CU_ASSERT(is_logs_file_exist(TEST_EVENT_PATH, "event", 4) == 0);
    RE_LOGS(read_event_logs);
    CU_ASSERT(is_logs_file_exist(TEST_EVENT_PATH, "event", 5) == 0);
    RE_LOGS(read_event_logs);
    CU_ASSERT(is_logs_file_exist(TEST_EVENT_PATH, "event", 6) == 0);

    WR_LOGS(count, 7, wr_event_logs, EVENT_LOGS_TEXT);
    CU_ASSERT(is_logs_file_exist(TEST_EVENT_PATH, "event", 7) == 1);

    return;
}

#define METRICS_LOGS_TEXT   "I'am metrics, len 20"
static void TestLogsWrMetricLogs(void)
{
    int ret = 0;
    int count = (LOGS_FILE_SIZE / strlen(METRICS_LOGS_TEXT) + 1);

    WR_LOGS(count, 0, wr_metrics_logs, METRICS_LOGS_TEXT);
    CU_ASSERT(is_logs_file_exist(TEST_METRICS_PATH, "metrics", 0) == 1);
    WR_LOGS(count, 1, wr_metrics_logs, METRICS_LOGS_TEXT);
    CU_ASSERT(is_logs_file_exist(TEST_METRICS_PATH, "metrics", 1) == 1);
    WR_LOGS(count, 2, wr_metrics_logs, METRICS_LOGS_TEXT);
    CU_ASSERT(is_logs_file_exist(TEST_METRICS_PATH, "metrics", 2) == 1);
    WR_LOGS(count, 3, wr_metrics_logs, METRICS_LOGS_TEXT);
    CU_ASSERT(is_logs_file_exist(TEST_METRICS_PATH, "metrics", 3) == 1);

    RE_LOGS(read_metrics_logs);
    CU_ASSERT(is_logs_file_exist(TEST_METRICS_PATH, "metrics", 0) == 0);
    RE_LOGS(read_metrics_logs);
    CU_ASSERT(is_logs_file_exist(TEST_METRICS_PATH, "metrics", 1) == 0);

    WR_LOGS(count, 4, wr_metrics_logs, METRICS_LOGS_TEXT);
    CU_ASSERT(is_logs_file_exist(TEST_METRICS_PATH, "metrics", 4) == 1);
    WR_LOGS(count, 5, wr_metrics_logs, METRICS_LOGS_TEXT);
    CU_ASSERT(is_logs_file_exist(TEST_METRICS_PATH, "metrics", 5) == 1);
    WR_LOGS(count, 6, wr_metrics_logs, METRICS_LOGS_TEXT);
    CU_ASSERT(is_logs_file_exist(TEST_METRICS_PATH, "metrics", 6) == 1);

    RE_LOGS(read_metrics_logs);
    CU_ASSERT(is_logs_file_exist(TEST_METRICS_PATH, "metrics", 2) == 0);
    RE_LOGS(read_metrics_logs);
    CU_ASSERT(is_logs_file_exist(TEST_METRICS_PATH, "metrics", 3) == 0);
    RE_LOGS(read_metrics_logs);
    CU_ASSERT(is_logs_file_exist(TEST_METRICS_PATH, "metrics", 4) == 0);
    RE_LOGS(read_metrics_logs);
    CU_ASSERT(is_logs_file_exist(TEST_METRICS_PATH, "metrics", 5) == 0);
    RE_LOGS(read_metrics_logs);
    CU_ASSERT(is_logs_file_exist(TEST_METRICS_PATH, "metrics", 6) == 0);

    WR_LOGS(count, 7, wr_metrics_logs, METRICS_LOGS_TEXT);
    CU_ASSERT(is_logs_file_exist(TEST_METRICS_PATH, "metrics", 7) == 1);

    return;
}

static void TestLogsMgrDestroy(void)
{
    destroy_log_mgr(test_local);
    CU_ASSERT(test_local->metrics_files != NULL);
    CU_ASSERT(test_local->event_files != NULL);
    CU_ASSERT(test_local != NULL);

    return;
}

void TestLogsMain(CU_pSuite suite)
{
    CU_ADD_TEST(suite, TestLogsMgrInit);
    CU_ADD_TEST(suite, TestLogsWrDebugLogs);
    CU_ADD_TEST(suite, TestLogsWrMetaLogs);
    CU_ADD_TEST(suite, TestLogsWrEventLogs);
    CU_ADD_TEST(suite, TestLogsWrMetricLogs);
    CU_ADD_TEST(suite, TestLogsMgrDestroy);
}