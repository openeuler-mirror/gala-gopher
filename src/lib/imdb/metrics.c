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
 * Create: 2022-08-16
 * Description:
 ******************************************************************************/
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "imdb.h"
#include "logs.h"


#define LEN_1M (1024 * 1024)     // 1 MB
static char g_buffer[LEN_1M];


int ReadMetricsLogs(char logs_file_name[])
{
    return read_metrics_logs(logs_file_name, PATH_LEN);
}

void RemoveMetricsLogs(char logs_file_name[])
{
    rm_log_file(logs_file_name);
}

static int WriteMetricsLogs(IMDB_DataBaseMgr *imdbMgr)
{
    int ret;
    int buffer_len = 0;
    g_buffer[0] = 0;

    ret = IMDB_DataBase2Prometheus(imdbMgr, g_buffer, LEN_1M, &buffer_len);
    if (ret < 0) {
        ERROR("[METRICLOG] IMDB database to promethous fail, ret: %d\n", ret);
        return -1;
    }

    if (buffer_len == 0) {
        // return when no data in tables
        return 0;
    }

    ret = wr_metrics_logs(g_buffer, buffer_len);
    if (ret < 0) {
        ERROR("[METRICLOG] write metrics logs fail.\n");
        return -1;
    }

    return 0;
}

#define METRIC_LOG_WRITE_INTERVAL   1
void WriteMetricsLogsMain(IMDB_DataBaseMgr *mgr)
{
    int ret;

    if (mgr->writeLogsOn == 0) {
        ERROR("[METRICLOG] metric outchannel isn't web_server or logs, break.\n");
        return;
    }

    for (;;) {
        sleep(METRIC_LOG_WRITE_INTERVAL);
        ret = WriteMetricsLogs(mgr);
        if (ret < 0) {
            ERROR("[METRICLOG] write buffer error.\n");
        }
    }
}
