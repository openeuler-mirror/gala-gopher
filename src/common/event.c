/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: luzhihao
 * Create: 2022-05-16
 * Description:
 ******************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#include "common.h"
#include "event.h"
#ifdef NATIVE_PROBE_FPRINTF
#include "nprobe_fprintf.h"
#endif

static void __get_local_time(char *buf, int buf_len)
{
    time_t rawtime;
    struct tm tm;
    char time_str[TIME_STRING_LEN];

    (void)time(&rawtime);
    asctime_r(localtime_r(&rawtime, &tm), time_str);
    SPLIT_NEWLINE_SYMBOL(time_str);
    (void)snprintf(buf, (const int)buf_len, "%s", time_str);
}

#define __SEC_TXT_LEN  32
struct evt_sec_s {
    int sec_number;
    char sec_text[__SEC_TXT_LEN];
};

static struct evt_sec_s secs[EVT_SEC_MAX] = {
    {9,              "INFO"},
    {13,              "WARN"},
    {17,              "ERROR"},
    {21,              "FATAL"}
};

#define __EVT_BODY_LEN  256
void report_logs(const char* entityName,
                 const char* entityId,
                 const char* metrics,
                 enum evt_sec_e sec,
                 const char * fmt, ...)
{
    int len;
    va_list args;
    char body[__EVT_BODY_LEN];
    char *p;

    body[0] = 0;
    __get_local_time(body, __EVT_BODY_LEN);
    p = body + strlen(body);
    len = __EVT_BODY_LEN - strlen(body);

    (void)snprintf(p, len, " %s Entity(%s) ", secs[sec].sec_text, entityId);
    p = body + strlen(body);
    len = __EVT_BODY_LEN - strlen(body);

    va_start(args, fmt);
    (void)vsnprintf(p, len, fmt, args);
    va_end(args);

#ifdef NATIVE_PROBE_FPRINTF
    (void)nprobe_fprintf(stdout, "|%s|%s|%s|%s|%s|%d|%s|\n",
                         "event",
                         entityName,
                         entityId,
                         metrics,
                         secs[sec].sec_text,
                         secs[sec].sec_number,
                         body);
#else
    (void)fprintf(stdout, "|%s|%s|%s|%s|%s|%d|%s|\n",
                          "event",
                          entityName,
                          entityId,
                          metrics,
                          secs[sec].sec_text,
                          secs[sec].sec_number,
                          body);
#endif
    return;
}
