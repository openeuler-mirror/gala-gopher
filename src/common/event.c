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
#include "container.h"
#include "event.h"
#ifdef NATIVE_PROBE_FPRINTF
#include "nprobe_fprintf.h"
#endif

static unsigned int g_evt_period = 600;
// static EventsConfig *g_evt_conf;
// static char g_lang_type[MAX_EVT_GRP_NAME_LEN] = "zh_CN";

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

#ifdef ENABLE_REPORT_EVENT
static struct evt_ts_hash_t *g_evt_head = NULL;

static void hash_clear_older_evt(time_t cur_time);
static unsigned int hash_count_evt(void);
static int is_evt_need_report(const char *entityId, time_t cur_time);

static void __get_local_time(char *buf, int buf_len, time_t *cur_time)
{
    time_t rawtime;
    struct tm tm;
    char time_str[TIME_STRING_LEN];

    (void)time(&rawtime);
    asctime_r(localtime_r(&rawtime, &tm), time_str);
    SPLIT_NEWLINE_SYMBOL(time_str);
    (void)snprintf(buf, (const int)buf_len, "%s", time_str);
    *cur_time = rawtime;
}


#define __EVT_BODY_LEN  512 // same as MAX_IMDB_METRIC_VAL_LEN
void report_logs(const struct event_info_s* evt, enum evt_sec_e sec, const char * fmt, ...)
{
    size_t len;
    va_list args;
    char pid_str[INT_LEN];
    char pid_comm[TASK_COMM_LEN];
    char container_id[CONTAINER_ABBR_ID_LEN + 1];
    char pod_id[POD_ID_LEN + 1];
    char body[__EVT_BODY_LEN];
    char *p;
    time_t cur_time;

    body[0] = 0;
    __get_local_time(body, __EVT_BODY_LEN, &cur_time);
    if ((g_evt_period > 0) && (!is_evt_need_report(evt->entityId, cur_time))) {
        DEBUG("event not report, because entityId[%s] in event_period.\n", evt->entityId);
        return;
    }

    p = body + strlen(body);
    len = __EVT_BODY_LEN - strlen(body);

    (void)snprintf(p, len, " %s Entity(%s) ", secs[sec].sec_text, evt->entityId);
    p = body + strlen(body);
    len = __EVT_BODY_LEN - strlen(body);

    //char fmt2[MAX_EVT_BODY_LEN];
    //fmt2[0] = 0;
    va_start(args, fmt);
    //__replace_desc_fmt(evt->entityName, evt->metrics, fmt, fmt2);
    (void)vsnprintf(p, len, fmt, args);
    va_end(args);

    pid_str[0] = 0;
    pid_comm[0] = 0;
    container_id[0] = 0;
    if (evt->pid != 0) {
        (void)snprintf(pid_str, INT_LEN, "%d", evt->pid);
        (void)get_container_id_by_pid_cpuset((const char *)pid_str, container_id, CONTAINER_ABBR_ID_LEN + 1);
        (void)get_proc_comm(evt->pid, pid_comm, TASK_COMM_LEN);
    }

    pod_id[0] = 0;
    if (container_id[0] != 0) {
        (void)get_container_pod_id((const char *)container_id, pod_id, POD_ID_LEN + 1);
    }

#ifdef NATIVE_PROBE_FPRINTF
    (void)nprobe_fprintf(stdout, "|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%d|%s|\n",
                         "event",
                         evt->entityName,
                         evt->entityId,
                         evt->metrics,
                         (pid_str[0] != 0) ? pid_str : "",
                         (pid_comm[0] != 0) ? pid_comm : "",
                         (evt->ip[0] != 0) ? evt->ip : "",
                         (container_id[0] != 0) ? container_id : "",
                         (pod_id[0] != 0) ? pod_id : "",
                         evt->dev ? evt->dev : "",
                         secs[sec].sec_text,
                         secs[sec].sec_number,
                         body);
#else
    (void)fprintf(stdout, "|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%d|%s|\n",
                  "event",
                  evt->entityName,
                  evt->entityId,
                  evt->metrics,
                  (pid_str[0] != 0) ? pid_str : "",
                  (pid_comm[0] != 0) ? pid_comm : "",
                  (evt->ip[0] != 0) ? evt->ip : "",
                  (container_id[0] != 0) ? container_id : "",
                  (pod_id[0] != 0) ? pod_id : "",
                  evt->dev ? evt->dev : "",
                  secs[sec].sec_text,
                  secs[sec].sec_number,
                  body);
#endif
    return;
}

static void hash_add_evt(const char *entityId, time_t cur_time)
{
    struct evt_ts_hash_t *item = NULL;

    if (hash_count_evt() >= MAX_EVT_NUM) {
        // clear older events when event num beyond 1000
        hash_clear_older_evt(cur_time);
    }

    item = malloc(sizeof(struct evt_ts_hash_t));
    if (item == NULL) {
        ERROR("event malloc error\n");
        return;
    }
    item->entity_id[0] = 0;
    (void)snprintf(item->entity_id, sizeof(item->entity_id), "%s", entityId);
    item->evt_ts = cur_time;
    H_ADD_S(g_evt_head, entity_id, item);
}

static struct evt_ts_hash_t *hash_find_evt(const char *entityId)
{
    char str[MAX_ENTITY_NAME_LEN];
    struct evt_ts_hash_t *item = NULL;
    if (g_evt_head == NULL) {
        return NULL;
    }

    str[0] = 0;
    (void)snprintf(str, sizeof(str), "%s", entityId);
    H_FIND_S(g_evt_head, str, item);
    if (item == NULL) {
        return NULL;
    }
    return item;
}

static void hash_clear_older_evt(time_t cur_time)
{
    if (g_evt_head == NULL) {
        return;
    }

    struct evt_ts_hash_t *item, *tmp;
    H_ITER(g_evt_head, item, tmp) {
        if ((cur_time - item->evt_ts) <= g_evt_period) {
            continue;
        }
        H_DEL(g_evt_head, item);
        (void)free(item);
    }
}

static unsigned int hash_count_evt(void)
{
    unsigned int evt_num;
    evt_num = H_COUNT(g_evt_head);
    return evt_num;
}

static int is_evt_need_report(const char *entityId, time_t cur_time)
{
    struct evt_ts_hash_t *item = NULL;

    item = hash_find_evt(entityId);
    if (item == NULL) {
        hash_add_evt(entityId, cur_time);
        if (hash_find_evt(entityId) == NULL) {
            ERROR("evt_hash add eventid[%s] failed.\n", entityId);
            return 0;
        } else {
            return 1;
        }
    }
    if ((cur_time > item->evt_ts) && (cur_time - item->evt_ts >= g_evt_period)) {
        item->evt_ts = cur_time;
        return 1;
    }
    return 0;
}
#else
void report_logs(const struct event_info_s* evt, enum evt_sec_e sec, const char * fmt, ...)
{
    return;
}
#endif

void emit_otel_log(struct otel_log *ol)
{
    // output format: |log|<Timestamp>|<SeverityText>|<SeverityNumber>|<Resource>|<Attributes>|<Body>|
    fprintf(stdout, "|%s|%llu|\"%s\"|%d|%s|%s|\"%s\"|\n",
        "log",
        ol->timestamp,
        secs[ol->sec].sec_text,
        secs[ol->sec].sec_number,
        ol->resource,
        ol->attrs,
        ol->body);
}

void init_event_mgr(unsigned int time_out)
{
    g_evt_period = time_out;
    return;
}
