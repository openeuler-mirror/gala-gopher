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
 * Description: probe params parser
 ******************************************************************************/
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>


#include "args.h"
#include "probe_mng.h"
#include "probe_params_parser.h"

struct param_flags_s {
    const char *desc;
    u32 flags;
};

struct param_flags_s param_l7pro_flags[] = {
    {"http",    L7PROBE_TRACING_HTTP},
    {"dns",     L7PROBE_TRACING_DNS},
    {"redis",   L7PROBE_TRACING_REDIS},
    {"mysql",   L7PROBE_TRACING_MYSQL},
    {"pgsql",   L7PROBE_TRACING_PGSQL},
    {"kafka",   L7PROBE_TRACING_KAFKA},
    {"mongo",   L7PROBE_TRACING_MONGO}
};

struct param_flags_s param_metrics_flags[] = {
    {"raw",         SUPPORT_METRICS_RAW},
    {"telemetry",   SUPPORT_METRICS_TELEM}
};

struct param_flags_s param_env_flags[] = {
    {"node",        SUPPORT_NODE_ENV},
    {"container",   SUPPORT_CONTAINER_ENV},
    {"kubenet",     SUPPORT_K8S_ENV}
};

static int __get_params_flags(struct param_flags_s param_flags[], size_t size, const char *target)
{
    for (int i = 0; i < size; i++) {
        if (!strcasecmp(param_flags[i].desc, target)) {
            return param_flags[i].flags;
        }
    }
    return 0;
}

#define __PROBE_PARAM_DEFAULT_STRLEN    64
struct param_key_s;
typedef int (*parser_param_key)(struct probe_s *, struct param_key_s *, const cJSON *);
struct param_val_s {
    int default_int;
    int min, max;
    char default_string[__PROBE_PARAM_DEFAULT_STRLEN];
};
struct param_key_s {
    const char *key;
    struct param_val_s v;
    parser_param_key parser;
};

static int parser_sample_peirod(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    int value = (int)key_item->valueint;
    if (value < param_key->v.min || value > param_key->v.max) {
        return -1;
    }

    probe->probe_param.sample_period = (u32)value;
    return 0;
}

static int parser_report_peirod(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    int value = (int)key_item->valueint;
    if (value < param_key->v.min || value > param_key->v.max) {
        return -1;
    }

    probe->probe_param.period = (u32)value;
    return 0;
}


static int parser_latency_thr(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    int value = (int)key_item->valueint;
    if (value < param_key->v.min || value > param_key->v.max) {
        return -1;
    }

    probe->probe_param.latency_thr = (u32)value;
    return 0;
}

static int parser_drops_thr(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    int value = (int)key_item->valueint;
    if (value < param_key->v.min || value > param_key->v.max) {
        return -1;
    }

    probe->probe_param.drops_count_thr = (u32)value;
    return 0;
}

static int parser_res_lower_thr(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    int value = (int)key_item->valueint;
    if (value < param_key->v.min || value > param_key->v.max) {
        return -1;
    }

    probe->probe_param.res_percent_lower = (u32)value;
    return 0;
}

static int parser_res_upper_thr(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    int value = (int)key_item->valueint;
    if (value < param_key->v.min || value > param_key->v.max) {
        return -1;
    }

    probe->probe_param.res_percent_upper = (u32)value;
    return 0;
}

static int parser_report_event(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    int value = (int)key_item->valueint;
    if (value < param_key->v.min || value > param_key->v.max) {
        return -1;
    }

    probe->probe_param.logs = (u32)value;
    return 0;
}

static int parser_metrics_type(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    cJSON *object;
    u32 metrics_flags;
    size_t size = cJSON_GetArraySize(key_item);
    for (int i = 0; i < size; i++) {
        object = cJSON_GetArrayItem(key_item, i);
        if (object->type != cJSON_String) {
            return -1;
        }

        const char* value = (const char *)object->valuestring;
        metrics_flags = __get_params_flags(param_metrics_flags,
                        sizeof(param_metrics_flags)/sizeof(struct param_flags_s), value);
        if (metrics_flags == 0) {
            return -1;
        }

        probe->probe_param.metrics_flags |= metrics_flags;
    }


    return 0;
}

static int parser_work_env(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    cJSON *object;
    u32 env_flags;

    size_t size = cJSON_GetArraySize(key_item);
    for (int i = 0; i < size; i++) {
        object = cJSON_GetArrayItem(key_item, i);
        if (object->type != cJSON_String) {
            return -1;
        }
        const char* value = (const char *)object->valuestring;

        env_flags = __get_params_flags(param_env_flags,
                    sizeof(param_env_flags)/sizeof(struct param_flags_s), value);
        if (env_flags == 0) {
            return -1;
        }

        probe->probe_param.env_flags |= env_flags;
    }


    return 0;
}

static int parser_l7pro(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    cJSON *object;
    u32 l7pro_flags;

    size_t size = cJSON_GetArraySize(key_item);
    for (int i = 0; i < size; i++) {
        object = cJSON_GetArrayItem(key_item, i);
        if (object->type != cJSON_String) {
            return -1;
        }
        const char* value = (const char *)object->valuestring;

        l7pro_flags = __get_params_flags(param_l7pro_flags,
                    sizeof(param_l7pro_flags)/sizeof(struct param_flags_s), value);
        if (l7pro_flags == 0) {
            return -1;
        }

        probe->probe_param.l7_probe_proto_flags |= l7pro_flags;
    }


    return 0;
}

static int parser_report_tcpsport(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    int value = (int)key_item->valueint;
    if (value < param_key->v.min || value > param_key->v.max) {
        return -1;
    }

    probe->probe_param.cport_flag = (u8)value;
    return 0;
}

static int parser_support_ssl(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    int value = (int)key_item->valueint;
    if (value < param_key->v.min || value > param_key->v.max) {
        return -1;
    }

    probe->probe_param.support_ssl = (u8)value;
    return 0;
}

static int parser_pyscope_server(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    const char *value = (const char*)key_item->valuestring;

    if (key_item->type != cJSON_String) {
        return -1;
    }

    (void)strncpy(probe->probe_param.pyroscope_server, value, PYSCOPE_SERVER_URL_LEN - 1);
    return 0;
}

static int parser_sysdebuging_dir(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    const char *value = (const char*)key_item->valuestring;

    if (key_item->type != cJSON_String) {
        return -1;
    }

    (void)strncpy(probe->probe_param.sys_debuging_dir, value, MAX_PATH_LEN - 1);
    return 0;
}

struct param_key_s param_keys[] = {
    {"sample_period",      {DEFAULT_SAMPLE_PERIOD, 100, 10000, ""}, parser_sample_peirod},
    {"report_period",      {DEFAULT_PERIOD, 5, 600, ""},            parser_report_peirod},
    {"latency_thr",        {0, 10, 100000, ""},                     parser_latency_thr},
    {"drops_thr",          {0, 10, 100000, ""},                     parser_drops_thr},
    {"res_lower_thr",      {0, 0, 100, ""},                         parser_res_lower_thr},
    {"res_upper_thr",      {0, 0, 100, ""},                         parser_res_upper_thr},
    {"report_event",       {0, 0, 1, ""},                           parser_report_event},
    {"metrics_type",       {0, 0, 0, "raw"},                        parser_metrics_type},
    {"env",                {0, 0, 0, "node"},                       parser_work_env},
    {"report_source_port", {0, 0, 1, ""},                           parser_report_tcpsport},
    {"l7_protocol",        {0, 0, 0, "http"},                       parser_l7pro},
    {"support_ssl",        {0, 0, 1, ""},                           parser_support_ssl},
    {"pyroscope_server",   {0, 0, 0, "localhost:4040"},             parser_pyscope_server},
    {"debugging_dir",      {0, 0, 0, ""},                           parser_sysdebuging_dir}
};


void set_default_params(struct probe_s *probe)
{
    struct probe_params *params = &probe->probe_param;

    (void)memset(params, 0, sizeof(struct probe_params));
    params->period = DEFAULT_PERIOD;
    params->sample_period = DEFAULT_SAMPLE_PERIOD;
    params->load_probe = DEFAULT_LOAD_PROBE;
    params->kafka_port = DEFAULT_KAFKA_PORT;
    params->metrics_flags = SUPPORT_METRICS_RAW | SUPPORT_METRICS_TELEM;
    params->env_flags = SUPPORT_NODE_ENV;
}


int parse_params(struct probe_s *probe, const cJSON *params_json)
{
    int ret = -1;
    cJSON *key_item, *object;
    struct param_key_s *param_key;
    struct probe_params probe_params_bak = probe->probe_param;
    size_t size = sizeof(param_keys) / sizeof(struct param_key_s);

    for (int i = 0; i < size; i++) {
        param_key = &(param_keys[i]);
        key_item = cJSON_GetObjectItem(params_json, param_key->key);
        if (key_item == NULL) {
            continue;
        }

        ret = param_key->parser(probe, param_key, key_item);
        if (ret) {
            /* Resume old probe params */
            probe->probe_param = probe_params_bak;
            break;
        }
    }

    return ret;
}


