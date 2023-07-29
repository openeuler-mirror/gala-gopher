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
struct param_key_s;
struct param_val_s;
typedef int (*parser_param_key)(struct probe_s *, struct param_key_s *, const cJSON *);
typedef void (*parser_param_default)(struct probe_params *, struct param_val_s *);

#define __PROBE_PARAM_DEFAULT_STRLEN    64
struct param_val_s {
    int default_int;
    int min, max;
    char default_string[__PROBE_PARAM_DEFAULT_STRLEN];
};
struct param_key_s {
    const char *key;
    struct param_val_s v;
    parser_param_key parser;
    parser_param_default defaulter;
    int key_type;
};

static int parser_sample_peirod(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    int value = (int)key_item->valueint;
    if (value < param_key->v.min || value > param_key->v.max) {
        PARSE_ERR("params.%s invalid value, must be in [%d, %d]",
                  param_key->key, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.sample_period = (u32)value;
    return 0;
}

static int parser_report_peirod(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    int value = (int)key_item->valueint;
    if (value < param_key->v.min || value > param_key->v.max) {
        PARSE_ERR("params.%s invalid value, must be in [%d, %d]",
                  param_key->key, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.period = (u32)value;
    return 0;
}

static int parser_latency_thr(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    int value = (int)key_item->valueint;
    if (value < param_key->v.min || value > param_key->v.max) {
        PARSE_ERR("params.%s invalid value, must be in [%d, %d]",
                  param_key->key, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.latency_thr = (u32)value;
    return 0;
}

static int parser_drops_thr(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    int value = (int)key_item->valueint;
    if (value < param_key->v.min || value > param_key->v.max) {
        PARSE_ERR("params.%s invalid value, must be in [%d, %d]",
                  param_key->key, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.drops_count_thr = (u32)value;
    return 0;
}

static int parser_res_lower_thr(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    int value = (int)key_item->valueint;
    if (value < param_key->v.min || value > param_key->v.max) {
        PARSE_ERR("params.%s invalid value, must be in [%d, %d]",
                  param_key->key, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.res_percent_lower = (char)value;
    return 0;
}

static int parser_res_upper_thr(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    int value = (int)key_item->valueint;
    if (value < param_key->v.min || value > param_key->v.max) {
        PARSE_ERR("params.%s invalid value, must be in [%d, %d]",
                  param_key->key, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.res_percent_upper = (char)value;
    return 0;
}

#if 0
static int parse_host_ip_fields(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    char *p = NULL;
    int index = 0;

    if (key_item->type != cJSON_String) {
        return -1;
    }

    char *value = key_item->valuestring;
    p = strtok(value, ",");
    while (p != NULL && index < MAX_IP_NUM) {
        (void)snprintf(probe->probe_param.host_ip_list[index++], MAX_IP_LEN, "%s", p);
        p = strtok(NULL, ",");
    }
    return 0;
}
#endif

static int parser_report_event(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    int value = (int)key_item->valueint;
    if (value < param_key->v.min || value > param_key->v.max) {
        PARSE_ERR("params.%s invalid value, must be in [%d, %d]",
                  param_key->key, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.logs = (char)value;
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
            PARSE_ERR("params.%s invalid value: %s", param_key->key, value);
            return -1;
        }

        probe->probe_param.metrics_flags |= (char)metrics_flags;
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
            PARSE_ERR("params.%s invalid value: %s", param_key->key, value);
            return -1;
        }

        probe->probe_param.env_flags |= (char)env_flags;
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
            PARSE_ERR("params.%s invalid value: %s", param_key->key, value);
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
        PARSE_ERR("params.%s invalid value, must be in [%d, %d]",
                  param_key->key, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.cport_flag = (char)value;
    return 0;
}

static int parser_support_ssl(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    int value = (int)key_item->valueint;
    if (value < param_key->v.min || value > param_key->v.max) {
        PARSE_ERR("params.%s invalid value, must be in [%d, %d]",
                  param_key->key, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.support_ssl = (char)value;
    return 0;
}

static int parser_svg_dir(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    const char *value = (const char*)key_item->valuestring;

    if (key_item->type != cJSON_String) {
        return -1;
    }

    (void)snprintf(probe->probe_param.svg_dir, sizeof(probe->probe_param.svg_dir), "%s", value);
    return 0;
}

static int parser_flame_dir(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    const char *value = (const char*)key_item->valuestring;

    if (key_item->type != cJSON_String) {
        return -1;
    }

    (void)snprintf(probe->probe_param.flame_dir, sizeof(probe->probe_param.flame_dir), "%s", value);
    return 0;
}

static int parser_pyscope_server(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    const char *value = (const char*)key_item->valuestring;

    if (key_item->type != cJSON_String) {
        return -1;
    }

    if (value == NULL) {
        value = param_key->v.default_string;
    }

    if (strlen(value) >= sizeof(probe->probe_param.pyroscope_server)) {
        PARSE_ERR("params.%s value is too long, len must be less than %d",
                  param_key->key, sizeof(probe->probe_param.pyroscope_server));
        return -1;
    }

    (void)snprintf(probe->probe_param.pyroscope_server, sizeof(probe->probe_param.pyroscope_server), "%s", value);
    return 0;
}

static int parser_svg_period(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    int value = (int)key_item->valueint;
    if (value == 0) {
        value = param_key->v.default_int;
    } else if (value < param_key->v.min || value > param_key->v.max) {
        PARSE_ERR("params.%s invalid value, must be in [%d, %d]",
                  param_key->key, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.svg_period = (u32)value;
    return 0;
}

static int parser_perf_sample_period(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    int value = (int)key_item->valueint;
    if (value == 0) {
        value = param_key->v.default_int;
    } else if (value < param_key->v.min || value > param_key->v.max) {
        PARSE_ERR("params.%s invalid value, must be in [%d, %d]",
                  param_key->key, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.perf_sample_period = (u32)value;
    return 0;
}

static int parser_separate_out(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    int value = (int)key_item->valueint;
    if (value < param_key->v.min || value > param_key->v.max) {
        PARSE_ERR("params.%s invalid value, must be in [%d, %d]",
                  param_key->key, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.separate_out_flag = (char)value;
    return 0;
}

#if 0
static int parser_sysdebuging_dir(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    const char *value = (const char*)key_item->valuestring;

    if (key_item->type != cJSON_String) {
        return -1;
    }

    (void)snprintf(probe->probe_param.sys_debuging_dir, sizeof(probe->probe_param.sys_debuging_dir), "%s", value);
    return 0;
}
#endif

static int parser_dev_name(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    const char *value = (const char*)key_item->valuestring;

    if (key_item->type != cJSON_String) {
        return -1;
    }

    if (strlen(value) >= sizeof(probe->probe_param.target_dev)) {
        PARSE_ERR("params.%s value is too long, len must be less than %d",
                  param_key->key, sizeof(probe->probe_param.target_dev));
        return -1;
    }

    (void)snprintf(probe->probe_param.target_dev, sizeof(probe->probe_param.target_dev), "%s", value);
    return 0;
}

static int parser_kafka_port(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    int value = (int)key_item->valueint;
    if (value < param_key->v.min || value > param_key->v.max) {
        PARSE_ERR("params.%s invalid value, must be in [%d, %d]",
                  param_key->key, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.kafka_port = (u32)value;
    return 0;
}

static int parser_continuous_sampling(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    int value = (int)key_item->valueint;
    if (value < param_key->v.min || value > param_key->v.max) {
        PARSE_ERR("params.%s invalid value, must be in [%d, %d]",
                  param_key->key, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.continuous_sampling_flag = (char)value;
    return 0;
}

static int parser_elf_path(struct probe_s *probe, struct param_key_s *param_key, const cJSON *key_item)
{
    const char *value = (const char*)key_item->valuestring;

    if (key_item->type != cJSON_String) {
        return -1;
    }

    (void)snprintf(probe->probe_param.elf_path, sizeof(probe->probe_param.elf_path), "%s", value);
    return 0;
}

#define SET_DEFAULT_PARAMS_INTER(field) \
    static void set_default_params_inter_##field(struct probe_params *params, struct param_val_s *value) \
    { \
        params->field = (u32)value->default_int; \
    }

#define SET_DEFAULT_PARAMS_CAHR(field) \
    static void set_default_params_char_##field(struct probe_params *params, struct param_val_s *value) \
    { \
        params->field = (char)value->default_int; \
    }

#define SET_DEFAULT_PARAMS_STR(field) \
    static void set_default_params_str_##field(struct probe_params *params, struct param_val_s *value) \
    { \
        (void)snprintf(params->field, sizeof(params->field), "%s", value->default_string); \
    }

SET_DEFAULT_PARAMS_INTER(period);
SET_DEFAULT_PARAMS_INTER(sample_period);
SET_DEFAULT_PARAMS_INTER(latency_thr);
SET_DEFAULT_PARAMS_INTER(offline_thr);
SET_DEFAULT_PARAMS_INTER(drops_count_thr);
SET_DEFAULT_PARAMS_INTER(kafka_port);
SET_DEFAULT_PARAMS_INTER(l7_probe_proto_flags);
SET_DEFAULT_PARAMS_INTER(svg_period);
SET_DEFAULT_PARAMS_INTER(perf_sample_period);


SET_DEFAULT_PARAMS_CAHR(logs);
SET_DEFAULT_PARAMS_CAHR(metrics_flags);
SET_DEFAULT_PARAMS_CAHR(env_flags);
SET_DEFAULT_PARAMS_CAHR(support_ssl);
SET_DEFAULT_PARAMS_CAHR(res_percent_upper);
SET_DEFAULT_PARAMS_CAHR(res_percent_lower);
SET_DEFAULT_PARAMS_CAHR(cport_flag);
SET_DEFAULT_PARAMS_CAHR(continuous_sampling_flag);
SET_DEFAULT_PARAMS_CAHR(separate_out_flag);

#if 0
SET_DEFAULT_PARAMS_STR(sys_debuging_dir);
#endif
SET_DEFAULT_PARAMS_STR(pyroscope_server);
SET_DEFAULT_PARAMS_STR(svg_dir);
SET_DEFAULT_PARAMS_STR(flame_dir);


struct param_key_s param_keys[] = {
    {"sample_period",      {DEFAULT_SAMPLE_PERIOD, 100, 10000, ""}, parser_sample_peirod, set_default_params_inter_sample_period, cJSON_Number},
    {"report_period",      {DEFAULT_PERIOD, 5, 600, ""},            parser_report_peirod, set_default_params_inter_period, cJSON_Number},
    {"latency_thr",        {0, 10, 100000, ""},                     parser_latency_thr, set_default_params_inter_latency_thr, cJSON_Number},
    {"drops_thr",          {0, 10, 100000, ""},                     parser_drops_thr, set_default_params_inter_drops_count_thr, cJSON_Number},
    {"res_lower_thr",      {0, 0, 100, ""},                         parser_res_lower_thr, set_default_params_char_res_percent_lower, cJSON_Number},
    {"res_upper_thr",      {0, 0, 100, ""},                         parser_res_upper_thr, set_default_params_char_res_percent_upper, cJSON_Number},
    {"report_event",       {0, 0, 1, ""},                           parser_report_event, set_default_params_char_logs, cJSON_Number},
    {"metrics_type",       {SUPPORT_METRICS_RAW | SUPPORT_METRICS_TELEM, 0, 0, "raw"}, parser_metrics_type, set_default_params_char_metrics_flags, cJSON_Array},
    {"env",                {SUPPORT_NODE_ENV, 0, 0, "node"},        parser_work_env, set_default_params_char_env_flags, cJSON_Array},
    {"report_source_port", {0, 0, 1, ""},                           parser_report_tcpsport, set_default_params_char_cport_flag, cJSON_Number},
    {"l7_protocol",        {0, 0, 0, "http"},                       parser_l7pro, set_default_params_inter_l7_probe_proto_flags, cJSON_Array},
    {"support_ssl",        {0, 0, 1, ""},                           parser_support_ssl, set_default_params_char_support_ssl, cJSON_Number},
    {"pyroscope_server",   {0, 0, 0, "localhost:4040"},             parser_pyscope_server, set_default_params_str_pyroscope_server, cJSON_String},
    {"svg_period",         {180, 30, 600, ""},                      parser_svg_period, set_default_params_inter_svg_period, cJSON_Number},
    {"perf_sample_period", {10, 10, 1000, ""},                      parser_perf_sample_period, set_default_params_inter_perf_sample_period, cJSON_Number},
    {"separate_out",       {0, 0, 1, ""},                           parser_separate_out, set_default_params_char_separate_out_flag, cJSON_Number},
    {"svg_dir",            {0, 0, 0, "/var/log/gala-gopher/stacktrace"}, parser_svg_dir, set_default_params_str_svg_dir, cJSON_String},
    {"flame_dir",          {0, 0, 0, "/var/log/gala-gopher/flamegraph"}, parser_flame_dir, set_default_params_str_flame_dir, cJSON_String},
#if 0
    {"debugging_dir",      {0, 0, 0, ""},                           parser_sysdebuging_dir, set_default_params_str_sys_debuging_dir, cJSON_String},
    {"host_ip_fields",     {0, 0, 0, ""},                           parse_host_ip_fields, NULL, cJSON_String},
#endif
    {"dev_name",           {0, 0, 0, ""},                           parser_dev_name, NULL, cJSON_String},
    {"continuous_sampling", {0, 0, 1, ""},                          parser_continuous_sampling, set_default_params_char_continuous_sampling_flag, cJSON_Number},
    {"elf_path",            {0, 0, 0, ""},                          parser_elf_path, NULL, cJSON_String},
    {"kafka_port",         {DEFAULT_KAFKA_PORT, 1, 65535, ""},      parser_kafka_port, set_default_params_inter_kafka_port, cJSON_Number}
};

void set_default_params(struct probe_s *probe)
{
    struct param_key_s *param_key;
    struct probe_params *params = &probe->probe_param;

    (void)memset(params, 0, sizeof(struct probe_params));

    size_t size = sizeof(param_keys) / sizeof(struct param_key_s);
    for (int i = 0; i < size; i++) {
        param_key = &(param_keys[i]);
        if (param_key->defaulter) {
            param_key->defaulter(params, &(param_key->v));
        }
    }
}

int parse_params(struct probe_s *probe, const cJSON *params_json)
{
    int ret = -1;
    cJSON *key_item, *object;
    struct param_key_s *param_key;
    size_t size = sizeof(param_keys) / sizeof(struct param_key_s);

    for (int i = 0; i < size; i++) {
        param_key = &(param_keys[i]);
        key_item = cJSON_GetObjectItem(params_json, param_key->key);
        if (key_item == NULL) {
            continue;
        }

        if (key_item->type != param_key->key_type) {
            PARSE_ERR("params.%s invalid data type", param_key->key);
            return -1;
        }

        ret = param_key->parser(probe, param_key, key_item);
        if (ret) {
            break;
        }
    }

    return ret;
}