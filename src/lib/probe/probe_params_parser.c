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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "args.h"
#include "probe_mng.h"
#include "json_tool.h"
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
typedef int (*parser_param_key)(struct probe_s *, const struct param_key_s *, const void *);
typedef void (*parser_param_default)(struct probe_params *, const struct param_val_s *);

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

static int parser_sample_peirod(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    int value = Json_GetValueInt(key_item);
    if (value < param_key->v.min || value > param_key->v.max || value == INVALID_INT_NUM) {
        PARSE_ERR("params.%s invalid value %d, must be in [%d, %d]",
                  param_key->key, value, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.sample_period = (u32)value;
    return 0;
}

static int parser_report_peirod(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    int value = Json_GetValueInt(key_item);
    if (value < param_key->v.min || value > param_key->v.max || value == INVALID_INT_NUM) {
        PARSE_ERR("params.%s invalid value %d, must be in [%d, %d]",
                  param_key->key, value, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.period = (u32)value;
    return 0;
}

static int parser_latency_thr(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    int value = Json_GetValueInt(key_item);
    if (value < param_key->v.min || value > param_key->v.max || value == INVALID_INT_NUM) {
        PARSE_ERR("params.%s invalid value %d, must be in [%d, %d]",
                  param_key->key, value, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.latency_thr = (u32)value;
    return 0;
}

static int parser_offline_thr(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    int value = Json_GetValueInt(key_item);
    if (value < param_key->v.min || value > param_key->v.max || value == INVALID_INT_NUM) {
        PARSE_ERR("params.%s invalid value %d, must be in [%d, %d]",
                  param_key->key, value, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.offline_thr = (u32)value;
    return 0;
}

static int parser_drops_thr(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    int value = Json_GetValueInt(key_item);
    if (value < param_key->v.min || value > param_key->v.max || value == INVALID_INT_NUM) {
        PARSE_ERR("params.%s invalid value %d, must be in [%d, %d]",
                  param_key->key, value, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.drops_count_thr = (u32)value;
    return 0;
}

static int parser_res_lower_thr(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    int value = Json_GetValueInt(key_item);
    if (value < param_key->v.min || value > param_key->v.max || value == INVALID_INT_NUM) {
        PARSE_ERR("params.%s invalid value %d, must be in [%d, %d]",
                  param_key->key, value, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.res_percent_lower = (char)value;
    return 0;
}

static int parser_res_upper_thr(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    int value = Json_GetValueInt(key_item);
    if (value < param_key->v.min || value > param_key->v.max || value == INVALID_INT_NUM) {
        PARSE_ERR("params.%s invalid value %d, must be in [%d, %d]",
                  param_key->key, value, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.res_percent_upper = (char)value;
    return 0;
}

#if 0
static int parse_host_ip_fields(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    char *p = NULL;
    int index = 0;
    if (!Json_IsString(key_item)) {
        return -1;
    }

    char *value = (char *)Json_GetValueString(key_item);
    p = strtok(value, ",");
    while (p != NULL && index < MAX_IP_NUM) {
        (void)snprintf(probe->probe_param.host_ip_list[index++], MAX_IP_LEN, "%s", p);
        p = strtok(NULL, ",");
    }
    return 0;
}
#endif

static int parser_report_event(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    int value = Json_GetValueInt(key_item);
    if (value < param_key->v.min || value > param_key->v.max || value == INVALID_INT_NUM) {
        PARSE_ERR("params.%s invalid value %d, must be in [%d, %d]",
                  param_key->key, value, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.logs = (char)value;
    return 0;
}

static int parser_metrics_type(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    void *object;
    u32 metrics_flags;

    probe->probe_param.metrics_flags = 0;
    size_t size = Json_GetArraySize(key_item);
    for (int i = 0; i < size; i++) {
        object = Json_GetArrayItem(key_item, i);
        if (!Json_IsString(object)) {
            return -1;
        }

        const char* value = (const char *)Json_GetValueString(object);
        metrics_flags = __get_params_flags(param_metrics_flags,
                        sizeof(param_metrics_flags) / sizeof(struct param_flags_s), value);
        if (metrics_flags == 0) {
            PARSE_ERR("params.%s invalid value: %s", param_key->key, value);
            return -1;
        }

        probe->probe_param.metrics_flags |= (char)metrics_flags;
    }


    return 0;
}

static int parser_work_env(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    void *object;
    u32 env_flags;

    probe->probe_param.env_flags = 0;
    size_t size = Json_GetArraySize(key_item);
    for (int i = 0; i < size; i++) {
        object = Json_GetArrayItem(key_item, i);
        if (!Json_IsString(object)) {
            return -1;
        }
        const char* value = (const char *)Json_GetValueString(object);

        env_flags = __get_params_flags(param_env_flags,
                    sizeof(param_env_flags) / sizeof(struct param_flags_s), value);
        if (env_flags == 0) {
            PARSE_ERR("params.%s invalid value: %s", param_key->key, value);
            return -1;
        }

        probe->probe_param.env_flags |= (char)env_flags;
    }


    return 0;
}

static int parser_l7pro(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    void *object;
    u32 l7pro_flags;

    probe->probe_param.l7_probe_proto_flags = 0;
    size_t size = Json_GetArraySize(key_item);
    for (int i = 0; i < size; i++) {
        object = Json_GetArrayItem(key_item, i);
        if (!Json_IsString(object)) {
            return -1;
        }
        const char* value = (const char *)Json_GetValueString(object);

        l7pro_flags = __get_params_flags(param_l7pro_flags,
                    sizeof(param_l7pro_flags) / sizeof(struct param_flags_s), value);
        if (l7pro_flags == 0) {
            PARSE_ERR("params.%s invalid value: %s", param_key->key, value);
            return -1;
        }

        probe->probe_param.l7_probe_proto_flags |= l7pro_flags;
    }


    return 0;
}

static int parser_support_ssl(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    int value = Json_GetValueInt(key_item);
    if (value < param_key->v.min || value > param_key->v.max || value == INVALID_INT_NUM) {
        PARSE_ERR("params.%s invalid value %d, must be in [%d, %d]",
                  param_key->key, value, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.support_ssl = (char)value;
    return 0;
}

static int parser_svg_dir(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    const char *value = (const char*)Json_GetValueString(key_item);

    if (!Json_IsString(key_item)) {
        return -1;
    }

    if (check_path_for_security(value)) {
        PARSE_ERR("params.%s contains unsafe characters", param_key->key);
        return -1;
    }

    (void)snprintf(probe->probe_param.svg_dir, sizeof(probe->probe_param.svg_dir), "%s", value);
    return 0;
}

static int parser_flame_dir(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    const char *value = (const char*)Json_GetValueString(key_item);

    if (!Json_IsString(key_item)) {
        return -1;
    }

    if (check_path_for_security(value)) {
        PARSE_ERR("params.%s contains unsafe characters", param_key->key);
        return -1;
    }
    (void)snprintf(probe->probe_param.flame_dir, sizeof(probe->probe_param.flame_dir), "%s", value);
    return 0;
}

static int parser_pyscope_server(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    const char *value = (const char*)Json_GetValueString(key_item);

    if (!Json_IsString(key_item)) {
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

static int parser_svg_period(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    int value = Json_GetValueInt(key_item);
    if (value == 0) {
        value = param_key->v.default_int;
    } else if (value < param_key->v.min || value > param_key->v.max || value == INVALID_INT_NUM) {
        PARSE_ERR("params.%s invalid value %d, must be in [%d, %d]",
                  param_key->key, value, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.svg_period = (u32)value;
    return 0;
}

static int parser_perf_sample_period(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    int value = Json_GetValueInt(key_item);
    if (value == 0) {
        value = param_key->v.default_int;
    } else if (value < param_key->v.min || value > param_key->v.max || value == INVALID_INT_NUM) {
        PARSE_ERR("params.%s invalid value %d, must be in [%d, %d]",
                  param_key->key, value, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.perf_sample_period = (u32)value;
    return 0;
}

static int parser_multi_instance(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    int value = Json_GetValueInt(key_item);
    if (value < param_key->v.min || value > param_key->v.max || value == INVALID_INT_NUM) {
        PARSE_ERR("params.%s invalid value %d, must be in [%d, %d]",
                  param_key->key, value, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.multi_instance_flag = (char)value;
    return 0;
}

static int parser_native_stack(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    int value = Json_GetValueInt(key_item);
    if (value < param_key->v.min || value > param_key->v.max || value == INVALID_INT_NUM) {
        PARSE_ERR("params.%s invalid value %d, must be in [%d, %d]",
                  param_key->key, value, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.native_stack_flag = (char)value;
    return 0;
}

static int parser_cluster_ip_backend_flag(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    int value = Json_GetValueInt(key_item);
    if (value < param_key->v.min || value > param_key->v.max || value == INVALID_INT_NUM) {
        PARSE_ERR("params.%s invalid value %d, must be in [%d, %d]",
                  param_key->key, value, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.cluster_ip_backend = (char)value;
    return 0;
}


#if 0
static int parser_sysdebuging_dir(struct probe_s *probe, struct param_key_s *param_key, const void *key_item)
{
    const char *value = (const char*)Json_GetListValueString(key_item);

    if (!Json_Type(key_item) != JSON_STRING) {
        return -1;
    }

    (void)snprintf(probe->probe_param.sys_debuging_dir, sizeof(probe->probe_param.sys_debuging_dir), "%s", value);
    return 0;
}
#endif

static int parser_dev_name(struct probe_s *probe, const struct param_key_s *param_key, const void* key_item)
{
    const char *value = (const char*)Json_GetValueString(key_item);

    if (!Json_IsString(key_item) || value == NULL) {
        return -1;
    }

    if (strlen(value) >= sizeof(probe->probe_param.target_dev)) {
        PARSE_ERR("params.%s value is too long, len must be less than %lu",
                  param_key->key, sizeof(probe->probe_param.target_dev));
        return -1;
    }

    (void)snprintf(probe->probe_param.target_dev, sizeof(probe->probe_param.target_dev), "%s", value);
    return 0;
}

static int parser_kafka_port(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    int value = Json_GetValueInt(key_item);
    if (value < param_key->v.min || value > param_key->v.max || value == INVALID_INT_NUM) {
        PARSE_ERR("params.%s invalid value %d, must be in [%d, %d]",
                  param_key->key, value, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.kafka_port = (u32)value;
    return 0;
}

static int parser_continuous_sampling(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    int value = Json_GetValueInt(key_item);
    if (value < param_key->v.min || value > param_key->v.max || value == INVALID_INT_NUM) {
        PARSE_ERR("params.%s invalid value %d, must be in [%d, %d]",
                  param_key->key, value, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.continuous_sampling_flag = (char)value;
    return 0;
}

static int parser_elf_path(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    const char *value = (const char*)Json_GetValueString(key_item);

    if (!Json_IsString(key_item)) {
        return -1;
    }

    if (check_path_for_security(value)) {
        PARSE_ERR("params.%s contains unsafe characters", param_key->key);
        return -1;
    }
    (void)snprintf(probe->probe_param.elf_path, sizeof(probe->probe_param.elf_path), "%s", value);
    return 0;
}

static int parser_cadvisor_port(struct probe_s *probe, const struct param_key_s *param_key, const void *key_item)
{
    int value = Json_GetValueInt(key_item);
    if (value < param_key->v.min || value > param_key->v.max || value == INVALID_INT_NUM) {
        PARSE_ERR("params.%s invalid value %d, must be in [%d, %d]",
                  param_key->key, value, param_key->v.min, param_key->v.max);
        return -1;
    }

    probe->probe_param.cadvisor_port = (u32)value;
    return 0;
}

#define SET_DEFAULT_PARAMS_INTER(field) \
    static void set_default_params_inter_##field(struct probe_params *params, const struct param_val_s *value) \
    { \
        params->field = (u32)value->default_int; \
    }

#define SET_DEFAULT_PARAMS_CAHR(field) \
    static void set_default_params_char_##field(struct probe_params *params, const struct param_val_s *value) \
    { \
        params->field = (char)value->default_int; \
    }

#define SET_DEFAULT_PARAMS_STR(field) \
    static void set_default_params_str_##field(struct probe_params *params, const struct param_val_s *value) \
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
SET_DEFAULT_PARAMS_INTER(cadvisor_port);


SET_DEFAULT_PARAMS_CAHR(logs);
SET_DEFAULT_PARAMS_CAHR(metrics_flags);
SET_DEFAULT_PARAMS_CAHR(env_flags);
SET_DEFAULT_PARAMS_CAHR(support_ssl);
SET_DEFAULT_PARAMS_CAHR(res_percent_upper);
SET_DEFAULT_PARAMS_CAHR(res_percent_lower);
SET_DEFAULT_PARAMS_CAHR(continuous_sampling_flag);
SET_DEFAULT_PARAMS_CAHR(multi_instance_flag);
SET_DEFAULT_PARAMS_CAHR(native_stack_flag);
SET_DEFAULT_PARAMS_CAHR(cluster_ip_backend);

#if 0
SET_DEFAULT_PARAMS_STR(sys_debuging_dir);
#endif
SET_DEFAULT_PARAMS_STR(pyroscope_server);
SET_DEFAULT_PARAMS_STR(svg_dir);
SET_DEFAULT_PARAMS_STR(flame_dir);

#define SAMPLE_PERIOD       "sample_period"
#define REPORT_PERIOD       "report_period"
#define LATENCY_THR         "latency_thr"
#define OFFLINE_THR         "offline_thr"
#define DROPS_THR           "drops_thr"
#define RES_LOWER_THR       "res_lower_thr"
#define RES_UPPER_THR       "res_upper_thr"
#define REPORT_EVENT        "report_event"
#define METRICS_TYPE        "metrics_type"
#define ENV                 "env"
#define L7_PROTOCOL         "l7_protocol"
#define SUPPORT_SSL         "support_ssl"
#define PYROSCOPE_SERVER    "pyroscope_server"
#define SVG_PERIOD          "svg_period"
#define PERF_SAMPLE_PERIOD  "perf_sample_period"
#define MULTI_INSTANCE      "multi_instance"
#define NATIVE_STACK        "native_stack"
#define CLUSTER_IP_BACKEND  "cluster_ip_backend"
#define SVG_DIR             "svg_dir"
#define FLAME_DIR           "flame_dir"
#if 0
#define DEBUGGING_DIR       "debugging_dir"
#define HOST_IP_FIELDS      "host_ip_fields"
#endif
#define DEV_NAME_KEY        "dev_name"
#define CONTINUOUS_SAMPLING "continuous_sampling"
#define ELF_PATH            "elf_path"
#define KAFKA_PORT          "kafka_port"
#define CADVISOR_PORT       "cadvisor_port"

struct param_key_s param_keys[] = {
    {SAMPLE_PERIOD,       {DEFAULT_SAMPLE_PERIOD, 100, 10000, ""},   parser_sample_peirod,           set_default_params_inter_sample_period, JSON_NUMBER},
    {REPORT_PERIOD,       {DEFAULT_PERIOD, 5, 600, ""},              parser_report_peirod,           set_default_params_inter_period, JSON_NUMBER},
    {LATENCY_THR,         {0, 10, 100000, ""},                       parser_latency_thr,             set_default_params_inter_latency_thr, JSON_NUMBER},
    {OFFLINE_THR,         {0, 10, 100000, ""},                       parser_offline_thr,             set_default_params_inter_offline_thr, JSON_NUMBER},
    {DROPS_THR,           {0, 10, 100000, ""},                       parser_drops_thr,               set_default_params_inter_drops_count_thr, JSON_NUMBER},
    {RES_LOWER_THR,       {0, 0, 100, ""},                           parser_res_lower_thr,           set_default_params_char_res_percent_lower, JSON_NUMBER},
    {RES_UPPER_THR,       {0, 0, 100, ""},                           parser_res_upper_thr,           set_default_params_char_res_percent_upper, JSON_NUMBER},
    {REPORT_EVENT,        {0, 0, 1, ""},                             parser_report_event,            set_default_params_char_logs, JSON_NUMBER},
    {METRICS_TYPE,        {SUPPORT_METRICS_RAW | SUPPORT_METRICS_TELEM, 0, 0, "raw"}, parser_metrics_type,   set_default_params_char_metrics_flags, JSON_ARRAY},
    {ENV,                 {SUPPORT_NODE_ENV, 0, 0, "node"},          parser_work_env,                set_default_params_char_env_flags, JSON_ARRAY},
    {L7_PROTOCOL,         {0, 0, 0, ""},                             parser_l7pro,                   set_default_params_inter_l7_probe_proto_flags, JSON_ARRAY},
    {SUPPORT_SSL,         {0, 0, 1, ""},                             parser_support_ssl,             set_default_params_char_support_ssl, JSON_NUMBER},
    {PYROSCOPE_SERVER,    {0, 0, 0, "localhost:4040"},               parser_pyscope_server,          set_default_params_str_pyroscope_server, JSON_STRING},
    {SVG_PERIOD,          {180, 30, 600, ""},                        parser_svg_period,              set_default_params_inter_svg_period, JSON_NUMBER},
    {PERF_SAMPLE_PERIOD,  {10, 10, 1000, ""},                        parser_perf_sample_period,      set_default_params_inter_perf_sample_period, JSON_NUMBER},
    {MULTI_INSTANCE,      {0, 0, 1, ""},                             parser_multi_instance,          set_default_params_char_multi_instance_flag, JSON_NUMBER},
    {NATIVE_STACK,        {0, 0, 1, ""},                             parser_native_stack,            set_default_params_char_native_stack_flag, JSON_NUMBER},
    {CLUSTER_IP_BACKEND,  {0, 0, 1, ""},                             parser_cluster_ip_backend_flag, set_default_params_char_cluster_ip_backend, JSON_NUMBER},
    {SVG_DIR,             {0, 0, 0, "/var/log/gala-gopher/stacktrace"},  parser_svg_dir,             set_default_params_str_svg_dir, JSON_STRING},
    {FLAME_DIR,           {0, 0, 0, "/var/log/gala-gopher/flamegraph"},  parser_flame_dir,           set_default_params_str_flame_dir, JSON_STRING},
#if 0
    {DEBUGGING_DIR,       {0, 0, 0, ""},                             parser_sysdebuging_dir,         set_default_params_str_sys_debuging_dir, JSON_STRING},
    {HOST_IP_FIELDS,      {0, 0, 0, ""},                             parse_host_ip_fields,           NULL, JSON_STRING},
#endif
    {DEV_NAME_KEY,        {0, 0, 0, ""},                             parser_dev_name,                NULL, JSON_STRING},
    {CONTINUOUS_SAMPLING, {0, 0, 1, ""},                             parser_continuous_sampling,     set_default_params_char_continuous_sampling_flag, JSON_NUMBER},
    {ELF_PATH,            {0, 0, 0, ""},                             parser_elf_path,                NULL, JSON_STRING},
    {KAFKA_PORT,          {DEFAULT_KAFKA_PORT, 1, 65535, ""},        parser_kafka_port,              set_default_params_inter_kafka_port, JSON_NUMBER},
    {CADVISOR_PORT,       {DEFAULT_CADVISOR_PORT, 1, 65535, ""},     parser_cadvisor_port,           set_default_params_inter_cadvisor_port, JSON_NUMBER}
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

int parse_params(struct probe_s *probe, const void *params_json)
{
    int ret = -1;
    void *key_item, *object;
    struct param_key_s *param_key;
    size_t size = sizeof(param_keys) / sizeof(struct param_key_s);

    for (int i = 0; i < size; i++) {
        param_key = &(param_keys[i]);
        key_item = Json_GetObjectItem(params_json, param_key->key);
        if (key_item == NULL) {
            continue;
        }
        // key_item has String, number, array, object etc.
        if (Json_GetType(key_item) != param_key->key_type) {
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

static void *param_flags_to_json(unsigned int flags, struct param_flags_s param_flags[], size_t size)
{
    void *arr = Json_CreateArray();
    int i;

    for (i = 0; i < size; i++) {
        if (flags & param_flags[i].flags) {
            Json_AddStringItemToArray(arr, param_flags[i].desc);
        }
    }

    return arr;
}

void probe_params_to_json(struct probe_s *probe, void *params)
{
    struct probe_params *probe_param = &probe->probe_param;
    enum probe_type_e probe_type = probe->probe_type;
    void *flags_arr;
    size_t flags_size;

    Json_AddUIntItemToObject(params, SAMPLE_PERIOD, probe_param->sample_period);
    Json_AddUIntItemToObject(params, REPORT_PERIOD, probe_param->period);
    Json_AddCharItemToObject(params, RES_LOWER_THR, probe_param->res_percent_lower);
    Json_AddCharItemToObject(params, RES_UPPER_THR, probe_param->res_percent_upper);
    Json_AddCharItemToObject(params, REPORT_EVENT, probe_param->logs);

    if (probe_param->latency_thr != 0) {
        Json_AddUIntItemToObject(params, LATENCY_THR, probe_param->latency_thr);
    }

    if (probe_param->offline_thr != 0) {
        Json_AddUIntItemToObject(params, OFFLINE_THR, probe_param->offline_thr);
    }

    if (probe_param->drops_count_thr != 0) {
        Json_AddUIntItemToObject(params, DROPS_THR, probe_param->drops_count_thr);
    }

    flags_size = sizeof(param_metrics_flags) / sizeof(param_metrics_flags[0]);
    flags_arr = param_flags_to_json(probe_param->metrics_flags, param_metrics_flags, flags_size);
    Json_AddItemToObject(params, METRICS_TYPE, flags_arr);
    Json_Delete(flags_arr);

    flags_size = sizeof(param_env_flags) / sizeof(param_env_flags[0]);
    flags_arr = param_flags_to_json(probe_param->env_flags, param_env_flags, flags_size);
    Json_AddItemToObject(params, ENV, flags_arr);
    Json_Delete(flags_arr);

    if (probe_type == PROBE_L7) {
        flags_size = sizeof(param_l7pro_flags) / sizeof(param_l7pro_flags[0]);
        flags_arr = param_flags_to_json(probe_param->l7_probe_proto_flags, param_l7pro_flags, flags_size);
        Json_AddItemToObject(params, L7_PROTOCOL, flags_arr);
        Json_Delete(flags_arr);
        Json_AddCharItemToObject(params, SUPPORT_SSL, probe_param->support_ssl);
    }
    if (probe_type == PROBE_L7 || probe_type == PROBE_TCP) {
        Json_AddCharItemToObject(params, CLUSTER_IP_BACKEND, probe_param->cluster_ip_backend);
    }
    if (probe_type == PROBE_BASEINFO) {
        Json_AddStringToObject(params, ELF_PATH, probe_param->elf_path);
    }
    if (probe_type == PROBE_FG) {
        Json_AddStringToObject(params, PYROSCOPE_SERVER, probe_param->pyroscope_server);
        Json_AddUIntItemToObject(params, SVG_PERIOD,probe_param->svg_period);
        Json_AddUIntItemToObject(params, PERF_SAMPLE_PERIOD, probe_param->perf_sample_period);
        Json_AddCharItemToObject(params, MULTI_INSTANCE, probe_param->multi_instance_flag);
        Json_AddCharItemToObject(params, NATIVE_STACK, probe_param->native_stack_flag);
        Json_AddStringToObject(params, SVG_DIR, probe_param->svg_dir);
        Json_AddStringToObject(params, FLAME_DIR, probe_param->flame_dir);
    }
    if (probe_type == PROBE_IO || probe_type == PROBE_KAFKA || probe_type == PROBE_KSLI ||
        probe_type == PROBE_POSTGRE_SLI || probe_type == PROBE_BASEINFO || probe_type == PROBE_TCP) {
        Json_AddStringToObject(params, DEV_NAME_KEY, probe_param->target_dev);
    }
    if (probe_type == PROBE_KSLI) {
        Json_AddCharItemToObject(params, CONTINUOUS_SAMPLING, probe_param->continuous_sampling_flag);
    }
    if (probe_type == PROBE_NGINX || probe_type == PROBE_HAPROXY || probe_type == PROBE_DNSMASQ) {
        Json_AddStringToObject(params, ELF_PATH, probe_param->elf_path);
    }
    if (probe_type == PROBE_KAFKA) {
        Json_AddUIntItemToObject(params, KAFKA_PORT, probe_param->kafka_port);
    }
    if (probe_type == PROBE_CONTAINER) {
        Json_AddUIntItemToObject(params, CADVISOR_PORT, probe_param->cadvisor_port);
    }
}
