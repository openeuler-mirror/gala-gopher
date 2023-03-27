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
 * Author: Mr.lu
 * Create: 2021-10-18
 * Description: probe's args
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <getopt.h>
#include "logs.h"
#include "args.h"

#define OUT_PUT_PERIOD_MAX     (120) // 2mim
#define OUT_PUT_PERIOD_MIN     (1)  // 1s
#define MAX_PARAM_LEN           128
#define MAX_PORT_NUM            65535
#define FILTER_BY_TASKPROBE    "task"

static void __set_default_params(struct probe_params *params)
{
    (void)memset(params, 0, sizeof(struct probe_params));
    params->period = DEFAULT_PERIOD;
    params->sample_period = DEFAULT_SAMPLE_PERIOD;
    params->load_probe = DEFAULT_LOAD_PROBE;
    params->kafka_port = DEFAULT_KAFKA_PORT;
    params->metrics_flags = SUPPORT_METRICS_RAW | SUPPORT_METRICS_TELEM;
    params->env_flags = SUPPORT_NODE_ENV;    // Support for node environment(include guest/host os)
}

static void __parse_host_ip_fields(char *ip_str, struct probe_params *params)
{
    char *p = NULL;
    int index = 0;

    if (ip_str == NULL || strlen(ip_str) == 0) {
        return;
    }

    p = strtok(ip_str, ",");
    while (p != NULL) {
        if (index >= MAX_IP_NUM) {
            break;
        }
        (void)strncpy((char *)params->host_ip_list[index++], p, MAX_IP_LEN - 1);
        p = strtok(NULL, ",");
    }
    return;
}

static char __is_digit_str(const char *s)
{
    int len = (int)strlen(s);
    for (int i = 0; i < len; i++) {
        if (!(isdigit(s[i]))) {
            return 0;
        }
    }
    return 1;
}

static void __filter_arg_parse(char *arg, struct probe_params *params)
{
    if (strcmp(arg, FILTER_BY_TASKPROBE) == 0) {
        params->filter_task_probe = 1;
        return;
    }

    if (__is_digit_str(arg)) {
        params->filter_pid = (unsigned int)atoi(arg);
        return;
    }

    (void)snprintf((void *)params->target_comm, MAX_COMM_LEN, "%s", arg);

    return;
}

// gala-gopher.conf only support one arg, used set out put period
static int __period_arg_parse(char opt, char *arg, struct probe_params *params)
{
    unsigned int interval, cport_flag;

    switch (opt) {
        case 't':
            interval = (unsigned int)atoi(arg);
            if (interval < OUT_PUT_PERIOD_MIN || interval > OUT_PUT_PERIOD_MAX) {
                ERROR("Please check arg(t), val shold inside 1~120.\n");
                return -1;
            }
            params->period = interval;
            break;
        case 's':
            interval = (unsigned int)atoi(arg);
            params->sample_period = interval;
            break;
        case 'p':
            if (arg != NULL) {
                (void)snprintf((void *)params->elf_path, MAX_PATH_LEN, "%s", arg);
            }
            break;
        case 'w':
            if (arg != NULL) {
                (void)snprintf((void *)params->task_whitelist, MAX_PATH_LEN, "%s", arg);
            }
            break;
        case 'c':
            cport_flag = (unsigned int)atoi(arg);
            if (cport_flag != 0 && cport_flag != 1) {
                ERROR("Please check arg(t), val shold be 1:cport_valid 0:cport_invalid.\n");
                return -1;
            }
            params->cport_flag = (unsigned char)cport_flag;
            break;
        case 'T':
            params->latency_thr = (unsigned int)atoi(arg);
            break;
        case 'J':
            params->jitter_thr = (unsigned int)atoi(arg);
            break;
        case 'O':
            params->offline_thr = (unsigned int)atoi(arg);
            break;
        case 'D':
            params->drops_count_thr = (unsigned int)atoi(arg);
            break;
        case 'U':
            params->res_percent_upper = (char)atoi(arg);
        case 'e':
            params->env_flags = (char)atoi(arg);
            if (params->env_flags == 0) {
                params->env_flags = SUPPORT_NODE_ENV;
            }
        case 'm':
            params->metrics_flags = (char)atoi(arg);
            if (params->metrics_flags == 0) {
                params->metrics_flags = SUPPORT_METRICS_RAW | SUPPORT_METRICS_TELEM;
            }
            break;
        case 'L':
            params->res_percent_lower = (char)atoi(arg);
            break;
        case 'F':
            __filter_arg_parse(arg, params);
            break;
        case 'l':
            params->logs = 1;
            break;
        case 'd':
            if (arg != NULL) {
                (void)snprintf((void *)params->netcard_list, MAX_PATH_LEN, "%s", arg);
                (void)snprintf((void *)params->target_dev, DEV_NAME, "%s", arg);
            }
            break;
        case 'P':
            unsigned int param_val = (unsigned int)atoi(arg);
            params->load_probe = param_val;
            if (params->load_probe == 0) {
                // if -P 0 then set load_probe to default
                params->load_probe = DEFAULT_LOAD_PROBE;
            }

            params->l7_probe_proto_flags = param_val;
            break;
        case 'C':
            params->continuous_sampling_flag = 1;
            break;
        case 'k':
            params->kafka_port = (unsigned int)atoi(arg);
            if (params->kafka_port > MAX_PORT_NUM) {
                ERROR("Please check arg(k), kafka port shold be less than 65535.\n");
                return -1;
            }
            break;
        case 'i':
            __parse_host_ip_fields(arg, params);
            break;
        case 'T':
            params->latency_thr = (unsigned int)atoi(arg);
            break;
        default:
            return -1;
    }

    return 0;
}

static int __args_parse(int argc, char **argv, char *opt_str, struct probe_params *params)
{
    int ch = -1;

    if (opt_str == NULL) {
        return -1;
    }

    while ((ch = getopt(argc, argv, opt_str)) != -1) {
        if (__period_arg_parse(ch, optarg, params) != 0) {
            return -1;
        }
    }
    return 0;
}

int args_parse(int argc, char **argv, struct probe_params *params)
{
    __set_default_params(params);

    return __args_parse(argc, argv, __OPT_S, params);
}

static void __params_val_parse(char *p, char params_val[], size_t params_len)
{
    size_t index = 0;
    size_t len = strlen(p);
    for (int i = 1; i < len; i++) {
        if ((p[i] != ' ') && (index < params_len)) {
            params_val[index++] = p[i];
        }
    }
    if (index < params_len) {
        params_val[index] = '\0';
    }
}

/*
  -p val -c val2
*/
#define ARGS_SPILT_STRING   " -"
int params_parse(char *s, struct probe_params *params)
{
    char opt;
    char params_val[MAX_PARAM_LEN];
    char temp[MAX_PARAM_LEN];
    int slen = strlen(s);
    int split_len = strlen(ARGS_SPILT_STRING);
    int i, j, start;

    __set_default_params(params);

    for (i = 0; i < slen; i++) {
        if (s[i] == '-') {
            break;
        }
    }
    start = i + 1;

    for (j = start; j <= slen; j++) {
        if ((strncmp(s + j, ARGS_SPILT_STRING, split_len) == 0) || (s[j] == '\0')) {
            (void)memset(temp, 0, MAX_PARAM_LEN);
            (void)strncpy(temp, s + start, j - start);
            start = j + split_len;

            opt = temp[0];
            params_val[0] = 0;
            __params_val_parse((char *)temp, params_val, MAX_PARAM_LEN);
            if (__period_arg_parse(opt, params_val, params) != 0) {
                return -1;
            }
        }
    }
    return 0;
}

