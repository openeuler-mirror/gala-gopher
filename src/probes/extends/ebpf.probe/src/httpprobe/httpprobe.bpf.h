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
 * Author: Ernest
 * Create: 2022-08-27
 * Description: include file for *.bpf.c
 ******************************************************************************/
#ifndef __HTTPPROBE_BPF_H
#define __HTTPPROBE_BPF_H

#pragma once

#include "httpprobe.h"

struct conn_key_t {
    u32 tgid;
    int skfd;
};

struct conn_data_t {
    u64 sock;
    int method;
    int status;
    u64 recvtime;
    u64 ackedtime;
};

struct conn_samp_key_t {
    struct sock *sk;
};

struct conn_samp_data_t {
    u32 tgid;
    int skfd;
    int method;
    int status;
    u32 endseq;
    u64 recvtime;
    u64 ackedtime;
    u64 longestrtt;
    u64 lastreport;
};

struct bpf_map_def SEC("maps") conn_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct conn_key_t),
    .value_size = sizeof(struct conn_data_t),
    .max_entries = MAX_CONN_LEN,
};

struct bpf_map_def SEC("maps") conn_samp_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct conn_samp_key_t),
    .value_size = sizeof(struct conn_samp_data_t),
    .max_entries = MAX_CONN_LEN,
};

static __always_inline int parse_req_method(const char *str)
{
    if (__builtin_memcmp(str, "GET ", 4) == 0) {
        return HTTP_GET;
    } else if (__builtin_memcmp(str, "HEAD", 4) == 0 && str[4] == ' ') {
        return HTTP_HEAD;
    } else if (__builtin_memcmp(str, "POST", 4) == 0 && str[4] == ' ') {
        return HTTP_POST;
    } else if (__builtin_memcmp(str, "PUT ", 4) == 0) {
        return HTTP_PUT;
    } else if (__builtin_memcmp(str, "DELE", 4) == 0 && __builtin_memcmp(str + 3, "ETE ", 4) == 0) {
        return HTTP_DELETE;
    } else if (__builtin_memcmp(str, "CONN", 4) == 0 && __builtin_memcmp(str + 4, "ECT ", 4) == 0) {
        return HTTP_CONNECT;
    } else if (__builtin_memcmp(str, "OPTI", 4) == 0 && __builtin_memcmp(str + 4, "ONS ", 4) == 0) {
        return HTTP_OPTIONS;
    } else if (__builtin_memcmp(str, "TRAC", 4) == 0 && __builtin_memcmp(str + 2, "ACE ", 4) == 0) {
        return HTTP_TRACE;
    } else if (__builtin_memcmp(str, "PATC", 4) == 0 && __builtin_memcmp(str + 2, "TCH ", 4) == 0) {
        return HTTP_PATCH;
    }
    return HTTP_UNKNOWN;
}

#endif