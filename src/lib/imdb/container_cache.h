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
 * Author: algorithmofdish
 * Create: 2023-09-04
 * Description: cache container info
 ******************************************************************************/
#ifndef __CONTAINER_CACHE_H__
#define __CONTAINER_CACHE_H__

#pragma once

#include "common.h"
#include "hash.h"

struct container_cache {
    char container_id[CONTAINER_ABBR_ID_LEN + 1];   // key
    char container_name[CONTAINER_NAME_LEN];
    char container_image[CONTAINER_IMAGE_LEN];
    char container_hostname[CONTAINER_HOSTNAME_LEN];
    char pod_id[POD_ID_LEN + 1];
    H_HANDLE;
};

struct pod_label_cache {
    char key[POD_LABEL_KEY_LEN];    // key
    char val[POD_LABEL_VAL_LEN];
    H_HANDLE;
};

struct pod_cache {
    char pod_id[POD_ID_LEN + 1];    // key
    char pod_name[POD_NAME_LEN];
    char pod_namespace[POD_NAMESPACE_LEN];
    struct pod_label_cache *pod_labels;
    H_HANDLE;
};

struct container_cache *lkup_container_cache(struct container_cache *caches, const char *container_id);
struct container_cache *create_container_cache(struct container_cache **caches_ptr, const char *container_id);
void free_container_cache(struct container_cache *cache);
void free_container_caches(struct container_cache **caches_ptr);
void fill_container_info(struct container_cache *con_cache);
struct pod_cache *lkup_pod_cache(struct pod_cache *caches, const char *pod_id);
struct pod_cache *create_pod_cache(struct pod_cache **caches_ptr, const char *pod_id, const char *container_id);
void free_pod_cache(struct pod_cache *cache);
void free_pod_caches(struct pod_cache **caches_ptr);

struct pod_label_cache *lkup_pod_label_cache(struct pod_label_cache *caches, const char *key);

#endif