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
#include <stdio.h>

#include "container.h"
#include "json_tool.h"
#include "container_cache.h"

#define __MAX_CACHE_POD_NUM         100
#define __MAX_CACHE_POD_LABEL_NUM   100
#define __MAX_CACHE_CONTAINER_NUM   (10 * __MAX_CACHE_POD_NUM)

static void delete_if_container_caches_full(struct container_cache **caches_ptr)
{
    struct container_cache *cache, *tmp;

    if (H_COUNT(*caches_ptr) >= __MAX_CACHE_CONTAINER_NUM) {
        H_ITER(*caches_ptr, cache, tmp) {
            H_DEL(*caches_ptr, cache);
            free_container_cache(cache);
            return;
        }
    }
}

static void delete_if_pod_caches_full(struct pod_cache **caches_ptr)
{
    struct pod_cache *cache, *tmp;

    if (H_COUNT(*caches_ptr) >= __MAX_CACHE_POD_NUM) {
        H_ITER(*caches_ptr, cache, tmp) {
            H_DEL(*caches_ptr, cache);
            free_pod_cache(cache);
            return;
        }
    }
}

struct container_cache *lkup_container_cache(struct container_cache *caches, const char *container_id)
{
    struct container_cache *con_cache = NULL;

    H_FIND_S(caches, container_id, con_cache);
    return con_cache;
}

void fill_container_info(struct container_cache *con_cache)
{
    int ret;

    con_cache->container_name[0] = 0;
    con_cache->container_image[0] = 0;

    con_cache->container_hostname[0] = 0;
    ret = get_container_hostname(con_cache->container_id, con_cache->container_hostname, sizeof(con_cache->container_hostname));
    if (ret) {
        DEBUG("[IMDB] Failed to get container hostname(container_id=%s)\n", con_cache->container_id);
        con_cache->container_hostname[0] = 0;
    }

    con_cache->pod_id[0] = 0;
}

struct container_cache *create_container_cache(struct container_cache **caches_ptr, const char *container_id)
{
    struct container_cache *con_cache;
    int ret;

    con_cache = (struct container_cache *)calloc(1, sizeof(struct container_cache));
    if (con_cache == NULL) {
        return NULL;
    }
    (void)memset(con_cache, 0, sizeof(struct container_cache));

    ret = snprintf(con_cache->container_id, sizeof(con_cache->container_id), "%s", container_id);
    if (ret < 0) {
        free(con_cache);
        return NULL;
    }

    fill_container_info(con_cache);
    delete_if_container_caches_full(caches_ptr);
    H_ADD_S(*caches_ptr, container_id, con_cache);
    return con_cache;
}

void free_container_cache(struct container_cache *cache)
{
    free(cache);
}

void free_container_caches(struct container_cache **caches_ptr)
{
    struct container_cache *cache, *tmp;

    H_ITER(*caches_ptr, cache, tmp) {
        H_DEL(*caches_ptr, cache);
        free_container_cache(cache);
    }
    *caches_ptr = NULL;
}

struct pod_cache *lkup_pod_cache(struct pod_cache *caches, const char *pod_id)
{
    struct pod_cache *pod_cache = NULL;

    H_FIND_S(caches, pod_id, pod_cache);
    return pod_cache;
}

#define __KW_POD_NAME       "io.kubernetes.pod.name"
#define __KW_POD_NAMESPACE  "io.kubernetes.pod.namespace"

static void fill_pod_info(struct pod_cache *pod_cache, const char *container_id)
{
    char pod_labels_buf[POD_LABELS_BUF_SIZE];
    void *pod_labels_json;
    char *label_val;
    struct pod_label_cache *pod_label_cache;
    int ret;

    pod_labels_buf[0] = 0;
    ret = get_container_pod_labels(container_id, pod_labels_buf, sizeof(pod_labels_buf));
    if (ret) {
        DEBUG("[IMDB] Failed to get container pod labels(container_id=%s)\n", container_id);
        return;
    }

    pod_labels_json = Json_Parse(pod_labels_buf);
    if (!pod_labels_json) {
        return;
    }
    if (!Json_IsObject(pod_labels_json)) {
        Json_Delete(pod_labels_json);
        return;
    }
    struct key_value_pairs *kv_pairs = Json_GetKeyValuePairs(pod_labels_json);
    if (!kv_pairs) {
        return;
    }
    struct key_value *kv;
    Json_ArrayForEach(kv, kv_pairs) {
        label_val = (char *)Json_GetValueString(kv->valuePtr);
        if (!label_val) {
            continue;
        }
        if (!kv->key) {
            continue;
        }
        if (strcmp(kv->key, __KW_POD_NAME) == 0) {
            (void)snprintf(pod_cache->pod_name, sizeof(pod_cache->pod_name), "%s", label_val);
        } else if (strcmp(kv->key, __KW_POD_NAMESPACE) == 0) {
            (void)snprintf(pod_cache->pod_namespace, sizeof(pod_cache->pod_namespace), "%s", label_val);
        }

        pod_label_cache = (struct pod_label_cache *)calloc(1, sizeof(struct pod_label_cache));
        if (!pod_label_cache) {
            continue;
        }
        (void)snprintf(pod_label_cache->key, sizeof(pod_label_cache->key),
                       "%s", kv->key);
        (void)snprintf(pod_label_cache->val, sizeof(pod_label_cache->val), "%s", label_val);
        if (H_COUNT(pod_cache->pod_labels) < __MAX_CACHE_POD_LABEL_NUM) {
            H_ADD_S(pod_cache->pod_labels, key, pod_label_cache);
        } else {
            free(pod_label_cache);
        }
    }
    Json_DeleteKeyValuePairs(kv_pairs);
    Json_Delete(pod_labels_json);
}

struct pod_cache *create_pod_cache(struct pod_cache **caches_ptr, const char *pod_id, const char *container_id)
{
    struct pod_cache *pod_cache;
    int ret;

    pod_cache = (struct pod_cache *)calloc(1, sizeof(struct pod_cache));
    if (!pod_cache) {
        return NULL;
    }
    ret = snprintf(pod_cache->pod_id, sizeof(pod_cache->pod_id), "%s", pod_id);
    if (ret < 0) {
        free(pod_cache);
        return NULL;
    }

    fill_pod_info(pod_cache, container_id);
    delete_if_pod_caches_full(caches_ptr);
    H_ADD_S(*caches_ptr, pod_id, pod_cache);
    return pod_cache;
}

static void free_pod_label_caches(struct pod_label_cache **caches_ptr)
{
    struct pod_label_cache *cache, *tmp;

    H_ITER(*caches_ptr, cache, tmp) {
        H_DEL(*caches_ptr, cache);
        free(cache);
    }
    *caches_ptr = NULL;
}

void free_pod_cache(struct pod_cache *cache)
{
    if (!cache) {
        return;
    }

    free_pod_label_caches(&cache->pod_labels);
    free(cache);
}

void free_pod_caches(struct pod_cache **caches_ptr)
{
    struct pod_cache *cache, *tmp;

    H_ITER(*caches_ptr, cache, tmp) {
        H_DEL(*caches_ptr, cache);
        free_pod_cache(cache);
    }
    *caches_ptr = NULL;
}

struct pod_label_cache *lkup_pod_label_cache(struct pod_label_cache *caches, const char *key)
{
    struct pod_label_cache *cache;

    H_FIND_S(caches, key, cache);
    return cache;
}
