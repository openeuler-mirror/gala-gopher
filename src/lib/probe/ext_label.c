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
 * Author: algorithmofdish
 * Create: 2023-08-31
 * Description: extend label management
 ******************************************************************************/
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "ext_label.h"

void update_custom_labels(struct ext_label_conf *ext_label_conf, struct custom_label_elem *custom_labels, int num)
{
    free_custom_labels(ext_label_conf->custom_labels, ext_label_conf->custom_label_num);
    ext_label_conf->custom_labels = custom_labels;
    ext_label_conf->custom_label_num = num;
    (void)time(&ext_label_conf->last_update_time);
}

void update_custom_labels_locked(struct ext_label_conf *ext_label_conf, struct custom_label_elem *custom_labels, int num)
{
    (void)pthread_rwlock_wrlock(&ext_label_conf->rwlock);
    update_custom_labels(ext_label_conf, custom_labels, num);
    (void)pthread_rwlock_unlock(&ext_label_conf->rwlock);
}

void update_pod_labels(struct ext_label_conf *ext_label_conf, struct pod_label_elem *pod_labels, int num)
{
    free_pod_labels(ext_label_conf->pod_labels, ext_label_conf->pod_label_num);
    ext_label_conf->pod_labels = pod_labels;
    ext_label_conf->pod_label_num = num;
    (void)time(&ext_label_conf->last_update_time);
}

void update_pod_labels_locked(struct ext_label_conf *ext_label_conf, struct pod_label_elem *pod_labels, int num)
{
    (void)pthread_rwlock_wrlock(&ext_label_conf->rwlock);
    update_pod_labels(ext_label_conf, pod_labels, num);
    (void)pthread_rwlock_unlock(&ext_label_conf->rwlock);
}

static void free_custom_label_elem(struct custom_label_elem *elem)
{
    if (elem) {
        free(elem->key);
        free(elem->val);
    }
}

static void free_pod_label_elem(struct pod_label_elem *elem)
{
    if (elem) {
        free(elem->key);
    }
}

void free_custom_labels(struct custom_label_elem *custom_labels, int num)
{
    int i;

    if (!custom_labels) {
        return;
    }

    for (i = 0; i < num; i++) {
        free_custom_label_elem(&custom_labels[i]);
    }
    free(custom_labels);
}

void free_pod_labels(struct pod_label_elem *pod_labels, int num)
{
    int i;

    if (!pod_labels) {
        return;
    }

    for (i = 0; i < num; i++) {
        free_pod_label_elem(&pod_labels[i]);
    }
    free(pod_labels);
}

static struct custom_label_elem *dup_custom_labels(struct custom_label_elem *custom_labels, int num)
{
    struct custom_label_elem *dup = NULL;
    int i;

    dup = (struct custom_label_elem *)calloc(num, sizeof(struct custom_label_elem));
    if (!dup) {
        return NULL;
    }
    for (i = 0; i < num; i++) {
        dup[i].key = strdup(custom_labels[i].key);
        dup[i].val = strdup(custom_labels[i].val);
        if (!dup[i].key || !dup[i].val) {
            free_custom_labels(dup, num);
            return NULL;
        }
    }
    return dup;
}

static struct pod_label_elem *dup_pod_labels(struct pod_label_elem *pod_labels, int num)
{
    struct pod_label_elem *dup = NULL;
    int i;

    dup = (struct pod_label_elem *)calloc(num, sizeof(struct pod_label_elem));
    if (!dup) {
        return NULL;
    }
    for (i = 0; i < num; i++) {
        dup[i].key = strdup(pod_labels[i].key);
        if (!dup[i].key) {
            free_pod_labels(dup, num);
            return NULL;
        }
    }
    return dup;
}

int copy_ext_label_conf(struct ext_label_conf *dest, const struct ext_label_conf *src)
{
    struct custom_label_elem *custom_labels = NULL;
    struct pod_label_elem *pod_labels = NULL;
    int i;

    if (src->custom_label_num > 0) {
        custom_labels = dup_custom_labels(src->custom_labels, src->custom_label_num);
        if (!custom_labels) {
            goto err;
        }
    }

    if (src->pod_label_num > 0) {
        pod_labels = dup_pod_labels(src->pod_labels, src->pod_label_num);
        if (!pod_labels) {
            goto err;
        }
    }

    destroy_ext_label_conf(dest);
    dest->custom_labels = custom_labels;
    dest->custom_label_num = src->custom_label_num;
    dest->pod_labels = pod_labels;
    dest->pod_label_num = src->pod_label_num;
    return 0;
err:
    free_custom_labels(custom_labels, src->custom_label_num);
    free_pod_labels(pod_labels, src->pod_label_num);
    return -1;
}

void destroy_ext_label_conf(struct ext_label_conf *ext_label_conf)
{
    free_custom_labels(ext_label_conf->custom_labels, ext_label_conf->custom_label_num);
    ext_label_conf->custom_labels = NULL;
    ext_label_conf->custom_label_num = 0;

    free_pod_labels(ext_label_conf->pod_labels, ext_label_conf->pod_label_num);
    ext_label_conf->pod_labels = NULL;
    ext_label_conf->pod_label_num = 0;
}

void destroy_ext_label_conf_locked(struct ext_label_conf *ext_label_conf)
{
    (void)pthread_rwlock_wrlock(&ext_label_conf->rwlock);
    destroy_ext_label_conf(ext_label_conf);
    (void)pthread_rwlock_unlock(&ext_label_conf->rwlock);
}