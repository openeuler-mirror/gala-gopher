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
#ifndef __EXT_LABEL_H__
#define __EXT_LABEL_H__
#include <time.h>
#include <pthread.h>

struct custom_label_elem {
    char *key;
    char *val;
};

struct pod_label_elem {
    char *key;
};

struct ext_label_conf {
    pthread_rwlock_t rwlock;
    time_t last_update_time;
    int custom_label_num;
    struct custom_label_elem *custom_labels;
    int pod_label_num;
    struct pod_label_elem *pod_labels;
};

void update_custom_labels(struct ext_label_conf *ext_label_conf, struct custom_label_elem *custom_labels, int num);
void update_custom_labels_locked(struct ext_label_conf *ext_label_conf, struct custom_label_elem *custom_labels, int num);
void free_custom_labels(struct custom_label_elem *custom_labels, int num);
struct custom_label_elem *dup_custom_labels(struct custom_label_elem *custom_labels, int num);

void update_pod_labels(struct ext_label_conf *ext_label_conf, struct pod_label_elem *pod_labels, int num);
void update_pod_labels_locked(struct ext_label_conf *ext_label_conf, struct pod_label_elem *pod_labels, int num);
void free_pod_labels(struct pod_label_elem *pod_labels, int num);

int copy_ext_label_conf(struct ext_label_conf *dest, const struct ext_label_conf *src);
void destroy_ext_label_conf(struct ext_label_conf *ext_label_conf);
void destroy_ext_label_conf_locked(struct ext_label_conf *ext_label_conf);

#endif