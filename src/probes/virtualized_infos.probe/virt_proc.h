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
* Author: dowzyx
 * Create: 2022-11-10
 * Description: include file for virt_proc
 ******************************************************************************/
#ifndef VIRT_PROC_RPOBE__H
#define VIRT_PROC_RPOBE__H

#pragma once

#include "common.h"

#define MAX_SYSTEM_UUID_LEN     40
#define MAX_VM_NAME_LEN         64

struct proc_infos {
    int tgid;
    char uuid[MAX_SYSTEM_UUID_LEN];
    char vm_name[MAX_VM_NAME_LEN];

};

int virt_proc_init(void);
int virt_proc_probe(void);

#endif