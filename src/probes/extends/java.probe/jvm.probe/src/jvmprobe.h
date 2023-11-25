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
 * Author: dowzyx
 * Create: 2023-04-12
 * Description: jvmprobe include file
 ******************************************************************************/
#ifndef __JVMPROBE__H
#define __JVMPROBE__H

#include <uthash.h>

#ifndef JAVA_AGENT_VER
#define JAVA_AGENT_VER ""
#endif

#define JVMPROBE_AGENT_FILE "JvmProbeAgent" JAVA_AGENT_VER ".jar"
#define JVMPROBE_TMP_FILE "jvm-metrics.txt"

#define JVMPROBE_SLEEP_SEC   1


struct proc_key_t {
    u32 pid;         // process id
    u64 start_time;  // time the process started
};

struct proc_hash_t {
    struct proc_key_t key;
    u32 failed_count;
    UT_hash_handle hh;
};

#endif