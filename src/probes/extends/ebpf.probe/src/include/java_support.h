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
 * Author: wo_cow
 * Create: 2022-12-09
 * Description: java support header
 ******************************************************************************/
#ifndef __JAVA_SUPPORT_H__
#define __JAVA_SUPPORT_H__

#pragma once

#define FILENAME_LEN    128

#define JAVA_SYM_AGENT_FILE     "jvm_agent.so"
#define JAVA_SYM_FILE           "java-symbols.bin"

struct java_attach_args {
    int proc_obj_map_fd;
    int loop_period;
    int is_only_attach_once;    // 1 - attach only once, eg: jvmtiagent
                                // 0 - attach every loop, eg: jsseprobeagent
    char agent_file_name[FILENAME_LEN];
    char tmp_file_name[FILENAME_LEN];
};

int get_host_java_tmp_file(int pid, const char *file_name, char *file_path, int path_len);
int detect_proc_is_java(int pid, char *comm, int comm_len);
void *java_support(void *arg);

#endif
