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
 * Description: jvm probe main prog
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include "args.h"
#include "common.h"
#include "object.h"
#include "java_support.h"
#include "jvmprobe.h"

static struct probe_params params = {.period = DEFAULT_PERIOD};

static volatile sig_atomic_t stop = 0;
static void sig_int(int signal)
{
    stop = 1;
}

static int load_jvm_probe(struct java_attach_args *args)
{
    int err;
    pthread_t attach_thd;

    err = pthread_create(&attach_thd, NULL, java_support, (void *)args);
    if (err != 0) {
        ERROR("[JVMPROBE]: Failed to create java_support_pthread.\n");
        return -1;
    }
    (void)pthread_detach(attach_thd);

    INFO("[JVMPROBE]: init jvmprobe prog succeed.\n");
    return 0;
}

int main(int argc, char **argv)
{
    int err = 0;
    struct java_attach_args attach_args = {0};

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %d\n", errno);
        return errno;
    }

    err = args_parse(argc, argv, &params);
    if (err != 0) {
        return -1;
    }

    obj_module_init();

    attach_args.proc_obj_map_fd = obj_get_proc_obj_map_fd();
    attach_args.loop_period = params.period;
    attach_args.is_only_attach_once = 0;
    (void)snprintf(attach_args.agent_file_name, FILENAME_LEN, JVMPROBE_AGENT_FILE);
    (void)snprintf(attach_args.tmp_file_name, FILENAME_LEN, JVMPROBE_TMP_FILE);
        
    err = load_jvm_probe(&attach_args);
    if (err < 0) {
        goto out;
    }

    while (!stop) {
        java_msg_handler(&attach_args);
        sleep(params.period);
    }

out:
    obj_module_exit();
    return err;
}

