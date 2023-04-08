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
 * Author: wo_cow
 * Create: 2023-02-20
 * Description: l7probe probe main program
 ******************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "args.h"

#include "include/bpf_mng.h"
#include "include/java_mng.h"
#include "include/pod.h"

volatile sig_atomic_t stop;
static struct probe_params params = {.period = DEFAULT_PERIOD};

static void sig_int(int signo)
{
    stop = 1;
}

int main(int argc, char **argv)
{
    int err = 0;
    struct bpf_prog_s *prog;

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        ERROR("[L7PROBE]: Can't set signal handler: %d\n", errno);
        return -1;
    }

    err = args_parse(argc, argv, &params);
    if (err != 0) {
        return -1;
    }
    INFO("[L7PROBE]: arg parse interval time:%us\n", params.period);

    obj_module_init();

    INIT_BPF_APP(l7probe, EBPF_RLIM_LIMITED);

    prog = init_bpf_progs(&params);
    if (prog == NULL) {
        goto out;
    }
    INFO("[L7PROBE]: l7probe successfully started bpf progs!\n");

    err = init_java_progs(&params);
    if (err != 0) {
        return -1;
    }
    INFO("[L7PROBE]: l7probe successfully started java progs!\n");

    while (!stop) {
        sleep(params.period);
    }

    for (int i = 0; i < prog->num; i++) {
        if (prog->pbs[i] != NULL) {
            pthread_join(prog->resident_thd[i], NULL);
        }
    }

    obj_module_exit();

out:
    unload_bpf_prog(&prog);
    del_pods();
    return -err;
}
