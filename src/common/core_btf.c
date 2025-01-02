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
 * Author: luzhihao
 * Create: 2023-11-18
 * Description: eBPF CO-RE BTF
 ******************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <sys/utsname.h>

#include "common.h"
#include "core_btf.h"

static bool vmlinux_btf_exists(void)
{
    struct btf *btf;
    int err;

    btf = btf__load_vmlinux_btf();
    err = libbpf_get_error(btf);
    if (err) {
        return false;
    }

    btf__free(btf);
    return true;
}

#define CORE_BTF_FILE "/opt/gala-gopher/btf/%s.btf"
int ensure_core_btf(struct bpf_object_open_opts* opts)
{
    char btf_file[PATH_LEN];
    struct utsname uts;

    if (vmlinux_btf_exists()) {
        return 0;
    }

    if (uname(&uts) == -1) {
        return -1;
    }

    btf_file[0] = 0;
    (void)snprintf(btf_file, PATH_LEN, CORE_BTF_FILE, uts.release);
    if (access((const char *)btf_file, 0) != 0) {
        return -1;
    }

    opts->btf_custom_path = strdup(btf_file);
    if (!opts->btf_custom_path) {
        return -1;
    }
    return 0;
}

void cleanup_core_btf(struct bpf_object_open_opts* opts)
{
    if (!opts) {
        return;
    }

    if (!opts->btf_custom_path) {
        return;
    }

    free((char *)opts->btf_custom_path);
    opts->btf_custom_path = NULL;
    return;
}
