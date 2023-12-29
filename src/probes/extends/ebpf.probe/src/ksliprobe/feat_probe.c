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
 * Create: 2023-11-10
 * Description: Kernel feature probes
 ******************************************************************************/

#include <sys/syscall.h>
#include <unistd.h>

#include "bpf.h"
#include "feat_probe.skel.h"

#include "feat_probe.h"

static struct feature_probe __probe = {0};

static int probe_features()
{
    int ret = -1;
    u32 key = 0;
    struct feature_probe probe = {0};

    if (__probe.is_probed) {
        return 0;
    }

    INIT_OPEN_OPTS(feat_probe);
    PREPARE_CUSTOM_BTF(feat_probe);
    OPEN_OPTS(feat_probe, out, true);

    LOAD_ATTACH(ksliprobe, feat_probe, out, true);

    /* Invoke feature probe BPF program */
    syscall(__NR_nanosleep, NULL, NULL);

    (void)bpf_map_lookup_elem(GET_MAP_FD(feat_probe, feature_map), &key, &probe);

    if (probe.is_probed == 0) {
        ERROR("[KSLIPROBE] Failed to invoke feature probe BPF program\n");
        goto out;
    }

    __probe.is_probed = 1;
    __probe.is_tstamp_enabled = probe.is_tstamp_enabled;
    ret = 0;

out:
    UNLOAD(feat_probe);
    return ret;
}

bool probe_tstamp() {
    int err;

    err = probe_features();
    if (err) {
        WARN("[KSLIPROBE] Failed to probe features; probe_tstamp() defaults to false\n");
        return false;
    }

    return __probe.is_tstamp_enabled;
}
