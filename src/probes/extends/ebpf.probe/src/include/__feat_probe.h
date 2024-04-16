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
 * Author: Yang Hanlin
 * Create: 2023-09-18
 * Description: Utility functions for feature probes
 ******************************************************************************/

#ifndef __GOPHER_FEAT_PROBE_H__
#define __GOPHER_FEAT_PROBE_H__

#if defined(BPF_PROG_KERN) || defined(BPF_PROG_USER)
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#endif

#ifdef BPF_PROG_KERN
#include "vmlinux.h"
#elif defined(BPF_PROG_USER)
struct bpf_ringbuf {
};
#endif

#if !defined(BPF_PROG_KERN) && !defined(BPF_PROG_USER)
#include <bpf/bpf.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "common.h"
#endif

/* BPF_MAP_TYPE_RINGBUF original defined in /usr/include/linux/bpf.h, which from kernel-headers
   if BPF_MAP_TYPE_RINGBUF wasn't defined, this kernel does not support using ringbuf */
#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF    27  // defined here to avoid compile error in lower kernel version
#define IS_RINGBUF_DEFINED      0
#else
#define IS_RINGBUF_DEFINED      1
#endif

#if defined(BPF_PROG_KERN) || defined(BPF_PROG_USER)
extern int LINUX_KERNEL_VERSION __kconfig;

static inline int probe_kernel_version(void) {
    return LINUX_KERNEL_VERSION;
}
#else
static inline int __probe_ubuntu_kernel_version(void)
{
    static const char *version_signature_path = "/proc/version_signature";
    u32 major, minor, patch, retval = 0;
    FILE *file;

    if (access(version_signature_path, R_OK)) {
        goto out;
    }

    if (!(file = fopen(version_signature_path, "r"))) {
        goto out;
    }

    if (fscanf(file, "%*s %*s %d.%d.%d", &major, &minor, &patch) != 3) {
        goto out_close_file;
    }
    retval = KERNEL_VERSION(major, minor, patch);

out_close_file:
    fclose(file);
out:
    return retval;
}

static inline int __parse_debian_kernel_version(struct utsname *uts)
{
    u32 major, minor, patch;
    char *p;

    p = strstr(uts->version, "Debian ");
    if (!p) {
        return 0;
    }

    if (sscanf(p, "Debian %d.%d.%d", &major, &minor, &patch) != 3) {
        return 0;
    }

    return KERNEL_VERSION(major, minor, patch);
}

static inline int __parse_normal_kernel_version(struct utsname *uts)
{
    u32 major, minor, patch;

    if (sscanf(uts->release, "%d.%d.%d", &major, &minor, &patch) != 3) {
        return 0;
    }

    return KERNEL_VERSION(major, minor, patch);
}

static inline int probe_kernel_version(void)
{
    int version;
    struct utsname uts;

    if ((version = __probe_ubuntu_kernel_version())) {
        return version;
    }

    uname(&uts);

    if ((version = __parse_debian_kernel_version(&uts))) {
        return version;
    }

    return __parse_normal_kernel_version(&uts);
}
#endif

#if defined(BPF_PROG_KERN) || defined(BPF_PROG_USER)
static inline char probe_ringbuf(void)
{
#if CLANG_VER_MAJOR >= 12
    return (char)bpf_core_type_exists(struct bpf_ringbuf);
#else
    return IS_RINGBUF_DEFINED;
#endif
}
#endif
#if !defined(BPF_PROG_KERN) && !defined(BPF_PROG_USER)
static inline bool probe_ringbuf(void) {
    int map_fd;

    if ((map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, getpagesize(), NULL)) < 0) {
        return false;
    }

    close(map_fd);
    return true;
}
#endif

#endif
