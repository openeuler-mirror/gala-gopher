/*
 * bpf code runs in the Linux kernel
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_USER

#include "bpf.h"
#include "task.h"
#include "proc_map.h"
#include "args_map.h"
#include "glibc_bpf.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} dns_output SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u64));          // context id
    __uint(value_size, sizeof(struct dns_cache_s));
    __uint(max_entries, 1000);
} dns_map SEC(".maps");

static __always_inline __maybe_unused void report_dns_perf_evt(void *ctx, struct dns_cache_s *cache)
{
    (void)bpfbuf_output(ctx, &dns_output, cache, sizeof(struct dns_cache_s));
}

static __always_inline int start_dns(struct pt_regs* ctx)
{
    u32 proc_id;
    u64 key = bpf_get_current_pid_tgid();
    proc_id = key >> INT_LEN;

    if (get_proc_entry(proc_id) == NULL) {
        return 0;
    }

    const char *domain = (const char *)PT_REGS_PARM1(ctx);

    struct dns_cache_s cache = {0};
    bpf_core_read_user(cache.domain, DOMAIN_LEN, domain);
    cache.proc_id = proc_id;
    cache.start_ts = bpf_ktime_get_ns();
    (void)bpf_map_update_elem(&dns_map, &key, &cache, BPF_ANY);
    return 0;
}

static __always_inline int end_dns(struct pt_regs* ctx, enum dns_rc_type_e type)
{
    u64 key = bpf_get_current_pid_tgid();
    u64 ret = (u64)PT_REGS_RC(ctx);

    struct dns_cache_s *cache = (struct dns_cache_s *)bpf_map_lookup_elem(&dns_map, &key);
    if (cache == NULL) {
        goto end;
    }

    if (type == DNS_RC_INT) {
        cache->error = ret;
    } else {
        cache->error = ret ? 0 : 1;
    }
    cache->end_ts = bpf_ktime_get_ns();

    report_dns_perf_evt(ctx, cache);

end:
    (void)bpf_map_delete_elem(&dns_map, &key);
    return 0;
}

// int getaddrinfo(const char *__name, const char *__service, const struct addrinfo *__req, struct addrinfo **__pai);
UPROBE(getaddrinfo, pt_regs)
{
    return start_dns(ctx);
}

URETPROBE(getaddrinfo, pt_regs)
{
    return end_dns(ctx, DNS_RC_INT);
}

// struct hostent *gethostbyname2 (const char *__name, int __af);
UPROBE(gethostbyname2, pt_regs)
{
    return start_dns(ctx);
}

URETPROBE(gethostbyname2, pt_regs)
{
    return end_dns(ctx, DNS_RC_POINTER);
}

// struct hostent *gethostbyname (const char *__name);
UPROBE(gethostbyname, pt_regs)
{
    return start_dns(ctx);
}

URETPROBE(gethostbyname, pt_regs)
{
    return end_dns(ctx, DNS_RC_POINTER);
}
