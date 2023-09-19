#ifndef __FEAT_PROBE_H
#define __FEAT_PROBE_H

#ifdef BPF_PROG_KERN
#include <bpf/bpf_core_read.h>

#include "vmlinux.h"

static inline bool probe_tstamp()
{
    return bpf_core_field_exists(((struct sk_buff *)0)->tstamp);
}
#endif

#if !defined(BPF_PROG_KERN) && !defined(BPF_PROG_USER)
bool probe_tstamp();
#endif

#endif
