#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN

#include "bpf.h"
#include "feat_probe.h"

bool feature_probe_completed = false;
bool supports_tstamp = false;

SEC("tracepoint/syscalls/sys_enter_nanosleep")
int probe_features(void *ctx)
{
    supports_tstamp = probe_tstamp();

    feature_probe_completed = true;
    return 0;
}
