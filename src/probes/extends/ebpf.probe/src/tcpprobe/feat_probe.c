#include <sys/syscall.h>
#include <unistd.h>

#include "bpf.h"
#include "feat_probe.skel.h"

#include "feat_probe.h"

static struct {
    bool probed;
    bool supports_tstamp;
} features;

static int probe_features() {
    int ret = -1;

    if (features.probed) {
        return 0;
    }

    OPEN(feat_probe, out, true);
    LOAD_ATTACH(tcpprobe, feat_probe, out, true);

    /* Invoke feature probe BPF program */
    syscall(__NR_nanosleep, NULL, NULL);

    if (!feat_probe_skel->bss->feature_probe_completed) {
        ERROR("[TCPPROBE] Failed to invoke feature probe BPF program\n");
        goto out;
    }

    features.supports_tstamp = feat_probe_skel->bss->supports_tstamp;
    features.probed = true;
    ret = 0;

out:
    UNLOAD(feat_probe);
    return ret;
}

bool probe_tstamp() {
    int err;

    err = probe_features();
    if (err) {
        WARN("[TCPPROBE] Failed to probe features; probe_tstamp() defaults to false\n");
        return false;
    }

    return features.supports_tstamp;
}
