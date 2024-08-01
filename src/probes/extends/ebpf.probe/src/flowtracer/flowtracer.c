/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: ilyashakhat
 * Create: 2024-01-05
 * Description: FlowTracer plugin
 ******************************************************************************/
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include "bpf.h"
#include "flowtracer.h"
#include "flowtracer.skel.h"

static volatile sig_atomic_t stop;

static void sig_handler(int signo)
{
    stop = 1;
}

static void usage(char *pname)
{
    printf("USAGE:\n  %s <cgroup-path>\n", pname);
    printf("\tLoad and attach FlowTracer BPF program to cgroup2 mounted at the specified path\n");
    exit(1);
}

#ifdef GOPHER_DEBUG
static int handle_evt(void *ctx, void *notification, size_t sz)
{
    struct flow_log *flow_log = notification;

    char local_ip4[16], remote_ip4[16], original_remote_ip4[16];
    inet_ntop(AF_INET, &flow_log->key.local_ip4, local_ip4, sizeof(local_ip4));
    inet_ntop(AF_INET, &flow_log->key.remote_ip4, remote_ip4, sizeof(remote_ip4));
    inet_ntop(AF_INET, &flow_log->data.original_remote_ip4, original_remote_ip4, sizeof(original_remote_ip4));

    char log_buf[40] = "\0";
    if (flow_log->op == FLOW_LOG_ADD) {
        snprintf(log_buf, sizeof(log_buf),
            " original_remote=%s:%u",
            original_remote_ip4, bpf_ntohs(flow_log->data.original_remote_port));
    }
    DEBUG("[FlowTracer:Event] "
        "op=%s"
        " local=%s:%u"
        " remote=%s:%u"
        "%s\n",
        (flow_log->op == FLOW_LOG_ADD)? "ADD": "DEL",
        local_ip4, bpf_ntohs(flow_log->key.local_port),
        remote_ip4, bpf_ntohs(flow_log->key.remote_port),
        log_buf
    );
    return 0;
}
#endif

int main(int argc, char **argv)
{
    char *cg_path;
    int cg_fd;
    struct flowtracer_bpf *flowtracer_skel;
    int err = 0;
    struct ring_buffer *ring_buffer = NULL;

    if (argc < 2) {
        cg_path = FLOWTRACER_CGROUP2_PATH;
        INFO("[FlowTracer] Cgroup2 mount path is not specified, attaching to the default: %s\n", cg_path);
    } else if (!strncmp(argv[argc - 1], "-h", 3)) {
        usage("flowtracer");
    } else {
        cg_path = argv[argc - 1];
    }

    /* Open cgroup path */
    cg_fd = open(cg_path, O_DIRECTORY, O_RDONLY);
    if (cg_fd < 0) {
        ERROR("[FlowTracer] Error opening cgroup2 path %s: %d (%s)\n", cg_path, cg_fd, strerror(errno));
        return 1;
    }

    INIT_BPF_APP(flowtracer, EBPF_RLIM_LIMITED);

    /* Open load and verify BPF application */
    flowtracer_skel = flowtracer_bpf__open();
    if (!flowtracer_skel) {
        ERROR("[FlowTracer] Failed to open BPF skeleton\n");
        goto cleanup;
    }

    /* Pin FlowTracer BPF map to the file system */
    err = bpf_map__set_pin_path(flowtracer_skel->maps.flowtracer_data, FLOWTRACER_DATA_MAP_PATH);
    if (err) {
        ERROR("[FlowTracer] Failed to pin FlowTracer BPF map at path %s: %d (%s)\n", FLOWTRACER_DATA_MAP_PATH, err, strerror(errno));
        goto cleanup;
    }

    /* Load BPF program */
    if ((err = flowtracer_bpf__load(flowtracer_skel))) {
        ERROR("[FlowTracer] Failed to load BPF skeleton: %d (%s)\n", err, strerror(errno));
        goto cleanup;
    }

    /* Create signal handler */
    if (signal(SIGINT, sig_handler) == SIG_ERR || signal(SIGTERM, sig_handler) == SIG_ERR) {
        ERROR("[FlowTracer] Failed to set a signal handler: %s\n", strerror(errno));
        goto cleanup;
    }

    /* Attach program to cgroup */
    int prog_fd = bpf_program__fd(flowtracer_skel -> progs.flowtracer_sockops_fn);
    err = bpf_prog_attach(prog_fd, cg_fd, BPF_CGROUP_SOCK_OPS, 0);
    if (err) {
        ERROR("[FlowTracer] Failed to attach BPF program to cgroup2 mounted at %s: %d (%s)\n", cg_path, err, strerror(errno));
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = flowtracer_bpf__attach(flowtracer_skel);
    if (err) {
        ERROR("[FlowTracer] Failed to attach BPF tracepoint: %d (%s)\n", err, strerror(errno));
        goto cleanup;
    }

#ifdef GOPHER_DEBUG
    /* Setup ring buffer to poll FlowTracer map operations for debug purposes */
    ring_buffer = ring_buffer__new(bpf_map__fd(flowtracer_skel->maps.ring_buffer), handle_evt, NULL, NULL);
    if (!ring_buffer) {
        err = 1;
        ERROR("[FlowTracer] Failed to create ring buffer!\n");
        goto cleanup;
    }
#endif

    INFO("[FlowTracer] Started successfully\n");

    /* Process events */
    while (!stop) {
#ifdef GOPHER_DEBUG
        err = ring_buffer__poll(ring_buffer, THOUSAND);
        if (err < 0 && err != -EINTR) {
            ERROR("[FlowTracer] Error polling ring buffer: %d (%s)\n", err, strerror(errno));
            break;
        }
#endif
        sleep(1);
    }

cleanup:
    bpf_prog_detach(cg_fd, BPF_CGROUP_SOCK_OPS);
    flowtracer_bpf__detach(flowtracer_skel);
    ring_buffer__free(ring_buffer);
    flowtracer_bpf__destroy(flowtracer_skel);
    close(cg_fd);
    // Delete BPF map (pinned at the default libbpf location)
    unlink("/sys/fs/bpf/flowtracer_data");
    INFO("[FlowTracer] Cleanup is completed\n");
    return -err;
}