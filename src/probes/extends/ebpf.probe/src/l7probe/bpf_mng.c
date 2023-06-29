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
 * Create: 2023-03-07
 * Description: BPF prog lifecycle management
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
#include "ipc.h"
#include "include/conn_tracker.h"
#include "bpf/kern_sock.skel.h"
#include "bpf/libssl.skel.h"
#include "l7_common.h"

#define L7_CONN_DATA_PATH        "/sys/fs/bpf/gala-gopher/__l7_conn_data"
#define L7_CONN_CONTROL_PATH     "/sys/fs/bpf/gala-gopher/__l7_conn_control"
#define L7_CONN_STATS_PATH       "/sys/fs/bpf/gala-gopher/__l7_conn_stats"
#define L7_CONN_CONN_PATH        "/sys/fs/bpf/gala-gopher/__l7_conn_tbl"
#define L7_FILTER_ARGS_PATH      "/sys/fs/bpf/gala-gopher/__l7_filter_args"
#define L7_PROC_OBJ_PATH         "/sys/fs/bpf/gala-gopher/__l7_proc_obj_map"

#define __LOAD_PROBE(probe_name, end, load) \
    OPEN(probe_name, end, load); \
    MAP_SET_PIN_PATH(probe_name, conn_data_events, L7_CONN_DATA_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, conn_control_events, L7_CONN_CONTROL_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, conn_stats_events, L7_CONN_STATS_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, conn_tbl, L7_CONN_CONN_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, filter_args_tbl, L7_FILTER_ARGS_PATH, load); \
    LOAD_ATTACH(l7probe, probe_name, end, load)

static int l7_prog_create_pb(struct bpf_prog_s *prog, int fd, void* cb, void *ctx)
{
#ifdef __USE_RING_BUF
    struct ring_buffer *rb = NULL;

    rb = create_rb(fd, (ring_buffer_sample_fn)cb, ctx, NULL);
    if (rb == NULL) {
        return -1;
    }
    prog->rbs[prog->num] = rb;
    prog->num++;
    return 0;
#else
    struct perf_buffer *pb = NULL;

    pb = create_pref_buffer3(fd, (perf_buffer_sample_fn)cb, NULL, ctx);
    if (pb == NULL) {
        return -1;
    }
    prog->pbs[prog->num] = pb;
    prog->num++;
    return 0;
#endif
}

static void* get_ctrl_msg_cb(void)
{
#ifdef __USE_RING_BUF
    return (void *)trakcer_ctrl_msg_rb;
#else
    return (void *)trakcer_ctrl_msg_pb;
#endif
}

static void* get_data_msg_cb(void)
{
#ifdef __USE_RING_BUF
    return (void *)trakcer_data_msg_rb;
#else
    return (void *)trakcer_data_msg_pb;
#endif
}

static void* get_stats_msg_cb(void)
{
#ifdef __USE_RING_BUF
    return (void *)trakcer_stats_msg_rb;
#else
    return (void *)trakcer_stats_msg_pb;
#endif
}

int l7_load_probe_libssl(struct l7_mng_s *l7_mng, struct bpf_prog_s *prog, const char *libssl_path)
{
    int fd, succeed;
    int link_num = 0;

    __LOAD_PROBE(libssl, err, 1);
    prog->skels[prog->num].skel = libssl_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)libssl_bpf__destroy;

    // libssl bpf prog attach function 'SSL_read'
    UBPF_ATTACH(libssl, SSL_read, libssl_path, SSL_read, succeed);
    if (!succeed) {
        goto err;
    }
    prog->skels[prog->num]._link[link_num++] = (void *)libssl_link[libssl_link_current - 1];

    UBPF_RET_ATTACH(libssl, SSL_read, libssl_path, SSL_read, succeed);
    if (!succeed) {
        goto err;
    }
    prog->skels[prog->num]._link[link_num++] = (void *)libssl_link[libssl_link_current - 1];

    // libssl bpf prog attach function 'SSL_write'
    UBPF_ATTACH(libssl, SSL_write, libssl_path, SSL_write, succeed);
    if (!succeed) {
        goto err;
    }
    prog->skels[prog->num]._link[link_num++] = (void *)libssl_link[libssl_link_current - 1];

    UBPF_RET_ATTACH(libssl, SSL_write, libssl_path, SSL_write, succeed);
    if (!succeed) {
        goto err;
    }
    prog->skels[prog->num]._link[link_num++] = (void *)libssl_link[libssl_link_current - 1];

    // libssl bpf prog create pb for 'conn_control_events'
    fd = GET_MAP_FD(libssl, conn_control_events);
    if (l7_prog_create_pb(prog, fd, get_ctrl_msg_cb(), l7_mng)) {
        ERROR("[L7PROBE]: Create 'conn_control_events' perf buf failed.\n");
        return -1;
    }

    // libssl bpf prog create pb for 'conn_stats_events'
    fd = GET_MAP_FD(libssl, conn_stats_events);
    if (l7_prog_create_pb(prog, fd, get_stats_msg_cb(), l7_mng)) {
        ERROR("[L7PROBE]: Create 'conn_stats_events' perf buf failed.\n");
        return -1;
    }

    // libssl bpf prog create pb for 'conn_data_events'
    fd = GET_MAP_FD(libssl, conn_data_events);
    if (l7_prog_create_pb(prog, fd, get_data_msg_cb(), l7_mng)) {
        ERROR("[L7PROBE]: Create 'conn_data_events' perf buf failed.\n");
        return -1;
    }

    if (l7_mng->bpf_progs.conn_tbl_fd == 0) {
        l7_mng->bpf_progs.conn_tbl_fd = GET_MAP_FD(libssl, conn_tbl);
    }

    if (l7_mng->bpf_progs.filter_args_fd == 0) {
        l7_mng->bpf_progs.filter_args_fd = GET_MAP_FD(libssl, filter_args_tbl);
    }

    if (l7_mng->bpf_progs.proc_obj_map_fd == 0) {
        l7_mng->bpf_progs.proc_obj_map_fd = GET_MAP_FD(libssl, proc_obj_map);
    }

    INFO("[L7PROBE]: init lib_ssl bpf prog succeed.\n");
    return 0;
err:
    UNLOAD(libssl);
    return -1;
}

int l7_load_probe_kern_sock(struct l7_mng_s *l7_mng, struct bpf_prog_s *prog)
{
    int fd;

    __LOAD_PROBE(kern_sock, err, 1);
    prog->skels[prog->num].skel = kern_sock_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)kern_sock_bpf__destroy;

    // kern_sock bpf prog create pb for 'conn_control_events'
    fd = GET_MAP_FD(kern_sock, conn_control_events);
    if (l7_prog_create_pb(prog, fd, get_ctrl_msg_cb(), l7_mng)) {
        ERROR("[L7PROBE]: Create 'conn_control_events' perf buf failed.\n");
        return -1;
    }

    // kern_sock bpf prog create pb for 'conn_stats_events'
    fd = GET_MAP_FD(kern_sock, conn_stats_events);
    if (l7_prog_create_pb(prog, fd, get_stats_msg_cb(), l7_mng)) {
        ERROR("[L7PROBE]: Create 'conn_stats_events' perf buf failed.\n");
        return -1;
    }

    // kern_sock bpf prog create pb for 'conn_data_events'
    fd = GET_MAP_FD(kern_sock, conn_data_events);
    if (l7_prog_create_pb(prog, fd, get_data_msg_cb(), l7_mng)) {
        ERROR("[L7PROBE]: Create 'conn_data_events' perf buf failed.\n");
        return -1;
    }

    if (l7_mng->bpf_progs.conn_tbl_fd == 0) {
        l7_mng->bpf_progs.conn_tbl_fd = GET_MAP_FD(kern_sock, conn_tbl);
    }

    if (l7_mng->bpf_progs.filter_args_fd == 0) {
        l7_mng->bpf_progs.filter_args_fd = GET_MAP_FD(kern_sock, filter_args_tbl);
    }

    if (l7_mng->bpf_progs.proc_obj_map_fd == 0) {
        l7_mng->bpf_progs.proc_obj_map_fd = GET_MAP_FD(kern_sock, proc_obj_map);
    }

    INFO("[L7PROBE]: init kern_sock bpf prog succeed.\n");
    return 0;
err:
    UNLOAD(kern_sock);
    return -1;
}

