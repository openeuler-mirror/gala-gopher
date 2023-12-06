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

#define L7_CONN_TRACKER_PATH     "/sys/fs/bpf/gala-gopher/__l7_conn_tracker"
#define L7_CONN_CONN_PATH        "/sys/fs/bpf/gala-gopher/__l7_conn_tbl"
#define L7_TCP_PATH              "/sys/fs/bpf/gala-gopher/__l7_tcp_tbl"
#define L7_FILTER_ARGS_PATH      "/sys/fs/bpf/gala-gopher/__l7_filter_args"
#define L7_PROC_OBJ_PATH         "/sys/fs/bpf/gala-gopher/__l7_proc_obj_map"

#define __LOAD_PROBE(probe_name, end, load, buffer) \
    INIT_OPEN_OPTS(probe_name); \
    PREPARE_CUSTOM_BTF(probe_name); \
    OPEN_OPTS(probe_name, end, load); \
    MAP_INIT_BPF_BUFFER(probe_name, conn_tracker_events, buffer, load); \
    MAP_SET_PIN_PATH(probe_name, conn_tracker_events, L7_CONN_TRACKER_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, conn_tbl, L7_CONN_CONN_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, l7_tcp, L7_TCP_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, filter_args_tbl, L7_FILTER_ARGS_PATH, load); \
    LOAD_ATTACH(l7probe, probe_name, end, load)

int l7_load_probe_libssl(struct l7_mng_s *l7_mng, struct bpf_prog_s *prog, const char *libssl_path)
{
    int succeed;
    int link_num = 0;
    struct bpf_buffer *buffer = NULL;

    __LOAD_PROBE(libssl, err, 1, buffer);
    prog->skels[prog->num].skel = libssl_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)libssl_bpf__destroy;
    prog->custom_btf_paths[prog->num] = libssl_open_opts.btf_custom_path;

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

    UBPF_ATTACH(libssl, SSL_set_fd, libssl_path, SSL_set_fd, succeed);
    if (!succeed) {
        goto err;
    }
    prog->skels[prog->num]._link[link_num++] = (void *)libssl_link[libssl_link_current - 1];

    UBPF_ATTACH(libssl, SSL_set_rfd, libssl_path, SSL_set_rfd, succeed);
    if (!succeed) {
        goto err;
    }
    prog->skels[prog->num]._link[link_num++] = (void *)libssl_link[libssl_link_current - 1];
    UBPF_ATTACH(libssl, SSL_set_wfd, libssl_path, SSL_set_wfd, succeed);
    if (!succeed) {
        goto err;
    }
    prog->skels[prog->num]._link[link_num++] = (void *)libssl_link[libssl_link_current - 1];

    // libssl bpf prog create pb for 'conn_tracker_events'
    int ret = bpf_buffer__open(buffer, tracker_msg, NULL, l7_mng);
    if (ret) {
        ERROR("[L7PROBE] Lib SSL open 'conn_tracker_events' bpf_buffer failed.\n");
        goto err;
    }
    prog->buffers[prog->num] = buffer;
    prog->num++;

    if (l7_mng->bpf_progs.conn_tbl_fd == 0) {
        l7_mng->bpf_progs.conn_tbl_fd = GET_MAP_FD(libssl, conn_tbl);
    }

    if (l7_mng->bpf_progs.l7_tcp_fd == 0) {
        l7_mng->bpf_progs.l7_tcp_fd = GET_MAP_FD(libssl, l7_tcp);
    }

    if (l7_mng->bpf_progs.filter_args_fd == 0) {
        l7_mng->bpf_progs.filter_args_fd = GET_MAP_FD(libssl, filter_args_tbl);
    }

    if (l7_mng->bpf_progs.proc_obj_map_fd == 0) {
        l7_mng->bpf_progs.proc_obj_map_fd = GET_MAP_FD(libssl, proc_obj_map);
    }

    DEBUG("[L7PROBE]: init lib_ssl bpf prog succeed.\n");
    return 0;
err:
    UNLOAD(libssl);
    if (buffer) {
        bpf_buffer__free(buffer);
    }
    return -1;
}

int l7_load_probe_kern_sock(struct l7_mng_s *l7_mng, struct bpf_prog_s *prog)
{
    struct bpf_buffer *buffer = NULL;

    __LOAD_PROBE(kern_sock, err, 1, buffer);
    prog->skels[prog->num].skel = kern_sock_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)kern_sock_bpf__destroy;
    prog->custom_btf_paths[prog->num] = kern_sock_open_opts.btf_custom_path;

    // kern_sock bpf prog create pb for 'conn_tracker_events'
    int ret = bpf_buffer__open(buffer, tracker_msg, NULL, l7_mng);
    if (ret) {
        ERROR("[L7PROBE] Kern sock open 'conn_tracker_events' bpf_buffer failed.\n");
        goto err;
    }
    prog->buffers[prog->num] = buffer;
    prog->num++;

    if (l7_mng->bpf_progs.conn_tbl_fd <= 0) {
        l7_mng->bpf_progs.conn_tbl_fd = GET_MAP_FD(kern_sock, conn_tbl);
    }

    if (l7_mng->bpf_progs.l7_tcp_fd <= 0) {
        l7_mng->bpf_progs.l7_tcp_fd = GET_MAP_FD(kern_sock, l7_tcp);
    }

    if (l7_mng->bpf_progs.filter_args_fd <= 0) {
        l7_mng->bpf_progs.filter_args_fd = GET_MAP_FD(kern_sock, filter_args_tbl);
    }

    if (l7_mng->bpf_progs.proc_obj_map_fd <= 0) {
        l7_mng->bpf_progs.proc_obj_map_fd = GET_MAP_FD(kern_sock, proc_obj_map);
    }

    INFO("[L7PROBE]: init kern_sock bpf prog succeed.\n");
    return 0;
err:
    UNLOAD(kern_sock);
    if (buffer) {
        bpf_buffer__free(buffer);
    }
    return -1;
}

