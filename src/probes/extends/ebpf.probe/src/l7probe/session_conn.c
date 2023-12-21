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
 * Create: 2023-07-01
 * Description: user session connection management
 ******************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "args.h"
#include "include/conn_tracker.h"
#include "session_conn.h"
#include "l7_common.h"

// Session connection to socket connection mapping.
// This is for connections that cannot obtain socket fd
struct session_hash_t {
    H_HANDLE;
    struct session_conn_id_s session_conn_id; // key
    struct conn_id_s conn_id; // value
};

static struct session_hash_t *session_head = NULL;

static void set_conn_data(enum l7_direction_t direction, struct sock_conn_s* sock_conn, struct conn_data_s *conn_data)
{
    if (conn_data == NULL) {
        return;
    }

    conn_data->msg.timestamp_ns = (u64)time(NULL);
    conn_data->msg.direction = direction;
    conn_data->msg.conn_id = sock_conn->info.id;
    conn_data->msg.proto = sock_conn->info.protocol;
    conn_data->msg.is_ssl = sock_conn->info.is_ssl;
    conn_data->msg.l7_role = sock_conn->info.l7_role;
    conn_data->msg.offset_pos = (direction == L7_EGRESS) ? sock_conn->wr_bytes : sock_conn->rd_bytes;

    return;
}

static void submit_perf_buf_user(void *ctx, const char *buf, size_t bytes_count, struct conn_data_s* conn_data)
{
    size_t copied_size;
    if (buf == NULL || bytes_count == 0) {
        return;
    }

    copied_size = (bytes_count > CONN_DATA_MAX_SIZE) ? CONN_DATA_MAX_SIZE : bytes_count;
    memcpy(conn_data->buf.data, buf, copied_size);
    conn_data->msg.data_size = (u32)copied_size;
    conn_data->msg.payload_size = (u32)copied_size;
    conn_data->msg.evt = TRACKER_EVT_DATA;
    (void)tracker_msg(ctx, conn_data, sizeof(struct conn_data_msg_s) + copied_size);
    return;
}

static void submit_conn_data_user(void *ctx, struct session_data_args_s *args,
                                    struct conn_data_s* conn_data, size_t bytes_count)
{
    int bytes_sent = 0, bytes_remaining = 0, bytes_truncated = 0;

    if (!args->buf) {
        return;
    }

    while (1) {
        bytes_remaining = (int)bytes_count - bytes_sent;
        bytes_truncated = (bytes_remaining > CONN_DATA_MAX_SIZE) ? CONN_DATA_MAX_SIZE : bytes_remaining;
        if (bytes_truncated <= 0) {
            return;
        }
        // summit perf buf
        submit_perf_buf_user(ctx, args->buf + bytes_sent, (size_t)bytes_truncated, conn_data);
        bytes_sent += bytes_truncated;

        conn_data->msg.offset_pos += (u64)bytes_truncated;
    }
}

static void submit_sock_conn_stats(void *ctx, struct sock_conn_s* sock_conn,
                                                                enum l7_direction_t direction, size_t bytes_count)
{
    if (direction == L7_EGRESS) {
        sock_conn->wr_bytes += bytes_count;
    } else if (direction == L7_INGRESS) {
        sock_conn->rd_bytes += bytes_count;
    } else {
        return;
    }

    struct conn_stats_s evt = {0};
    struct conn_stats_s *e = &evt;

    e->timestamp_ns = (u64)time(NULL);
    e->conn_id = sock_conn->info.id;
    e->wr_bytes = sock_conn->wr_bytes;
    e->rd_bytes = sock_conn->rd_bytes;

    // submit conn stats event.
    e->evt = TRACKER_EVT_STATS;
    (void)tracker_msg(ctx, e, sizeof(struct conn_stats_s));
    return;
}

// TODO: may need to check local IP and port。
static int cmp_sock_conn(struct conn_info_s *conn_info, struct session_data_args_s *args)
{
    if (conn_info->id.tgid != args->session_conn_id.tgid) {
        return -1;
    }

    char ip_s[INET6_ADDRSTRLEN];
    if (args->role == L4_SERVER) {
        if (conn_info->client_addr.port != args->port) {
            return -1;
        }
        (void)ip_str(conn_info->client_addr.family, (unsigned char *)&(conn_info->client_addr.ip),
                    (unsigned char *)ip_s, INET6_ADDRSTRLEN);
    } else if (args->role == L4_CLIENT) {
        if (conn_info->server_addr.port != args->port) {
            return -1;
        }
        (void)ip_str(conn_info->server_addr.family, (unsigned char *)&(conn_info->server_addr.ip),
                    (unsigned char *)ip_s, INET6_ADDRSTRLEN);
    } else {
        return -1;
    }

    if (strncmp(ip_s, args->ip, INET6_ADDRSTRLEN) != 0) {
        return -1;
    }

    return 0;
}

static int find_session_sock(struct l7_mng_s *l7_mng, struct session_data_args_s *args,
                            struct conn_id_s *matched_conn_id)
{
    struct conn_id_s key = {0};
    struct conn_id_s next_key = {0};
    struct sock_conn_s sock_conn = {0};
    int conn_tbl_fd = l7_mng->bpf_progs.conn_tbl_fd;

    while (bpf_map_get_next_key(conn_tbl_fd, &key, &next_key) != -1) {
        if (bpf_map_lookup_elem(conn_tbl_fd, &next_key, &sock_conn) != 0) {
            key = next_key;
            continue;
        }

        if (cmp_sock_conn(&sock_conn.info, args) == 0){
            matched_conn_id->tgid = next_key.tgid;
            matched_conn_id->fd = next_key.fd;
            return 0;
        }

        key = next_key;
    }

    return -1;
}

void clean_pid_session_hash(int tgid)
{
    struct session_hash_t *item, *tmp;
    if (session_head == NULL) {
        return;
    }

    H_ITER(session_head, item, tmp) {
        if (item->session_conn_id.tgid == tgid) {
            H_DEL(session_head, item);
        }
    }
}

static struct session_hash_t *add_session_hash(struct session_conn_id_s *session_conn_id, struct conn_id_s *conn_id)
{
    if (session_conn_id == NULL || conn_id == NULL) {
        ERROR("[L7PROBE]: add session hash failed  because session_conn_id or conn_id is null\n");
        return NULL;
    }

    struct session_hash_t *session_hash = malloc(sizeof(struct session_hash_t));
    if (session_hash == NULL) {
        ERROR("[L7PROBE]: add session hash failed because session_hash is null\n");
        return NULL;
    }

    (void)memset(session_hash, 0, sizeof(struct session_hash_t));
    memcpy(&session_hash->session_conn_id, session_conn_id, sizeof(struct session_conn_id_s));
    memcpy(&session_hash->conn_id, conn_id, sizeof(struct conn_id_s));
    H_ADD(session_head, session_conn_id, sizeof(struct session_conn_id_s), session_hash);

    return session_hash;
}

static int get_sock_conn_by_session(struct l7_mng_s *l7_mng, struct session_data_args_s *args,
                                    struct sock_conn_s *sock_conn)
{
    struct session_hash_t *session_hash = NULL;
    struct conn_id_s conn_id = {0};

    H_FIND(session_head, &args->session_conn_id, sizeof(struct session_conn_id_s), session_hash);
    if (session_hash == NULL) {
        if (find_session_sock(l7_mng, args, &conn_id) != 0) {
            goto err;
        } else {
            session_hash = add_session_hash(&args->session_conn_id, &conn_id);
        }
    }

    int conn_tbl_fd = l7_mng->bpf_progs.conn_tbl_fd;
    int ret = bpf_map_lookup_elem(conn_tbl_fd, &session_hash->conn_id, sock_conn);
    if (ret == 0) {
        return ret;
    }

err:
    if (session_hash != NULL) {
        H_DEL(session_head, session_hash);
    }
    ERROR("[L7PROBE]: Unable to match session connection and socket connection.\n");
    return -1;
}

void submit_sock_data_by_session(void *ctx, struct session_data_args_s *args)
{
    if (!args || !args->buf || args->buf[0] == 0 || args->bytes_count == 0) {
        return;
    }

    struct sock_conn_s sock_conn = {0};
    int ret = get_sock_conn_by_session((struct l7_mng_s *)ctx, args, &sock_conn);
    if (ret) {
        return;
    }
    sock_conn.info.is_ssl = 1;

    struct l7_mng_s* l7_mng = (struct l7_mng_s*)ctx;
    if (update_sock_conn_proto(&sock_conn, args->direct, args->buf, args->bytes_count,
                               l7_mng->ipc_body.probe_param.l7_probe_proto_flags)) {
        return;
    }

    struct conn_data_s *conn_data = &(((struct l7_mng_s *)ctx)->conn_data);
    set_conn_data(args->direct, &sock_conn, conn_data);

    submit_conn_data_user(ctx, args, conn_data, args->bytes_count);
    submit_sock_conn_stats(ctx, &sock_conn, args->direct, args->bytes_count);
    bpf_map_update_elem(((struct l7_mng_s *)ctx)->bpf_progs.conn_tbl_fd, &sock_conn.info, &sock_conn, BPF_ANY);

    args->buf[0] = 0;
    args->bytes_count = 0;
    return;
}


