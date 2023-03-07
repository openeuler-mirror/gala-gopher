/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: luzhihao
 * Create: 2023-02-22
 * Description: Socket trace
 ******************************************************************************/


/*
    Used to tracing syscall 'accept/accept4' event to generate 'sock_conn_s' obj.
    Syscall function prototype:
    int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
*/
struct sys_accept_args_s {
    struct sockaddr *addr;
    struct socket* newsock;
};

/*
    Used to tracing syscall 'connect' event to generate 'sock_conn_s' obj.
    Syscall function prototype:
    int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
*/
struct sys_connect_args_s {
    int fd;
    const struct sockaddr* addr;
};

/*
    Used to tracing syscall 'write/send...' args.
    Syscall function prototype:
    ssize_t write(int fd, const void *buf, size_t count);
    ssize_t send(int sockfd, const void *buf, size_t len, int flags);
    ssize_t read(int fd, void *buf, size_t count);
    ssize_t recv(int sockfd, void *buf, size_t len, int flags);

    ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
    ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
    ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
    ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
*/
struct sock_data_args_s {
    struct conn_id_s conn_id;
    enum l7_direction_t direct;
    char is_socket_op;

    // For send()/recv()/write()/read().
    const char* buf;
    
    // For sendmsg()/recvmsg()/writev()/readv().
    const struct iovec* iov;
    size_t iovlen;
};


#define __MAX_CONCURRENCY   1000
#define __MAX_CONN_COUNT    1000

struct {
    __uint(type, GOPHER_BPF_MAP_TYPE_PERF);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 64);
} conn_data_events SEC(".maps");

struct {
    __uint(type, GOPHER_BPF_MAP_TYPE_PERF);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 64);
} conn_control_events SEC(".maps");

struct {
    __uint(type, GOPHER_BPF_MAP_TYPE_PERF);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 64);
} conn_stats_events SEC(".maps");



struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct conn_id_s));
    __uint(value_size, sizeof(struct sock_conn_s));
    __uint(max_entries, __MAX_CONN_COUNT);
} conn_tbl SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(conn_ctx_t));
    __uint(value_size, sizeof(struct sys_accept_args_s));
    __uint(max_entries, __MAX_CONCURRENCY);
} sys_accept_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(conn_ctx_t));
    __uint(value_size, sizeof(struct sys_connect_args_s));
    __uint(max_entries, __MAX_CONCURRENCY);
} sys_connect_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(conn_ctx_t));
    __uint(value_size, sizeof(struct sock_data_args_s));
    __uint(max_entries, __MAX_CONCURRENCY);
} sock_data_args SEC(".maps");

// Use the BPF map to cache socket data to avoid the restriction
// that the BPF program stack does not exceed 512 bytes.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct conn_data_s));
    __uint(max_entries, 1);
} sock_data_buffer SEC(".maps");


static __inline struct sock_conn_s* __get_sock_conn(int tgid, int fd)
{
    conn_id_s id = {.tgid = tgid, fd = fd};

    return (struct sock_conn_s*)bpf_map_lookup_elem(&conn_tbl, &id);
}

static __inline void submit_conn_data(void* ctx, struct sock_data_args_s* args,
                                    struct conn_data_s* conn_data, size_t buf_size)
{
    int i;
    int bytes_sent = 0, bytes_remaining = 0, bytes_truncated = 0;

    if (args->buf) {
        #pragma unroll
        for (i = 0; i < LOOP_LIMIT; ++i) {
            bytes_remaining = buf_size - bytes_sent;
            bytes_truncated = (bytes_remaining > CONN_DATA_MAX_SIZE && (i != LOOP_LIMIT - 1)) ? CONN_DATA_MAX_SIZE : bytes_remaining;
            // TODO: summit perf buf
            bytes_sent += bytes_truncated;

            conn_data->offset_pos += bytes_truncated;
        }
    } else if (args->iov) {
        #pragma unroll
        for (i = 0; i < LOOP_LIMIT && i < args->iovlen && bytes_sent < buf_size; ++i) {
            struct iovec iov_cpy = {0};
            bpf_probe_read(&iov_cpy, sizeof(iov_cpy), &args->iov[i]);
            bytes_remaining = buf_size - bytes_sent;
            const size_t iov_len = min(iov_cpy.iov_len, bytes_remaining);

            // TODO: summit perf buf
            bytes_sent += iov_len;

            conn_data->offset_pos += iov_len;
        }
    }
}

static __inline void __get_sockaddr(struct conn_info_s* conn_info, const struct socket* socket)
{
    u16 family, port;

#if (CURRENT_LIBBPF_VERSION  >= LIBBPF_VERSION(0, 8))
    family = BPF_CORE_READ(socket, sk, __sk_common.skc_family);
    port = BPF_CORE_READ(socket, sk, __sk_common.skc_dport);

    conn_info->remote_addr.sa.sa_family = family;
    if (family == AF_INET) {
        conn_info->remote_addr.in4.sin_port = port;
        BPF_CORE_READ_INTO(conn_info->remote_addr.in4.sin_addr.s_addr,
            socket, sk, __sk_common.skc_daddr);
    } else if (family == AF_INET6) {
        conn_info->remote_addr.in6.sin6_port = port;
        BPF_CORE_READ_INTO(conn_info->remote_addr.in6.sin6_addr,
            sk, __sk_common.skc_v6_daddr);
    }
#else
    struct sock* sk = NULL;
    sk = _(socket->sk);
    family = _(sk->__sk_common.skc_family);
    port = _(sk->__sk_common.skc_dport);

    conn_info->remote_addr.sa.sa_family = family;

    if (family == AF_INET) {
        conn_info->remote_addr.in4.sin_port = port;
        conn_info->remote_addr.in4.sin_addr.s_addr = _(sk->__sk_common.skc_daddr);
    } else if (family == AF_INET6) {
      conn_info->remote_addr.in6.sin6_port = port;
      (void)bpf_probe_read(&conn_info->remote_addr.in6.sin6_addr, IP6_LEN, &sk->__sk_common.skc_v6_daddr);
    }
#endif
}

static __inline char __is_match_proc(int proc_id)
{
    struct proc_s proc = {.proc_id = proc_id};

    return is_proc_exist(&proc);
}

static __inline int __new_and_submit_sock_conn(void *ctx, int tgid, int fd, enum role_type_t role,
                                     const struct sockaddr* addr, const struct socket* socket)
{
    struct conn_id_s id = {0};
    struct sock_conn_s sock_conn = {0};

    id.fd = fd;
    id.tgid = tgid;

    sock_conn.info.id.fd = fd;
    sock_conn.info.id.tgid = tgid;
    sock_conn.info.is_ssl = 0;
    sock_conn.info.protocol = PROTO_UNKNOW;
    sock_conn.info.role = role;
    if (addr != NULL) {
        sock_conn.info.remote_addr = *((union sockaddr_t*)addr);
    } else if (socket != NULL) {
        __get_sockaddr(&sock_conn.info, socket);
    }

    // new conn obj
    (void)bpf_map_update_elem(&conn_tbl, &id, &sock_conn, BPF_ANY);

#if (CURRENT_KERNEL_VERSION  < KERNEL_VERSION(5, 10, 0))
    struct conn_ctl_s evt = {};
    struct conn_ctl_s *e = &evt;
#else
    struct conn_ctl_s *e = bpf_ringbuf_reserve(&conn_control_events, sizeof(struct conn_ctl_s), 0);
    if (!e) {
        return -1;
    }
#endif

    e->type = CONN_EVT_OPEN;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->conn_id = id;
    e->open.addr = sock_conn.info.remote_addr;
    e->open.role = sock_conn.info.role;

    // submit conn open event.
#if (CURRENT_KERNEL_VERSION  < KERNEL_VERSION(5, 10, 0))
    (void)bpf_perf_event_output(ctx, &conn_control_events, BPF_F_CURRENT_CPU, evt, sizeof(evt));
#else
    bpf_ringbuf_submit(e, 0);
#endif
    return 0;
}


static __inline int __update_sock_conn_proto(struct sock_conn_s* sock_conn, enum l7_direction_t direction,
                                                            const char* buf, size_t count)
{
    if (sock_conn->info.protocol != PROTO_UNKNOW) {
        return 0;
    }

    struct l7_proto_s l7pro = {0};
    if (get_l7_protocol(buf, count, PROTO_ALL_ENABLE, &l7pro)) {
        return -1;
    }

    if (l7pro.proto == PROTO_UNKNOW) {
        return -1;
    }
    sock_conn->info.protocol = l7pro.proto;
    // ROLE_CLIENT: message(MESSAGE_REQUEST) -> direct(L7_EGRESS)
    // ROLE_CLIENT: message(MESSAGE_RESPONSE) -> direct(L7_INGRESS)
    // ROLE_SERVER: message(MESSAGE_REQUEST) -> direct(L7_INGRESS)
    // ROLE_SERVER: message(MESSAGE_RESPONSE) -> direct(L7_EGRESS)
    sock_conn->info.role  = ((direction == L7_EGRESS) ^ (l7pro.type == MESSAGE_RESPONSE)) ? ROLE_CLIENT : ROLE_SERVER;
}


static __inline struct conn_data_s* __store_conn_data_buf(enum l7_direction_t direction, struct sock_conn_s* sock_conn)
{
    int key = 0;
    struct conn_data_s* conn_data = bpf_map_lookup_elem(&sock_data_buffer, &key);
    if (conn_data == NULL) {
        return NULL;
    }

    conn_data->timestamp_ns = bpf_ktime_get_ns();
    conn_data->direction = direction;
    conn_data->conn_id = sock_conn->info->id;
    conn_data->proto = sock_conn->info->protocol;
    conn_data->role = sock_conn->info->role;
    conn_data->offset_pos = (direction == L7_EGRESS) ? sock_conn->wr_bytes : sock_conn->rd_bytes;
    return conn_data;
}

static __inline void __submit_sock_data(void *ctx, conn_ctx_t id,
            enum l7_direction_t direction, struct sock_data_args_s* args, ssize_t bytes_count)
{
    struct sock_conn_s* sock_conn = __get_sock_conn(args->conn_id.tgid, args->conn_id.fd);
    if (sock_conn == NULL) {
        return;
    }

    if (args->buf) {
        __update_sock_conn_proto(sock_conn, direction, args->buf, (size_t)bytes_count);
    } else if (args->iov) {
        struct iovec iov_cpy;
        bpf_probe_read(&iov_cpy, sizeof(iov_cpy), &args->iov[0]);
        size_t iov_len = (size_t)min(iov_cpy.iov_len, bytes_count);
        __update_sock_conn_proto(sock_conn, direction, iov_cpy->iov_base, iov_len);
    } else {
        return;
    }

    struct conn_data_s* conn_data;
    conn_data = __store_conn_data_buf(direction, sock_conn);
    if (conn_data == NULL) {
        return;
    }

    submit_conn_data(ctx, args, conn_data, (size_t)bytes_count);

    // TODO: update sock connection tx/rx stats and submit 'conn_stats_events' event.
    return;
}


#define __KPROBE_SYSCALL(arch, func) KPROBE(arch##func, pt_regs)

#define KPROBE_SYSCALL(func) \
    #if defined(__TARGET_ARCH_x86) \
        __KPROBE_SYSCALL(__x64_sys_, func) \
    #elif defined(__TARGET_ARCH_arm64) \
        __KPROBE_SYSCALL(__arm64_sys_, func) \
    #endif

#define __KRETPROBE_SYSCALL(arch, func) KRETPROBE(arch##func, pt_regs)

#define KRETPROBE_SYSCALL(func) \
    #if defined(__TARGET_ARCH_x86) \
        __KRETPROBE_SYSCALL(__x64_sys_, func) \
    #elif defined(__TARGET_ARCH_arm64) \
        __KRETPROBE_SYSCALL(__arm64_sys_, func) \
    #endif


// int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
KPROBE_SYSCALL(connect)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);
    if (!__is_match_proc(proc_id)) {
        return 0;
    }

    int fd = (int)PT_REGS_PARM1(ctx);
    const struct sockaddr *addr = (const struct sockaddr *)PT_REGS_PARM2(ctx);

    struct sys_connect_args_s args = {};
    args.fd = fd;
    args.addr = addr;
    bpf_map_update_elem(&sys_connect_args, &id, &args, BPF_ANY);
}

KRETPROBE_SYSCALL(connect)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct sys_connect_args_s* args = bpf_map_lookup_elem(&sys_connect_args, &id);
    if (args != NULL) {
        if (args->fd < 0) {
          goto end;
        }

        int ret = (int)PT_REGS_RC(ctx);
        if (ret < 0 && ret != -EINPROGRESS) {
            // EINPROGRESS means NON_BLOCK socket is undergoing handshake.
            goto end;
        }

        __new_and_submit_sock_conn(ctx, (int)(id >> INT_LEN), args->fd,
                ROLE_CLIENT, args->addr, /*socket*/ NULL);
    }
end:
    bpf_map_delete_elem(&sys_connect_args, &id);
    return 0;
}

// ssize_t send(int sockfd, const void *buf, size_t len, int flags);
KPROBE_SYSCALL(send)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);
    if (!__is_match_proc(proc_id)) {
        return 0;
    }

    int fd = (int)PT_REGS_PARM1(ctx);

    struct sock_data_args_s args = {0};
    args.conn_id.fd = fd;
    args.conn_id.tgid = proc_id;
    args.direct = L7_EGRESS;
    args.buf = (char *)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&sock_data_args, &id, &args, BPF_ANY);
}

KRETPROBE_SYSCALL(send)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct sock_data_args_s* args = bpf_map_lookup_elem(&sock_data_args, &id);
    if (args != NULL) {
        ssize_t bytes_count = (ssize_t)PT_REGS_RC(ctx);
        if (bytes_count <= 0) {
            goto end;
        }

    }

end:
    bpf_map_delete_elem(&sock_data_args, &id)
    return 0;
}

