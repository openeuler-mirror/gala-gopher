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

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN

#include "kern_sock.h"

char g_license[] SEC("license") = "GPL";

#define __KPROBE_SYSCALL(arch, func) KPROBE(arch##func, pt_regs)

#if defined(__TARGET_ARCH_x86)
#define KPROBE_SYSCALL(func) __KPROBE_SYSCALL(__x64_sys_, func)
#elif defined(__TARGET_ARCH_arm64)
#define KPROBE_SYSCALL(func)  __KPROBE_SYSCALL(__arm64_sys_, func)
#elif defined(__TARGET_ARCH_riscv)
#define KPROBE_SYSCALL(func)  __KPROBE_SYSCALL(__riscv_sys_, func)
#endif

#define __KRETPROBE_SYSCALL(arch, func) KRETPROBE(arch##func, pt_regs)

#if defined(__TARGET_ARCH_x86)
#define KRETPROBE_SYSCALL(func) __KRETPROBE_SYSCALL(__x64_sys_, func)
#elif defined(__TARGET_ARCH_arm64)
#define KRETPROBE_SYSCALL(func) __KRETPROBE_SYSCALL(__arm64_sys_, func)
#elif defined(__TARGET_ARCH_riscv)
#define KRETPROBE_SYSCALL(func) __KRETPROBE_SYSCALL(__riscv_sys_, func)
#endif

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/format
struct sys_enter_connect_args {
    unsigned long long __unused__;
    long __syscall_nr;
    int fd;
    struct sockaddr *uservaddr;
    int addrlen;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_connect/format
struct sys_exit_connect_args {
    unsigned long long __unused__;
    long __syscall_nr;
    long ret;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_accept/format
struct sys_enter_accept_args {
    unsigned long long __unused__;
    long __syscall_nr;
    int fd;
    struct sockaddr *upeer_sockaddr;
    int *upeer_addrlen;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_accept/format
struct sys_exit_accept_args {
    unsigned long long __unused__;
    long __syscall_nr;
    long ret;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_accept4/format
struct sys_enter_accept4_args {
    unsigned long long __unused__;
    long __syscall_nr;
    int fd;
    struct sockaddr *upeer_sockaddr;
    int *upeer_addrlen;
    int flags;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_accept4/format
struct sys_exit_accept4_args {
    unsigned long long __unused__;
    long __syscall_nr;
    long ret;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_write/format
struct sys_enter_write_args {
    unsigned long long __unused__;
    long __syscall_nr;
    unsigned int fd;
    const char *buf;
    size_t count;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_write/format
struct sys_exit_write_args {
    unsigned long long __unused__;
    long __syscall_nr;
    long ret;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_writev/format
struct sys_enter_writev_args {
    unsigned long long __unused__;
    long __syscall_nr;
    unsigned int fd;
    const struct iovec * vec;
    unsigned long vlen;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_writev/format
struct sys_exit_writev_args {
    unsigned long long __unused__;
    long __syscall_nr;
    long ret;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format
struct sys_enter_read_args {
    unsigned long long __unused__;
    long __syscall_nr;
    unsigned int fd;
    char *buf;
    size_t count;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_read/format
struct sys_exit_read_args {
    unsigned long long __unused__;
    long __syscall_nr;
    int ret;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_readv/format
struct sys_enter_readv_args {
    unsigned long long __unused__;
    long __syscall_nr;
    unsigned int fd;
    const struct iovec * vec;
    unsigned long vlen;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_readv/format
struct sys_exit_readv_args {
    unsigned long long __unused__;
    long __syscall_nr;
    int ret;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_sendto/format
struct sys_enter_sendto_args {
    unsigned long long __unused__;
    long __syscall_nr;
    int fd;
    void *buff;
    size_t len;
    unsigned int flags;
    struct sockaddr *addr;
    int addr_len;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_sendto/format
struct sys_exit_sendto_args {
    unsigned long long __unused__;
    long __syscall_nr;
    long ret;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_recvfrom/format
struct sys_enter_recvfrom_args {
    unsigned long long __unused__;
    long __syscall_nr;
    int fd;
    void *ubuf;
    size_t size;
    unsigned int flags;
    struct sockaddr *addr;
    int *addr_len;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_recvfrom/format
struct sys_exit_recvfrom_args {
    unsigned long long __unused__;
    long __syscall_nr;
    long ret;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_sendmsg/format
struct sys_enter_sendmsg_args {
    unsigned long long __unused__;
    long __syscall_nr;
    int fd;
    struct user_msghdr *msg;
    unsigned int flags;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_sendmsg/format
struct sys_exit_sendmsg_args {
    unsigned long long __unused__;
    long __syscall_nr;
    long ret;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_recvmsg/format
struct sys_enter_recvmsg_args {
    unsigned long long __unused__;
    long __syscall_nr;
    int fd;
    struct user_msghdr *msg;
    unsigned int flags;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_recvmsg/format
struct sys_exit_recvmsg_args {
    unsigned long long __unused__;
    long __syscall_nr;
    long ret;
};

static __always_inline char is_tracing_udp(void)
{
    u32 proto = get_filter_proto();
    return proto & L7PROBE_TRACING_DNS;
}

static __always_inline __maybe_unused void get_remote_addr(struct conn_info_s* conn_info, const struct sockaddr* remote_addr)
{
    const struct sockaddr_in *addr_in = (const struct sockaddr_in *)remote_addr;
    const struct sockaddr_in6 *addr_in6 = (const struct sockaddr_in6 *)remote_addr;

    conn_info->remote_addr.family = _(remote_addr->sa_family);
    if (conn_info->remote_addr.family == AF_INET) {
        conn_info->remote_addr.ip = _(addr_in->sin_addr.s_addr);
        conn_info->remote_addr.port = bpf_ntohs(_(addr_in->sin_port));
    } else {
        BPF_CORE_READ_INTO(&(conn_info->remote_addr.ip6), addr_in6, sin6_addr);
        conn_info->remote_addr.port = bpf_ntohs(_(addr_in6->sin6_port));
    }

    return;
}

static __always_inline __maybe_unused void get_remote_sockaddr(struct conn_info_s* conn_info, const struct socket* socket)
{
    u16 family, remote_port;

    family = BPF_CORE_READ(socket, sk, __sk_common.skc_family);

    conn_info->remote_addr.family = family;

    if (family == AF_INET) {
        conn_info->remote_addr.ip = BPF_CORE_READ(socket, sk, __sk_common.skc_daddr);
    } else {
        BPF_CORE_READ_INTO(&(conn_info->remote_addr.ip6), socket, sk, __sk_common.skc_v6_daddr);
    }
    remote_port = BPF_CORE_READ(socket, sk, __sk_common.skc_dport);
    remote_port = bpf_ntohs(remote_port);
    conn_info->remote_addr.port = remote_port;
    return;
}

static __always_inline __maybe_unused void get_sockaddr(struct conn_info_s* conn_info, enum l4_role_t l4_role, const struct socket* socket)
{
    u16 family, server_port, client_port;

    family = BPF_CORE_READ(socket, sk, __sk_common.skc_family);

    conn_info->client_addr.family = family;
    conn_info->server_addr.family = family;

    if (l4_role == L4_CLIENT) {
        server_port = BPF_CORE_READ(socket, sk, __sk_common.skc_dport);
        server_port = bpf_ntohs(server_port);
        client_port = BPF_CORE_READ(socket, sk, __sk_common.skc_num);
    } else {
        server_port = BPF_CORE_READ(socket, sk, __sk_common.skc_num);
        client_port = BPF_CORE_READ(socket, sk, __sk_common.skc_dport);
        client_port = bpf_ntohs(client_port);
    }

    conn_info->server_addr.port = server_port;
    conn_info->client_addr.port = client_port;

    if (l4_role == L4_CLIENT) {
        if (family == AF_INET) {
            conn_info->client_addr.ip = BPF_CORE_READ(socket, sk, __sk_common.skc_rcv_saddr);
            conn_info->server_addr.ip = BPF_CORE_READ(socket, sk, __sk_common.skc_daddr);
        } else {
            BPF_CORE_READ_INTO(&(conn_info->client_addr.ip6), socket, sk, __sk_common.skc_v6_rcv_saddr);
            BPF_CORE_READ_INTO(&(conn_info->server_addr.ip6), socket, sk, __sk_common.skc_v6_daddr);
        }
    } else {
        if (family == AF_INET) {
            conn_info->client_addr.ip = BPF_CORE_READ(socket, sk, __sk_common.skc_daddr);
            conn_info->server_addr.ip = BPF_CORE_READ(socket, sk, __sk_common.skc_rcv_saddr);
        } else {
            BPF_CORE_READ_INTO(&(conn_info->client_addr.ip6), socket, sk, __sk_common.skc_v6_daddr);
            BPF_CORE_READ_INTO(&(conn_info->server_addr.ip6), socket, sk, __sk_common.skc_v6_rcv_saddr);
        }
    }
    return;
}

static __always_inline __maybe_unused struct sock_conn_s* new_sock_conn(void *ctx, int tgid, int fd, enum l4_role_t l4_role,
                                     const struct sockaddr* remote_addr, const struct socket* socket)
{
    struct conn_id_s id = {0};
    struct sock_conn_s sock_conn = {0};

    id.fd = fd;
    id.tgid = tgid;

    sock_conn.info.id.fd = fd;
    sock_conn.info.id.tgid = tgid;
    sock_conn.info.is_reported = 0;
    sock_conn.info.is_ssl = 0;
    sock_conn.info.protocol = PROTO_UNKNOW;
    sock_conn.info.l4_role = l4_role;

    if ((remote_addr != NULL) && (l4_role == L4_UNKNOW)) {
        get_remote_addr(&sock_conn.info, remote_addr);
    }

    if ((socket != NULL) && (l4_role == L4_UNKNOW)) {
        get_remote_sockaddr(&sock_conn.info, socket);
    }

    if (l4_role != L4_UNKNOW) {
        struct socket* new_socket = (struct socket *)socket;
        if (new_socket == NULL) {
            struct sock *sk = sock_get_by_fd(fd, (struct task_struct *)bpf_get_current_task());
            if (!sk) {
                return NULL;
            }
           new_socket = BPF_CORE_READ(sk, sk_socket);
            if (new_socket == NULL) {
                return NULL;
            }
        }

        get_sockaddr(&sock_conn.info, l4_role, (const struct socket *)new_socket);
    }

    // new conn obj
    bpf_map_update_elem(&conn_tbl, &id, &sock_conn, BPF_ANY);
    return lkup_sock_conn(tgid, fd);
}

static __always_inline __maybe_unused struct sock_conn_s* get_sock_conn(void *ctx, int tgid, int fd)
{
    int value;
    u16 sk_type;
    enum l4_role_t l4_role;
    struct sock_conn_s* sock_conn = NULL;

    struct sock *sk = sock_get_by_fd(fd, (struct task_struct *)bpf_get_current_task());
    if (!sk) {
        return NULL;
    }

    sk_type = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_type);
    if (sk_type != SOCK_STREAM) {
        l4_role = L4_UNKNOW;
    } else {
        value = lkup_l7_tcp(tgid, fd);
        if (value < 0) {
            return NULL;
        }
        l4_role = (value == 0) ? L4_CLIENT : L4_SERVER;
    }

    struct socket* socket = BPF_CORE_READ(sk, sk_socket);
    if (socket == NULL) {
        return NULL;
    }

    // new sock connection
    sock_conn = new_sock_conn(ctx, tgid, fd, l4_role, NULL, (const struct socket*)socket);
    return sock_conn;
}

static __always_inline __maybe_unused struct sock_conn_s* get_sock_conn_by_addr(void *ctx, int tgid, int fd, const struct sockaddr* addr)
{
    // new UDP sock connection
    return new_sock_conn(ctx, tgid, fd, L4_UNKNOW, addr, NULL);
}

static __always_inline __maybe_unused int submit_conn_open(void *ctx, struct sock_conn_s* sock_conn)
{
    if (sock_conn == NULL) {
        return -1;
    }

    if (sock_conn->info.is_reported != 0) {
        return 0;   // avoid report redundant events
    }

    struct conn_ctl_s* e = bpfbuf_reserve(&conn_tracker_events, sizeof(struct conn_ctl_s));
    if (!e) {
        return -1;
    }

    e->evt = TRACKER_EVT_CTRL;
    e->type = CONN_EVT_OPEN;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->conn_id = sock_conn->info.id;
    e->open.l4_role = sock_conn->info.l4_role;
    e->open.is_ssl = sock_conn->info.is_ssl;

    __builtin_memcpy(&(e->open.client_addr), &(sock_conn->info.client_addr), sizeof(struct conn_addr_s));
    if (e->open.l4_role == L4_UNKNOW) {
        __builtin_memcpy(&(e->open.server_addr), &(sock_conn->info.remote_addr), sizeof(struct conn_addr_s));
    } else {
        __builtin_memcpy(&(e->open.server_addr), &(sock_conn->info.server_addr), sizeof(struct conn_addr_s));
    }

    bpfbuf_submit(ctx, &conn_tracker_events, e, sizeof(struct conn_ctl_s));
    sock_conn->info.is_reported = 1;
    return 0;
}


static __always_inline __maybe_unused int submit_conn_close(void *ctx, conn_ctx_t id, int fd)
{
    int tgid = (int)(id >> INT_LEN);
    struct sock_conn_s* sock_conn = lkup_sock_conn(tgid, fd);
    if (sock_conn == NULL) {
        return 0;
    }

    struct conn_ctl_s* e = bpfbuf_reserve(&conn_tracker_events, sizeof(struct conn_ctl_s));
    if (!e) {
        goto end;
    }

    e->evt = TRACKER_EVT_CTRL;
    e->type = CONN_EVT_CLOSE;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->conn_id = sock_conn->info.id;
    e->close.rd_bytes = sock_conn->rd_bytes;
    e->close.wr_bytes = sock_conn->wr_bytes;

    // submit conn open event.
    bpfbuf_submit(ctx, &conn_tracker_events, e, sizeof(struct conn_ctl_s));

end:
    /* We should do "bpf_map_delete_elem(&conn_tbl, &conn_id)" here,
       but due to the lag in processing jsse messages, if the connection is deleted now,
       the connection will not be found in the cmp_sock_conn(). */

    sock_conn->info.is_reported = 0;
    return 0;
}

static __always_inline char is_tracing(int tgid)
{
    return is_filter_id(FILTER_TGID, tgid);
}


// int security_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
KPROBE(security_socket_sendmsg, pt_regs)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct sock_data_args_s* args = bpf_map_lookup_elem(&sock_data_args, &id);
    if (args) {
        args->is_socket_op = 1;
    }
    return 0;
}

// int security_socket_recvmsg(struct socket *sock, struct msghdr *msg, int size)
KPROBE(security_socket_recvmsg, pt_regs)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct sock_data_args_s* args = bpf_map_lookup_elem(&sock_data_args, &id);
    if (args) {
        args->is_socket_op = 1;
    }
    return 0;
}

KPROBE(sock_alloc_file, pt_regs)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct sys_accept_args_s* args = bpf_map_lookup_elem(&sys_accept_args, &id);
    if (args == NULL) {
        return 0;
    }

    if (args->newsock == NULL) {
        args->newsock = (struct socket *)PT_REGS_PARM1(ctx);
    }
    return 0;
}

// int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
bpf_section("tracepoint/syscalls/sys_enter_connect")
int function_sys_enter_connect(struct sys_enter_connect_args *ctx)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);

    if (!is_tracing(proc_id)) {
        return 0;
    }

    int fd = ctx->fd;
    const struct sockaddr *addr = ctx->uservaddr;

    struct sys_connect_args_s args = {0};
    args.fd = fd;
    args.addr = addr;
    bpf_map_update_elem(&sys_connect_args, &id, &args, BPF_ANY);
    return 0;
}

#define EINPROGRESS 115 // TODO: Varies in different arch
bpf_section("tracepoint/syscalls/sys_exit_connect")
int function_sys_exit_connect(struct sys_exit_connect_args *ctx)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct sys_connect_args_s* args = bpf_map_lookup_elem(&sys_connect_args, &id);
    if (args != NULL) {
        if (args->fd < 0) {
          goto end;
        }

        int ret = (int)(ctx->ret);
        if (ret < 0 && ret != -EINPROGRESS) {
            // EINPROGRESS means NON_BLOCK socket is undergoing handshake.
            goto end;
        }

        struct sock_conn_s* sock_conn = lkup_sock_conn((int)(id >> INT_LEN), args->fd);
        // new sock connection
        if (sock_conn) {
            struct conn_id_s conn_id = {.fd = args->fd, .tgid = (int)(id >> INT_LEN)};
            bpf_map_delete_elem(&conn_tbl, &conn_id);
        }
        sock_conn = new_sock_conn(ctx, (int)(id >> INT_LEN), args->fd, L4_CLIENT, args->addr, NULL);

        submit_conn_open(ctx, sock_conn);
    }
end:
    bpf_map_delete_elem(&sys_connect_args, &id);
    return 0;
}

// ssize_t send(int sockfd, const void *buf, size_t len, int flags);
KPROBE_SYSCALL(send)
{
    struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);

    if (!is_tracing(proc_id)) {
        return 0;
    }

    int fd = (int)PT_REGS_PARM1_CORE(regs);

    struct sock_data_args_s args = {0};
    args.conn_id.fd = fd;
    args.conn_id.tgid = proc_id;
    args.direct = L7_EGRESS;
    args.buf = (char *)PT_REGS_PARM2_CORE(regs);
    args.is_ssl = 0;
    bpf_map_update_elem(&sock_data_args, &id, &args, BPF_ANY);
    return 0;
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

        struct sock_conn_s* sock_conn = lkup_sock_conn(args->conn_id.tgid, args->conn_id.fd);
        // new sock connection
        if (!sock_conn) {
            sock_conn = get_sock_conn(ctx, args->conn_id.tgid, args->conn_id.fd);
            if (sock_conn == NULL) {
                goto end;
            }
            (void)submit_conn_open(ctx, sock_conn);
        }

        submit_sock_data(ctx, sock_conn, id, L7_EGRESS, args, (size_t)bytes_count);
    }

end:
    bpf_map_delete_elem(&sock_data_args, &id);
    return 0;
}

// int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
bpf_section("tracepoint/syscalls/sys_enter_accept")
int function_sys_enter_accept(struct sys_enter_accept_args *ctx)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();

    if (!is_tracing((int)(id >> INT_LEN))) {
        return 0;
    }

    struct sockaddr *addr = ctx->upeer_sockaddr;

    struct sys_accept_args_s args = {0};
    args.addr = addr;
    bpf_map_update_elem(&sys_accept_args, &id, &args, BPF_ANY);
    return 0;
}

bpf_section("tracepoint/syscalls/sys_exit_accept")
int function_sys_exit_accept(struct sys_exit_accept_args *ctx)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct sys_accept_args_s* args = bpf_map_lookup_elem(&sys_accept_args, &id);
    if (args != NULL) {
        if (args->addr == NULL) {
          goto end;
        }

        int new_fd = (int)(ctx->ret);
        if (new_fd < 0) {
            goto end;
        }
        struct sock_conn_s* sock_conn = lkup_sock_conn((int)(id >> INT_LEN), new_fd);
        // new sock connection
        if (sock_conn) {
            struct conn_id_s conn_id = {.fd = new_fd, .tgid = (int)(id >> INT_LEN)};
            bpf_map_delete_elem(&conn_tbl, &conn_id);
        }

        sock_conn = new_sock_conn(ctx, (int)(id >> INT_LEN), new_fd, L4_SERVER, args->addr, NULL);

        submit_conn_open(ctx, sock_conn);
    }
end:
    bpf_map_delete_elem(&sys_accept_args, &id);
    return 0;
}

// int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
bpf_section("tracepoint/syscalls/sys_enter_accept4")
int function_sys_enter_accept4(struct sys_enter_accept4_args *ctx)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();

    if (!is_tracing((int)(id >> INT_LEN))) {
        return 0;
    }

    struct sockaddr *addr = ctx->upeer_sockaddr;

    struct sys_accept_args_s args = {0};
    args.addr = addr;
    bpf_map_update_elem(&sys_accept_args, &id, &args, BPF_ANY);
    return 0;
}

bpf_section("tracepoint/syscalls/sys_exit_accept4")
int function_sys_exit_accept4(struct sys_exit_accept4_args *ctx)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct sys_accept_args_s* args = bpf_map_lookup_elem(&sys_accept_args, &id);
    if (args != NULL) {
        if (args->addr == NULL) {
          goto end;
        }

        int new_fd = (int)(ctx->ret);
        if (new_fd < 0) {
            goto end;
        }

        struct sock_conn_s* sock_conn = lkup_sock_conn((int)(id >> INT_LEN), new_fd);
        // new sock connection
        if (sock_conn) {
            struct conn_id_s conn_id = {.fd = new_fd, .tgid = (int)(id >> INT_LEN)};
            bpf_map_delete_elem(&conn_tbl, &conn_id);
        }
        sock_conn = new_sock_conn(ctx, (int)(id >> INT_LEN), new_fd, L4_SERVER, args->addr, args->newsock);

        submit_conn_open(ctx, sock_conn);
    }
end:
    bpf_map_delete_elem(&sys_accept_args, &id);
    return 0;
}

// ssize_t write(int fd, const void *buf, size_t count);
bpf_section("tracepoint/syscalls/sys_enter_write")
int function_sys_enter_write(struct sys_enter_write_args *ctx)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);
    int fd = (int)ctx->fd;

    if (!is_tracing(proc_id)) {
        return 0;
    }

    struct sock_data_args_s args = {0};
    args.conn_id.fd = fd;
    args.conn_id.tgid = proc_id;
    args.direct = L7_EGRESS;
    args.buf = ctx->buf;
    args.is_ssl = 0;
    bpf_map_update_elem(&sock_data_args, &id, &args, BPF_ANY);
    return 0;
}

bpf_section("tracepoint/syscalls/sys_exit_write")
int function_sys_exit_write(struct sys_exit_write_args *ctx)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct sock_data_args_s* args = bpf_map_lookup_elem(&sock_data_args, &id);
    if (args != NULL && args->is_socket_op) {
        ssize_t bytes_count = (ssize_t)(ctx->ret);
        if (bytes_count <= 0) {
            goto end;
        }

        struct sock_conn_s* sock_conn = lkup_sock_conn(args->conn_id.tgid, args->conn_id.fd);
        // new sock connection
        if (!sock_conn) {
            sock_conn = get_sock_conn(ctx, args->conn_id.tgid, args->conn_id.fd);
            if (sock_conn == NULL) {
                goto end;
            }
            (void)submit_conn_open(ctx, sock_conn);
        }

        submit_sock_data(ctx, sock_conn, id, L7_EGRESS, args, (size_t)bytes_count);
    }

end:
    bpf_map_delete_elem(&sock_data_args, &id);
    return 0;
}

bpf_section("tracepoint/syscalls/sys_enter_writev")
int function_sys_enter_writev(struct sys_enter_writev_args *ctx)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);

    if (!is_tracing(proc_id)) {
        return 0;
    }

    int fd = (int)ctx->fd;
    struct iovec *iov = (struct iovec *)ctx->vec;
    u32 iovlen = (u32)ctx->vlen;

    struct sock_data_args_s args = {0};
    args.conn_id.tgid = proc_id;
    args.conn_id.fd = fd;
    args.direct = L7_EGRESS;
    args.iov = iov;
    args.iovlen = iovlen;
    args.is_ssl = 0;

    bpf_map_update_elem(&sock_data_args, &id, &args, BPF_ANY);
    return 0;
}

bpf_section("tracepoint/syscalls/sys_exit_writev")
int function_sys_exit_writev(struct sys_exit_writev_args *ctx)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct sock_data_args_s *args = bpf_map_lookup_elem(&sock_data_args, &id);
    if (args != NULL && args->is_socket_op) {
        ssize_t bytes_count = (ssize_t)(ctx->ret);
        if (bytes_count <= 0) {
            goto end;
        }
        struct sock_conn_s *sock_conn = lkup_sock_conn(args->conn_id.tgid, args->conn_id.fd);
        // new sock connection
        if (!sock_conn) {
            sock_conn = get_sock_conn(ctx, args->conn_id.tgid, args->conn_id.fd);
            if (sock_conn == NULL) {
                goto end;
            }
            (void)submit_conn_open(ctx, sock_conn);
        }
        submit_sock_data(ctx, sock_conn, id, L7_EGRESS, args, (ssize_t)bytes_count);
    }
end:
    bpf_map_delete_elem(&sock_data_args, &id);
    return 0;
}

bpf_section("tracepoint/syscalls/sys_enter_read")
int function_sys_enter_read(struct sys_enter_read_args *ctx)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);
    int fd = ctx->fd;

    if (!is_tracing(proc_id)) {
        return 0;
    }

    struct sock_data_args_s args = {0};
    args.conn_id.fd = fd;
    args.conn_id.tgid = proc_id;
    args.direct = L7_INGRESS;
    args.buf = ctx->buf;
    args.is_ssl = 0;
    bpf_map_update_elem(&sock_data_args, &id, &args, BPF_ANY);
    return 0;
}

bpf_section("tracepoint/syscalls/sys_exit_read")
int function_sys_exit_read(struct sys_exit_read_args *ctx)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct sock_data_args_s* args = bpf_map_lookup_elem(&sock_data_args, &id);
    if (args != NULL && args->is_socket_op) {
        ssize_t bytes_count = (ssize_t)(ctx->ret);
        if (bytes_count <= 0) {
            goto end;
        }
        struct sock_conn_s* sock_conn = lkup_sock_conn(args->conn_id.tgid, args->conn_id.fd);
        // new sock connection
        if (!sock_conn) {
            sock_conn = get_sock_conn(ctx, args->conn_id.tgid, args->conn_id.fd);
            if (sock_conn == NULL) {
                goto end;
            }
            (void)submit_conn_open(ctx, sock_conn);
        }

        submit_sock_data(ctx, sock_conn, id, L7_INGRESS, args, (size_t)bytes_count);
    }

end:
    bpf_map_delete_elem(&sock_data_args, &id);
    return 0;

}

bpf_section("tracepoint/syscalls/sys_enter_readv")
int function_sys_enter_readv(struct sys_enter_readv_args *ctx)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);

    if (!is_tracing(proc_id)) {
        return 0;
    }

    int fd = (int)ctx->fd;
    struct iovec *iov = (struct iovec *)ctx->vec;
    u32 iovlen = (u32)ctx->vlen;

    struct sock_data_args_s args = {0};
    args.conn_id.tgid = proc_id;
    args.conn_id.fd = fd;
    args.direct = L7_INGRESS;
    args.iov = iov;
    args.iovlen = iovlen;
    args.is_ssl = 0;

    bpf_map_update_elem(&sock_data_args, &id, &args, BPF_ANY);
    return 0;
}

bpf_section("tracepoint/syscalls/sys_exit_readv")
int function_sys_exit_readv(struct sys_exit_readv_args *ctx)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct sock_data_args_s *args = bpf_map_lookup_elem(&sock_data_args, &id);
    if (args != NULL && args->is_socket_op) {
        ssize_t bytes_count = (ssize_t)(ctx->ret);
        if (bytes_count <= 0) {
            goto end;
        }
        struct sock_conn_s *sock_conn = lkup_sock_conn(args->conn_id.tgid, args->conn_id.fd);
        // new sock connection
        if (!sock_conn) {
            sock_conn = get_sock_conn(ctx, args->conn_id.tgid, args->conn_id.fd);
            if (sock_conn == NULL) {
                goto end;
            }
            (void)submit_conn_open(ctx, sock_conn);
        }
        submit_sock_data(ctx, sock_conn, id, L7_INGRESS, args, (size_t)bytes_count);
    }
end:
    bpf_map_delete_elem(&sock_data_args, &id);
    return 0;
}

// ssize_t recv(int sockfd, void *buf, size_t len, int flags);
KPROBE_SYSCALL(recv)
{
    struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);
    int fd = (int)PT_REGS_PARM1_CORE(regs);

    if (!is_tracing(proc_id)) {
        return 0;
    }

    struct sock_data_args_s args = {0};
    args.conn_id.fd = fd;
    args.conn_id.tgid = proc_id;
    args.direct = L7_INGRESS;
    args.buf = (char *)PT_REGS_PARM2_CORE(regs);
    args.is_ssl = 0;
    bpf_map_update_elem(&sock_data_args, &id, &args, BPF_ANY);
    return 0;
}

KRETPROBE_SYSCALL(recv)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct sock_data_args_s* args = bpf_map_lookup_elem(&sock_data_args, &id);
    if (args != NULL) {
        ssize_t bytes_count = (ssize_t)PT_REGS_RC(ctx);
        if (bytes_count <= 0) {
            goto end;
        }
        struct sock_conn_s* sock_conn = lkup_sock_conn(args->conn_id.tgid, args->conn_id.fd);
        // new sock connection
        if (!sock_conn) {
            sock_conn = get_sock_conn(ctx, args->conn_id.tgid, args->conn_id.fd);
            if (sock_conn == NULL) {
                goto end;
            }
            (void)submit_conn_open(ctx, sock_conn);
        }
        submit_sock_data(ctx, sock_conn, id, L7_INGRESS, args, (size_t)bytes_count);
    }

end:
    bpf_map_delete_elem(&sock_data_args, &id);
    return 0;
}

// ssize_t sendto(int sockfd, const void *buf, size_t len,
//      int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
bpf_section("tracepoint/syscalls/sys_enter_sendto")
int function_sys_enter_sendto(struct sys_enter_sendto_args *ctx)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);

    if (!is_tracing(proc_id)) {
        return 0;
    }

    int sockfd = ctx->fd;
    char *buf = (char *)ctx->buff;
    if (buf == NULL || sockfd < 0) {
        return -1;
    }

    // Filter by UDP tracing-on/off
    if (is_tracing_udp()) {
        struct sockaddr * dest_addr = ctx->addr;
        if (dest_addr && sockfd > 0) {
            struct sys_connect_args_s args = {0};
            args.fd = sockfd;
            args.addr = dest_addr;
            bpf_map_update_elem(&sys_connect_args, &id, &args, BPF_ANY);
        }
    }

    struct sock_data_args_s data_args = {0};
    data_args.buf = buf;
    data_args.conn_id.fd = sockfd;
    data_args.conn_id.tgid = proc_id;
    data_args.is_ssl = 0;
    bpf_map_update_elem(&sock_data_args, &id, &data_args, BPF_ANY);
    return 0;
}

bpf_section("tracepoint/syscalls/sys_exit_sendto")
int function_sys_exit_sendto(struct sys_exit_sendto_args *ctx)
{
    int is_udp = 0;
    conn_ctx_t id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = (ssize_t)(ctx->ret);
    struct sock_conn_s* sock_conn = NULL;

    // Filter by UDP tracing-on/off
    if (is_tracing_udp()) {
        struct sys_connect_args_s* args = bpf_map_lookup_elem(&sys_connect_args, &id);
        if ((args != NULL) && (bytes_count > 0)) {
            sock_conn = lkup_sock_conn((int)(id >> INT_LEN), args->fd);
            // new sock connection
            if (!sock_conn) {
                sock_conn = get_sock_conn_by_addr(ctx, (int)(id >> INT_LEN), args->fd, args->addr);
            }
            if (sock_conn == NULL) {
                goto end;
            }
            is_udp = 1;
            (void)submit_conn_open(ctx, sock_conn); // UDP socket open event;
        }
    }

    // Unstash arguments, and process syscall.
    struct sock_data_args_s* data_args = bpf_map_lookup_elem(&sock_data_args, &id);
    if ((data_args != NULL) && (bytes_count > 0)) {
        if (!is_udp) {
            sock_conn = lkup_sock_conn((int)(id >> INT_LEN), data_args->conn_id.fd);
            if (!sock_conn) {
                sock_conn = get_sock_conn(ctx, (int)(id >> INT_LEN), data_args->conn_id.fd);
            }
            if (sock_conn == NULL) {
                goto end;
            }
            (void)submit_conn_open(ctx, sock_conn); // TCP socket open event;
        }
        submit_sock_data(ctx, sock_conn, id, L7_EGRESS, data_args, (size_t)bytes_count);
    }
end:
    bpf_map_delete_elem(&sys_connect_args, &id);
    bpf_map_delete_elem(&sock_data_args, &id);
    return 0;
}


// ssize_t recvfrom(int sockfd, void *buf, size_t len,
//      int flags, struct sockaddr *src_addr, socklen_t *addrlen);
bpf_section("tracepoint/syscalls/sys_enter_recvfrom")
int function_sys_enter_recvfrom(struct sys_enter_recvfrom_args *ctx)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);

    if (!is_tracing(proc_id)) {
        return 0;
    }

    int sockfd = ctx->fd;
    char *buf = (char *)ctx->ubuf;
    if (buf == NULL || sockfd < 0) {
        return -1;
    }

    // Filter by UDP tracing-on/off
    if (is_tracing_udp()) {
        struct sockaddr * src_addr = ctx->addr;
        if (src_addr) {
            struct sys_connect_args_s args = {0};
            args.fd = sockfd;
            args.addr = src_addr;
            bpf_map_update_elem(&sys_connect_args, &id, &args, BPF_ANY);
        }
    }

    struct sock_data_args_s data_args = {0};
    data_args.buf = buf;
    data_args.conn_id.fd = sockfd;
    data_args.conn_id.tgid = proc_id;
    data_args.is_ssl = 0;
    bpf_map_update_elem(&sock_data_args, &id, &data_args, BPF_ANY);
    return 0;
}

bpf_section("tracepoint/syscalls/sys_exit_recvfrom")
int function_sys_exit_recvfrom(struct sys_exit_recvfrom_args *ctx)
{
    int is_udp = 0;
    conn_ctx_t id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = (ssize_t)(ctx->ret);
    struct sock_conn_s* sock_conn = NULL;

    // Filter by UDP tracing-on/off
    if (is_tracing_udp()) {
        struct sys_connect_args_s* args = bpf_map_lookup_elem(&sys_connect_args, &id);
        if ((args != NULL) && (bytes_count > 0)) {
            sock_conn = lkup_sock_conn((int)(id >> INT_LEN), args->fd);
            // new sock connection
            if (!sock_conn) {
                sock_conn = get_sock_conn_by_addr(ctx, (int)(id >> INT_LEN), args->fd, args->addr);
            }
            if (sock_conn == NULL) {
                goto end;
            }
            is_udp = 1;
            (void)submit_conn_open(ctx, sock_conn); // UDP socket open event;
        }
    }

    // Unstash arguments, and process syscall.
    struct sock_data_args_s* data_args = bpf_map_lookup_elem(&sock_data_args, &id);
    if ((data_args != NULL) && (bytes_count > 0)) {
        if (!is_udp) {
            sock_conn = lkup_sock_conn((int)(id >> INT_LEN), data_args->conn_id.fd);
            if (!sock_conn) {
                sock_conn = get_sock_conn(ctx, (int)(id >> INT_LEN), data_args->conn_id.fd);
            }
            if (sock_conn == NULL) {
                goto end;
            }
            (void)submit_conn_open(ctx, sock_conn); // TCP socket open event;
        }

        submit_sock_data(ctx, sock_conn, id, L7_INGRESS, data_args, (size_t)bytes_count);
    }

end:
    bpf_map_delete_elem(&sys_connect_args, &id);
    bpf_map_delete_elem(&sock_data_args, &id);
    return 0;
}

// ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
bpf_section("tracepoint/syscalls/sys_enter_sendmsg")
int function_sys_enter_sendmsg(struct sys_enter_sendmsg_args *ctx)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);

    if (!is_tracing(proc_id)) {
        return 0;
    }

    int fd = ctx->fd;
    struct user_msghdr *msg = ctx->msg;
    void * msg_name = BPF_CORE_READ_USER(msg, msg_name);
    struct iovec* iov = BPF_CORE_READ_USER(msg, msg_iov);
    size_t iovlen = BPF_CORE_READ_USER(msg, msg_iovlen);

    // Filter by UDP tracing-on/off
    if (is_tracing_udp()) {
        if (msg_name) {
            struct sys_connect_args_s args = {0};
            args.fd = fd;
            args.addr = msg_name;
            bpf_map_update_elem(&sys_connect_args, &id, &args, BPF_ANY);
        }
    }

    struct sock_data_args_s data_args = {0};
    data_args.conn_id.fd = fd;
    data_args.conn_id.tgid = proc_id;
    data_args.direct = L7_EGRESS;
    data_args.iov = iov;
    data_args.iovlen = iovlen;
    data_args.is_ssl = 0;
    bpf_map_update_elem(&sock_data_args, &id, &data_args, BPF_ANY);
    return 0;
}

bpf_section("tracepoint/syscalls/sys_exit_sendmsg")
int function_sys_exit_sendmsg(struct sys_exit_sendmsg_args *ctx)
{
    int is_udp = 0;
    conn_ctx_t id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = (ssize_t)(ctx->ret);
    struct sock_conn_s* sock_conn = NULL;

    // Filter by UDP tracing-on/off
    if (is_tracing_udp()) {
        struct sys_connect_args_s* args = bpf_map_lookup_elem(&sys_connect_args, &id);
        if (args && bytes_count > 0) {
            sock_conn = lkup_sock_conn((int)(id >> INT_LEN), args->fd);
            // new sock connection
            if (!sock_conn) {
                sock_conn = get_sock_conn_by_addr(ctx, (int)(id >> INT_LEN), args->fd, args->addr);
            }
            if (sock_conn == NULL) {
                goto end;
            }
            is_udp = 1;
            (void)submit_conn_open(ctx, sock_conn); // UDP socket open event;
        }
    }

    struct sock_data_args_s* data_args = bpf_map_lookup_elem(&sock_data_args, &id);
    if ((data_args != NULL) && (bytes_count > 0)) {
        if (!is_udp) {
            sock_conn = lkup_sock_conn((int)(id >> INT_LEN), data_args->conn_id.fd);
            if (!sock_conn) {
                sock_conn = get_sock_conn(ctx, (int)(id >> INT_LEN), data_args->conn_id.fd);
            }
            if (sock_conn == NULL) {
                goto end;
            }
            (void)submit_conn_open(ctx, sock_conn); // TCP socket open event;
        }
        submit_sock_data(ctx, sock_conn, id, L7_EGRESS, data_args, (size_t)bytes_count);
    }

end:
    bpf_map_delete_elem(&sys_connect_args, &id);
    bpf_map_delete_elem(&sock_data_args, &id);
    return 0;
}

// ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
bpf_section("tracepoint/syscalls/sys_enter_recvmsg")
int function_sys_enter_recvmsg(struct sys_enter_recvmsg_args *ctx)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);
    if (!is_tracing(proc_id)) {
        return 0;
    }

    int fd = ctx->fd;
    struct user_msghdr *msg = ctx->msg;
    void * msg_name = BPF_CORE_READ_USER(msg, msg_name);
    struct iovec* iov = BPF_CORE_READ_USER(msg, msg_iov);
    size_t iovlen = BPF_CORE_READ_USER(msg, msg_iovlen);

    // Filter by UDP tracing-on/off
    if (is_tracing_udp()) {
        if (msg_name) {
            struct sys_connect_args_s args = {0};
            args.fd = fd;
            args.addr = msg_name;
            bpf_map_update_elem(&sys_connect_args, &id, &args, BPF_ANY);
        }
    }

    struct sock_data_args_s data_args = {0};
    data_args.conn_id.fd = fd;
    data_args.conn_id.tgid = proc_id;
    data_args.direct = L7_INGRESS;
    data_args.iov = iov;
    data_args.iovlen = iovlen;
    data_args.is_ssl = 0;
    bpf_map_update_elem(&sock_data_args, &id, &data_args, BPF_ANY);
    return 0;
}

bpf_section("tracepoint/syscalls/sys_exit_recvmsg")
int function_sys_exit_recvmsg(struct sys_exit_recvmsg_args *ctx)
{
    int is_udp = 0;
    conn_ctx_t id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = (ssize_t)(ctx->ret);
    struct sock_conn_s* sock_conn = NULL;

    // Filter by UDP tracing-on/off
    if (is_tracing_udp()) {
        struct sys_connect_args_s* args = bpf_map_lookup_elem(&sys_connect_args, &id);
        if (args && bytes_count > 0) {
            sock_conn = lkup_sock_conn((int)(id >> INT_LEN), args->fd);
            // new sock connection
            if (!sock_conn) {
                sock_conn = get_sock_conn_by_addr(ctx, (int)(id >> INT_LEN), args->fd, args->addr);
            }
            if (sock_conn == NULL) {
                goto end;
            }
            is_udp = 1;
            (void)submit_conn_open(ctx, sock_conn); // UDP socket open event;
        }
    }

    struct sock_data_args_s* data_args = bpf_map_lookup_elem(&sock_data_args, &id);
    if ((data_args != NULL) && (bytes_count > 0)) {
        if (!is_udp) {
            sock_conn = lkup_sock_conn((int)(id >> INT_LEN), data_args->conn_id.fd);
            if (!sock_conn) {
                sock_conn = get_sock_conn(ctx, (int)(id >> INT_LEN), data_args->conn_id.fd);
            }
            if (sock_conn == NULL) {
                goto end;
            }
            (void)submit_conn_open(ctx, sock_conn); // TCP socket open event;
        }
        submit_sock_data(ctx, sock_conn, id, L7_INGRESS, data_args, (size_t)bytes_count);
    }

end:
    bpf_map_delete_elem(&sys_connect_args, &id);
    bpf_map_delete_elem(&sock_data_args, &id);
    return 0;
}

// int close(int fd);
KPROBE_SYSCALL(close)
{
    struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    conn_ctx_t id = bpf_get_current_pid_tgid();
    if (!is_tracing((int)(id >> INT_LEN))) {
        return 0;
    }

    int fd = (int)PT_REGS_PARM1_CORE(regs);
    if (fd < 0) {
        return 0;
    }

    (void)submit_conn_close(ctx, id, fd);
    return 0;
}

