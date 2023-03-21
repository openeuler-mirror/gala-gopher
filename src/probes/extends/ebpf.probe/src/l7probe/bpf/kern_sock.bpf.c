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
#include "filter_bpf.h"

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

static __always_inline char is_tracing(int tgid)
{
    if (is_filter_by_cgrp()) {
        u64 cgrp_id = get_cur_cpuacct_cgrp_id();
        if (is_filter_id(FILTER_CGRPID, cgrp_id)) {
            return 1;
        } else {
            return 0;
        }
    } else {
        if (is_filter_id(FILTER_TGID, tgid)) {
            return 1;
        } else {
            return 0;
        }
    }
}

static __always_inline char is_tracing_udp(void)
{
    u32 proto = get_filter_proto();
    return proto & L7PROBE_TRACING_DNS;
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

KRETPROBE(sock_alloc, pt_regs)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct sys_accept_args_s* args = bpf_map_lookup_elem(&sys_accept_args, &id);
    if (args == NULL) {
        return 0;
    }

    if (args->newsock == NULL) {
        args->newsock = (struct socket *)PT_REGS_RC(ctx);
    }
    return 0;
}

// int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
KPROBE_SYSCALL(connect)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);

    if (!is_tracing(proc_id)) {
        return 0;
    }

    int fd = (int)PT_REGS_PARM1(ctx);
    const struct sockaddr *addr = (const struct sockaddr *)PT_REGS_PARM2(ctx);

    struct sys_connect_args_s args = {0};
    args.fd = fd;
    args.addr = addr;
    bpf_map_update_elem(&sys_connect_args, &id, &args, BPF_ANY);
    return 0;
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

        submit_conn_open(ctx, (int)(id >> INT_LEN), args->fd,
                L4_CLIENT, args->addr, /*socket*/ NULL);
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

    if (!is_tracing(proc_id)) {
        return 0;
    }

    int fd = (int)PT_REGS_PARM1(ctx);

    struct sock_data_args_s args = {0};
    args.conn_id.fd = fd;
    args.conn_id.tgid = proc_id;
    args.direct = L7_EGRESS;
    args.buf = (char *)PT_REGS_PARM2(ctx);
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
        submit_sock_data(ctx, id, L7_EGRESS, args, (size_t)bytes_count);
    }

end:
    bpf_map_delete_elem(&sock_data_args, &id);
    return 0;
}

// int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
KPROBE_SYSCALL(accept)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();

    if (!is_tracing((int)(id >> INT_LEN))) {
        return 0;
    }

    const struct sockaddr *addr = (const struct sockaddr *)PT_REGS_PARM2(ctx);

    struct sys_accept_args_s args = {0};
    args.addr = addr;
    bpf_map_update_elem(&sys_accept_args, &id, &args, BPF_ANY);
    return 0;
}

KRETPROBE_SYSCALL(accept)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct sys_accept_args_s* args = bpf_map_lookup_elem(&sys_accept_args, &id);
    if (args != NULL) {
        if (args->addr == NULL) {
          goto end;
        }

        int new_fd = (int)PT_REGS_RC(ctx);
        if (new_fd < 0) {
            goto end;
        }

        submit_conn_open(ctx, (int)(id >> INT_LEN), new_fd,
                L4_SERVER, args->addr, /*socket*/ NULL);
    }
end:
    bpf_map_delete_elem(&sys_accept_args, &id);
    return 0;
}

// int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
KPROBE_SYSCALL(accept4)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();

    if (!is_tracing((int)(id >> INT_LEN))) {
        return 0;
    }

    const struct sockaddr *addr = (const struct sockaddr *)PT_REGS_PARM2(ctx);

    struct sys_accept_args_s args = {0};
    args.addr = addr;
    bpf_map_update_elem(&sys_accept_args, &id, &args, BPF_ANY);
    return 0;
}

KRETPROBE_SYSCALL(accept4)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct sys_accept_args_s* args = bpf_map_lookup_elem(&sys_accept_args, &id);
    if (args != NULL) {
        if (args->addr == NULL) {
          goto end;
        }

        int new_fd = (int)PT_REGS_RC(ctx);
        if (new_fd < 0) {
            goto end;
        }

        submit_conn_open(ctx, (int)(id >> INT_LEN), new_fd,
                L4_SERVER, args->addr, args->newsock);
    }
end:
    bpf_map_delete_elem(&sys_accept_args, &id);
    return 0;
}

// ssize_t write(int fd, const void *buf, size_t count);
KPROBE_SYSCALL(write)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);
    int fd = (int)PT_REGS_PARM1(ctx);

    if (!is_tracing(proc_id)) {
        return 0;
    }

    struct sock_data_args_s args = {0};
    args.conn_id.fd = fd;
    args.conn_id.tgid = proc_id;
    args.direct = L7_EGRESS;
    args.buf = (char *)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&sock_data_args, &id, &args, BPF_ANY);
    return 0;
}

KRETPROBE_SYSCALL(write)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct sock_data_args_s* args = bpf_map_lookup_elem(&sock_data_args, &id);
    if (args != NULL && args->is_socket_op) {
        ssize_t bytes_count = (ssize_t)PT_REGS_RC(ctx);
        if (bytes_count <= 0) {
            goto end;
        }
        submit_sock_data(ctx, id, L7_EGRESS, args, (size_t)bytes_count);
    }

end:
    bpf_map_delete_elem(&sock_data_args, &id);
    return 0;
}

// ssize_t read(int fd, void *buf, size_t count);
KPROBE_SYSCALL(read)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);
    int fd = (int)PT_REGS_PARM1(ctx);

    if (!is_tracing(proc_id)) {
        return 0;
    }

    struct sock_data_args_s args = {0};
    args.conn_id.fd = fd;
    args.conn_id.tgid = proc_id;
    args.direct = L7_INGRESS;
    args.buf = (char *)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&sock_data_args, &id, &args, BPF_ANY);
    return 0;
}

KRETPROBE_SYSCALL(read)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();

    struct sock_data_args_s* args = bpf_map_lookup_elem(&sock_data_args, &id);
    if (args != NULL && args->is_socket_op) {
        ssize_t bytes_count = (ssize_t)PT_REGS_RC(ctx);
        if (bytes_count <= 0) {
            goto end;
        }
        submit_sock_data(ctx, id, L7_INGRESS, args, (size_t)bytes_count);
    }

end:
    bpf_map_delete_elem(&sock_data_args, &id);
    return 0;
}

// ssize_t recv(int sockfd, void *buf, size_t len, int flags);
KPROBE_SYSCALL(recv)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);
    int fd = (int)PT_REGS_PARM1(ctx);

    if (!is_tracing(proc_id)) {
        return 0;
    }

    struct sock_data_args_s args = {0};
    args.conn_id.fd = fd;
    args.conn_id.tgid = proc_id;
    args.direct = L7_INGRESS;
    args.buf = (char *)PT_REGS_PARM2(ctx);
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
        submit_sock_data(ctx, id, L7_INGRESS, args, (size_t)bytes_count);
    }

end:
    bpf_map_delete_elem(&sock_data_args, &id);
    return 0;
}

// ssize_t sendto(int sockfd, const void *buf, size_t len,
//      int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
KPROBE_SYSCALL(sendto)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);

    if (!is_tracing(proc_id)) {
        return 0;
    }

    int sockfd = (int)PT_REGS_PARM1(ctx);
    char *buf = (char *)PT_REGS_PARM2(ctx);
    if (buf == NULL || sockfd < 0) {
        return -1;
    }

    // Filter by UDP tracing-on/off
    if (is_tracing_udp()) {
        struct sockaddr * dest_addr = (struct sockaddr *)PT_REGS_PARM5(ctx);
        if (dest_addr && sockfd > 0) {
            struct sys_connect_args_s args = {0};
            args.fd = fd;
            args.addr = dest_addr;
            bpf_map_update_elem(&sys_connect_args, &id, &args, BPF_ANY);
        }
    }

    struct sock_data_args_s data_args = {0};
    data_args.buf = buf;
    data_args.conn_id.fd = fd;
    data_args.conn_id.tgid = proc_id;
    bpf_map_update_elem(&sock_data_args, &id, &data_args, BPF_ANY);
    return 0;
}

KRETPROBE_SYSCALL(sendto)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = PT_REGS_RC(ctx);

    // Filter by UDP tracing-on/off
    if (is_tracing_udp()) {
        struct sys_connect_args_s* args = bpf_map_lookup_elem(&sys_connect_args, &id);
        if ((args != NULL) && (bytes_count > 0)) {
            submit_conn_open(ctx, (int)(id >> INT_LEN), args->fd, L4_UNKNOW, args->addr, /*socket*/ NULL);
        }

        bpf_map_delete_elem(&sys_connect_args, &id);
    }

    // Unstash arguments, and process syscall.
    struct sock_data_args_s* data_args = bpf_map_lookup_elem(&sock_data_args, &id);
    if ((data_args != NULL) && (bytes_count > 0)) {
        submit_sock_data(ctx, id, L7_EGRESS, data_args, (size_t)bytes_count);
    }

    bpf_map_delete_elem(&sock_data_args, &id);
    return 0;
}


// ssize_t recvfrom(int sockfd, void *buf, size_t len,
//      int flags, struct sockaddr *src_addr, socklen_t *addrlen);
KPROBE_SYSCALL(recvfrom)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);

    if (!is_tracing(proc_id)) {
        return 0;
    }

    int sockfd = (int)PT_REGS_PARM1(ctx);
    char *buf = (char *)PT_REGS_PARM2(ctx);
    if (buf == NULL || sockfd < 0) {
        return -1;
    }

    // Filter by UDP tracing-on/off
    if (is_tracing_udp()) {
        struct sockaddr * src_addr = (struct sockaddr *)PT_REGS_PARM5(ctx);
        if (src_addr) {
            struct sys_connect_args_s args = {0};
            args.fd = fd;
            args.addr = src_addr;
            bpf_map_update_elem(&sys_connect_args, &id, &args, BPF_ANY);
        }
    }

    struct sock_data_args_s data_args = {0};
    data_args.buf = buf;
    data_args.conn_id.fd = fd;
    data_args.conn_id.tgid = proc_id;
    bpf_map_update_elem(&sock_data_args, &id, &data_args, BPF_ANY);
    return 0;
}

KRETPROBE_SYSCALL(recvfrom)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = PT_REGS_RC(ctx);

    // Filter by UDP tracing-on/off
    if (is_tracing_udp()) {
        struct sys_connect_args_s* args = bpf_map_lookup_elem(&sys_connect_args, &id);
        if (args && bytes_count > 0) {
            submit_conn_open(ctx, (int)(id >> INT_LEN), args->fd, L4_UNKNOW, args->addr, /*socket*/ NULL);
        }
    }

    bpf_map_delete_elem(&sys_connect_args, &id);

    // Unstash arguments, and process syscall.
    struct sock_data_args_s* data_args = bpf_map_lookup_elem(&sock_data_args, &id);
    if ((data_args != NULL) && (bytes_count > 0)) {
        submit_sock_data(ctx, id, L7_INGRESS, data_args, (size_t)bytes_count);
    }

    bpf_map_delete_elem(&sock_data_args, &id);
    return 0;
}

// ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
KPROBE_SYSCALL(sendmsg)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);

    if (!is_tracing(proc_id)) {
        return 0;
    }

    int fd = (int)PT_REGS_PARM1(ctx);
    struct user_msghdr *msg = (struct user_msghdr *)PT_REGS_PARM2(ctx);
#if (CURRENT_LIBBPF_VERSION  < LIBBPF_VERSION(0, 8))
    void * msg_name = BPF_CORE_READ(msg, msg_name);
    struct iovec* iov = BPF_CORE_READ(msg, msg_iov);
    size_t iovlen = BPF_CORE_READ(msg, msg_iovlen);
#else
    void * msg_name = BPF_CORE_READ_USER(msg, msg_name);
    struct iovec* iov = BPF_CORE_READ_USER(msg, msg_iov);
    size_t iovlen = BPF_CORE_READ_USER(msg, msg_iovlen);
#endif

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
    bpf_map_update_elem(&sock_data_args, &id, &data_args, BPF_ANY);
    return 0;
}

KRETPROBE_SYSCALL(sendmsg)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = PT_REGS_RC(ctx);

    // Filter by UDP tracing-on/off
    if (is_tracing_udp()) {
        struct sys_connect_args_s* args = bpf_map_lookup_elem(&sys_connect_args, &id);
        if (args && bytes_count > 0) {
            submit_conn_open(ctx, (int)(id >> INT_LEN), args->fd, L4_UNKNOW, args->addr, /*socket*/ NULL);
        }

        bpf_map_delete_elem(&sys_connect_args, &id);
    }

    struct sock_data_args_s* data_args = bpf_map_lookup_elem(&sock_data_args, &id);
    if ((data_args != NULL) && (bytes_count > 0)) {
        submit_sock_data(ctx, id, L7_EGRESS, data_args, (size_t)bytes_count);
    }

    bpf_map_delete_elem(&sock_data_args, &id);
    return 0;
}

// ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
KPROBE_SYSCALL(recvmsg)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    int proc_id = (int)(id >> INT_LEN);
    if (!is_tracing(proc_id)) {
        return 0;
    }

    int fd = (int)PT_REGS_PARM1(ctx);
    struct user_msghdr *msg = (struct user_msghdr *)PT_REGS_PARM2(ctx);
#if (CURRENT_LIBBPF_VERSION  < LIBBPF_VERSION(0, 8))
    void * msg_name = BPF_CORE_READ(msg, msg_name);
    struct iovec* iov = BPF_CORE_READ(msg, msg_iov);
    size_t iovlen = BPF_CORE_READ(msg, msg_iovlen);
#else
    void * msg_name = BPF_CORE_READ_USER(msg, msg_name);
    struct iovec* iov = BPF_CORE_READ_USER(msg, msg_iov);
    size_t iovlen = BPF_CORE_READ_USER(msg, msg_iovlen);
#endif

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
    bpf_map_update_elem(&sock_data_args, &id, &data_args, BPF_ANY);
    return 0;
}

KRETPROBE_SYSCALL(recvmsg)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = PT_REGS_RC(ctx);

    // Filter by UDP tracing-on/off
    if (is_tracing_udp()) {
        struct sys_connect_args_s* args = bpf_map_lookup_elem(&sys_connect_args, &id);
        if (args && bytes_count > 0) {
            submit_conn_open(ctx, (int)(id >> INT_LEN), args->fd, L4_UNKNOW, args->addr, /*socket*/ NULL);
        }

        bpf_map_delete_elem(&sys_connect_args, &id);
    }

    struct sock_data_args_s* data_args = bpf_map_lookup_elem(&sock_data_args, &id);
    if ((data_args != NULL) && (bytes_count > 0)) {
        submit_sock_data(ctx, id, L7_INGRESS, data_args, (size_t)bytes_count);
    }

    bpf_map_delete_elem(&sock_data_args, &id);
    return 0;
}

// int close(int fd);
KPROBE_SYSCALL(close)
{
    conn_ctx_t id = bpf_get_current_pid_tgid();
    if (!is_tracing((int)(id >> INT_LEN))) {
        return 0;
    }

    int fd = (int)PT_REGS_PARM1(ctx);
    if (fd < 0) {
        return 0;
    }

    (void)submit_conn_close(ctx, id, fd);
    return 0;
}

