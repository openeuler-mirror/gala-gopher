#ifndef __SYSCALL_TP_ARGS_H__
#define __SYSCALL_TP_ARGS_H__

#define SC_ARG_E(name) struct syscalls_enter_##name##_args
#define SC_ARG_X(name) struct syscalls_exit_##name##_args

#define SC_ARG_E_T(name) syscalls_enter_##name##_args_t
#define SC_ARG_X_T(name) syscalls_exit_##name##_args_t

SC_ARG_E(fd_common) {
    unsigned long long unused;
    long nr;
    int fd;
};

SC_ARG_E(common) {
    unsigned long long unused;
    long nr;
};

SC_ARG_X(common) {
    unsigned long long unused;
    long nr;
};

SC_ARG_E(futex) {
    unsigned long long unused;
    long nr;
    void *uaddr;
    int op;
};

#define SC_E_FD_COMMON(name) typedef SC_ARG_E(fd_common) SC_ARG_E_T(name)

#define SC_E_COMMON(name) typedef SC_ARG_E(common) SC_ARG_E_T(name)
#define SC_X_COMMON(name) typedef SC_ARG_X(common) SC_ARG_X_T(name)

#define SC_E_FUTEX(name) typedef SC_ARG_E(futex) SC_ARG_E_T(name)

SC_E_FUTEX(futex);
SC_X_COMMON(futex);

SC_E_FD_COMMON(read);
SC_X_COMMON(read);

SC_E_FD_COMMON(write);
SC_X_COMMON(write);

SC_E_FD_COMMON(readv);
SC_X_COMMON(readv);

SC_E_FD_COMMON(writev);
SC_X_COMMON(writev);

SC_E_FD_COMMON(preadv);
SC_X_COMMON(preadv);

SC_E_FD_COMMON(pwritev);
SC_X_COMMON(pwritev);

SC_E_COMMON(sync);
SC_X_COMMON(sync);

SC_E_FD_COMMON(fsync);
SC_X_COMMON(fsync);

SC_E_FD_COMMON(fdatasync);
SC_X_COMMON(fdatasync);

SC_E_FD_COMMON(sendto);
SC_X_COMMON(sendto);

SC_E_FD_COMMON(recvfrom);
SC_X_COMMON(recvfrom);

SC_E_FD_COMMON(sendmsg);
SC_X_COMMON(sendmsg);

SC_E_FD_COMMON(recvmsg);
SC_X_COMMON(recvmsg);

SC_E_FD_COMMON(sendmmsg);
SC_X_COMMON(sendmmsg);

SC_E_FD_COMMON(recvmmsg);
SC_X_COMMON(recvmmsg);

SC_E_COMMON(sched_yield);
SC_X_COMMON(sched_yield);

SC_E_COMMON(nanosleep);
SC_X_COMMON(nanosleep);

SC_E_COMMON(clock_nanosleep);
SC_X_COMMON(clock_nanosleep);

SC_E_COMMON(wait4);
SC_X_COMMON(wait4);

#if defined(__TARGET_ARCH_x86)
SC_E_COMMON(waitpid);
SC_X_COMMON(waitpid);
#endif

SC_E_COMMON(select);
SC_X_COMMON(select);

SC_E_COMMON(pselect6);
SC_X_COMMON(pselect6);

SC_E_COMMON(poll);
SC_X_COMMON(poll);

SC_E_COMMON(ppoll);
SC_X_COMMON(ppoll);

SC_E_COMMON(epoll_wait);
SC_X_COMMON(epoll_wait);

SC_E_COMMON(epoll_wait);
SC_X_COMMON(epoll_wait);
#endif