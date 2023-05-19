#ifndef __SYSCALL_TP_ARGS_H__
#define __SYSCALL_TP_ARGS_H__

#define SC_ARG_E(name) struct syscalls_enter_##name##_args
#define SC_ARG_X(name) struct syscalls_exit_##name##_args

#define SC_ARG_E_T(name) syscalls_enter_##name##_args_t
#define SC_ARG_X_T(name) syscalls_exit_##name##_args_t

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

#define SC_E_COMMON(name) typedef SC_ARG_E(common) SC_ARG_E_T(name)
#define SC_X_COMMON(name) typedef SC_ARG_X(common) SC_ARG_X_T(name)

#define SC_E_FUTEX(name) typedef SC_ARG_E(futex) SC_ARG_E_T(name)

SC_E_FUTEX(futex);
SC_X_COMMON(futex);

#endif