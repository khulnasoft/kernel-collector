// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _KHULNASOFT_EBPF_FD_H_
#define _KHULNASOFT_EBPF_FD_H_ 1

struct khulnasoft_fd_stat_t {
    __u64 ct;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    char name[TASK_COMM_LEN];

    //Counter
    __u32 open_call;                    //open syscalls (open and openat)
    __u32 close_call;                   //Close syscall (close)

    //Counter
    __u32 open_err;
    __u32 close_err;
};

enum fd_counters {
    KHULNASOFT_KEY_CALLS_DO_SYS_OPEN,
    KHULNASOFT_KEY_ERROR_DO_SYS_OPEN,

    KHULNASOFT_KEY_CALLS_CLOSE_FD,
    KHULNASOFT_KEY_ERROR_CLOSE_FD,

    // Keep this as last and don't skip numbers as it is used as element counter
    KHULNASOFT_FD_COUNTER
};

enum fd_actions {
    KHULNASOFT_FD_OPEN,
    KHULNASOFT_FD_CLOSE,

    KHULNASOFT_FD_ACTIONS
};

#endif /* _KHULNASOFT_EBPF_FD_H_ */

