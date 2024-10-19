// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _KHULNASOFT_EBPF_PROCESS_H_
#define _KHULNASOFT_EBPF_PROCESS_H_ 1

// /sys/kernel/tracing/events/sched/sched_process_exit/format
typedef struct khulnasoft_sched_process_exit {
    __u64 pad;      // This is not used with eBPF
    char comm[16] ; // offset:8;       size:16;        signed:1;
    int pid;        // offset:24;      size:4; signed:1;
    int prio;       // offset:28;      size:4; signed:1;
} khulnasoft_sched_process_exit_t;

// /sys/kernel/tracing/events/sched/sched_process_fork/format
typedef struct khulnasoft_sched_process_fork {
    __u64 pad;                // This is not used with eBPF
    char parent_comm[16];     // offset:8;       size:16;        signed:1;
    int parent_pid;           // offset:24;      size:4; signed:1;
    char child_comm[16];      // offset:28;      size:16;        signed:1;
    int child_pid;            // offset:44;      size:4; signed:1;
} khulnasoft_sched_process_fork_t;

// /sys/kernel/tracing/events/sched/sched_process_exec/format
typedef struct khulnasoft_sched_process_exec {
    __u64 pad;      // This is not used with eBPF
    int filename;   // offset:8;       size:4; signed:1;
    int pid;        // offset:12;      size:4; signed:1;
    int old_pid;   // offset:16;      size:4; signed:1;
} khulnasoft_sched_process_exec_t;

struct khulnasoft_pid_stat_t {
    __u64 ct;
    __u32 uid;
    __u32 gid;
    char name[TASK_COMM_LEN];

    __u32 tgid;                         //Task id
    __u32 pid;                          //Process id

    //Counter
    __u32 exit_call;                    //Exit syscalls (exit for exit_group)
    __u32 release_call;                 //Exit syscalls (exit and exit_group)
    __u32 create_process;               //Start syscall (fork, clone, forkv)
    __u32 create_thread;                //Start syscall (fork, clone, forkv)

    __u32 task_err;
};

enum process_counters {
    KHULNASOFT_KEY_CALLS_DO_EXIT,

    KHULNASOFT_KEY_CALLS_RELEASE_TASK,

    KHULNASOFT_KEY_CALLS_PROCESS,
    KHULNASOFT_KEY_ERROR_PROCESS,

    KHULNASOFT_KEY_CALLS_THREAD,
    KHULNASOFT_KEY_ERROR_THREAD,

    // Keep this as last and don't skip numbers as it is used as element counter
    KHULNASOFT_GLOBAL_COUNTER
};

#endif /* _KHULNASOFT_EBPF_PROCESS_H_ */

