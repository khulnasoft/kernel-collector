// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _KHULNASOFT_SHM_H_
#define _KHULNASOFT_SHM_H_ 1

typedef struct khulnasoft_shm {
    __u64 ct;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    char name[TASK_COMM_LEN];

    __u32 get;
    __u32 at;
    __u32 dt;
    __u32 ctl;
} khulnasoft_shm_t;

enum shm_counters {
    KHULNASOFT_KEY_SHMGET_CALL,
    KHULNASOFT_KEY_SHMAT_CALL,
    KHULNASOFT_KEY_SHMDT_CALL,
    KHULNASOFT_KEY_SHMCTL_CALL,

    // Keep this as last and don't skip numbers as it is used as element counter
    KHULNASOFT_SHM_END
};

#endif /* _KHULNASOFT_SHM_H_ */
