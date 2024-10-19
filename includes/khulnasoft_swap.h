// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _KHULNASOFT_SWAP_H_
#define _KHULNASOFT_SWAP_H_ 1

typedef struct khulnasoft_swap_access {
    __u64 ct;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    char name[TASK_COMM_LEN];

    __u32 read;
    __u32 write;
} khulnasoft_swap_access_t;

enum swap_counters {
    KHULNASOFT_KEY_SWAP_READPAGE_CALL,
    KHULNASOFT_KEY_SWAP_WRITEPAGE_CALL,

    // Keep this as last and don't skip numbers as it is used as element counter
    KHULNASOFT_SWAP_END
};

#endif /* _KHULNASOFT_SWAP_H_ */
