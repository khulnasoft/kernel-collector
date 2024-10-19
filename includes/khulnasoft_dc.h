// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _KHULNASOFT_DIRECTORY_CACHE_H_
#define _KHULNASOFT_DIRECTORY_CACHE_H_ 1

typedef struct khulnasoft_dc_stat {
    __u64 ct;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    char name[TASK_COMM_LEN];

    __u32 references;
    __u32 slow;
    __u32 missed;
} khulnasoft_dc_stat_t;

enum directory_cache_counters {
    KHULNASOFT_KEY_DC_REFERENCE,
    KHULNASOFT_KEY_DC_SLOW,
    KHULNASOFT_KEY_DC_MISS,

    // Keep this as last and don't skip numbers as it is used as element counter
    KHULNASOFT_DIRECTORY_CACHE_END
};

enum directory_cachec_functions {
    KHULNASOFT_LOOKUP_FAST,
    KHULNASOFT_D_LOOKUP,

    KHULNASOFT_DC_COUNTER
};

#endif /* _KHULNASOFT_DIRECTORY_CACHE_H_ */

