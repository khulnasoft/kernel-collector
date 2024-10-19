// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _KHULNASOFT_CACHE_H_
#define _KHULNASOFT_CACHE_H_ 1

typedef struct khulnasoft_cachestat {
    __u64 ct;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    char name[TASK_COMM_LEN];

    __u32 add_to_page_cache_lru;
    __u32 mark_page_accessed;
    __u32 account_page_dirtied;
    __u32 mark_buffer_dirty;
} khulnasoft_cachestat_t;

enum cachestat_counters {
    KHULNASOFT_KEY_CALLS_ADD_TO_PAGE_CACHE_LRU,
    KHULNASOFT_KEY_CALLS_MARK_PAGE_ACCESSED,
    KHULNASOFT_KEY_CALLS_ACCOUNT_PAGE_DIRTIED,
    KHULNASOFT_KEY_CALLS_MARK_BUFFER_DIRTY,

    // Keep this as last and don't skip numbers as it is used as element counter
    KHULNASOFT_CACHESTAT_END
};

#endif /* _KHULNASOFT_CACHE_H_ */
