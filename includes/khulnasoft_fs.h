// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _KHULNASOFT_FS_H_
#define _KHULNASOFT_FS_H_ 1

enum fs_counters {
    KHULNASOFT_KEY_CALLS_READ,
    KHULNASOFT_KEY_CALLS_WRITE,
    KHULNASOFT_KEY_CALLS_OPEN,
    KHULNASOFT_KEY_CALLS_SYNC,

    KHULNASOFT_FS_END
};

enum fs_btf_counters {
    KHULNASOFT_KEY_BTF_READ,
    KHULNASOFT_KEY_BTF_WRITE,
    KHULNASOFT_KEY_BTF_OPEN,
    KHULNASOFT_KEY_BTF_SYNC_ATTR,
    KHULNASOFT_KEY_BTF_OPEN2,

    KHULNASOFT_FS_BTF_END
};

// We are using 24 as hard limit to avoid intervals bigger than
// 8 seconds and to keep memory aligment.
#define KHULNASOFT_FS_MAX_BINS 24UL
#define KHULNASOFT_FS_MAX_TABLES 4UL
#define KHULNASOFT_FS_MAX_ELEMENTS (KHULNASOFT_FS_MAX_BINS * KHULNASOFT_FS_MAX_TABLES)
#define KHULNASOFT_FS_MAX_BINS_POS (KHULNASOFT_FS_MAX_BINS - 1)
#define KHULNASOFT_FS_HISTOGRAM_LENGTH  (KHULNASOFT_FS_MAX_BINS * KHULNASOFT_FS_MAX_BINS)


#endif /* _KHULNASOFT_FS_H_ */

