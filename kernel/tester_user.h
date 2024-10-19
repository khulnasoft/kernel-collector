#ifndef KHULNASOFT_LEGACY_TESTER
#define KHULNASOFT_LEGACY_TESTER 1

#include <libbpf.h>
#include <bpf.h>

#include "../includes/khulnasoft_defs.h"

#define VERSION_STRING_LEN 256
#define KHULNASOFT_EBPF_PROGRAM_LEN  VERSION_STRING_LEN


/**
 * The RedHat magic number was got doing:
 *
 * 1797 = 7*256 + 5
 *
 *  For more details, please, read /usr/include/linux/version.h
 *  in any Red Hat installation.
 */
#define KHULNASOFT_MINIMUM_RH_VERSION 1797

/**
 * 2048 = 8*256 + 0
 */
#define KHULNASOFT_RH_8 2048

/**
 *  Kernel Version
 *
 *  Kernel versions are calculated using the following formula:
 *
 *  VERSION = LINUX_VERSION_MAJOR*65536 + LINUX_VERSION_PATCHLEVEL*256 + LINUX_VERSION_SUBLEVEL
 *
 *  Where LINUX_VERSION_MAJOR, LINUX_VERSION_PATCHLEVEL, and LINUX_VERSION_SUBLEVEL are extracted
 *  from /usr/include/linux/version.h.
 *
 *  LINUX_VERSION_SUBLEVEL has the maximum value 255, but linux can have more SUBLEVELS.
 *
 */
enum khulnasoft_ebpf_kernel_versions {
    KHULNASOFT_EBPF_KERNEL_4_11 = 264960,  //  264960 = 4 * 65536 + 15 * 256
    KHULNASOFT_EBPF_KERNEL_4_14 = 265728,  //  264960 = 4 * 65536 + 14 * 256
    KHULNASOFT_EBPF_KERNEL_4_15 = 265984,  //  265984 = 4 * 65536 + 15 * 256
    KHULNASOFT_EBPF_KERNEL_4_17 = 266496,  //  266496 = 4 * 65536 + 17 * 256
    KHULNASOFT_EBPF_KERNEL_5_0  = 327680,  //  327680 = 5 * 65536 +  0 * 256
    KHULNASOFT_EBPF_KERNEL_5_2  = 328192,  //  327680 = 5 * 65536 +  2 * 256
    KHULNASOFT_EBPF_KERNEL_5_4  = 328704,  //  327680 = 5 * 65536 +  4 * 256
    KHULNASOFT_EBPF_KERNEL_5_10 = 330240,  //  330240 = 5 * 65536 + 10 * 256
    KHULNASOFT_EBPF_KERNEL_5_11 = 330496,  //  330240 = 5 * 65536 + 11 * 256
    KHULNASOFT_EBPF_KERNEL_5_14 = 331264,  //  331264 = 5 * 65536 + 14 * 256
    KHULNASOFT_EBPF_KERNEL_5_15 = 331520,  //  331520 = 5 * 65536 + 15 * 256
    KHULNASOFT_EBPF_KERNEL_5_16 = 331776,  //  331776 = 5 * 65536 + 16 * 256
    KHULNASOFT_EBPF_KERNEL_6_8  = 395264   //  395264 = 5 * 65536 +  8 * 256
};

/**
 * Minimum value has relationship with libbpf support.
 */
#define KHULNASOFT_MINIMUM_EBPF_KERNEL KHULNASOFT_EBPF_KERNEL_4_11


enum khulnasoft_kernel_flag {
    KHULNASOFT_V3_10 = 1 <<  0,
    KHULNASOFT_V4_14 = 1 <<  1,
    KHULNASOFT_V4_16 = 1 <<  2,
    KHULNASOFT_V4_18 = 1 <<  3,
    KHULNASOFT_V5_4  = 1 <<  4,
    KHULNASOFT_V5_10 = 1 <<  5,
    KHULNASOFT_V5_11 = 1 <<  6,
    KHULNASOFT_V5_14 = 1 <<  7,
    KHULNASOFT_V5_15 = 1 <<  8,
    KHULNASOFT_V5_16 = 1 <<  9,
    KHULNASOFT_V6_8  = 1 << 10
};

enum khulnasoft_kernel_counter {
    KHULNASOFT_3_10,
    KHULNASOFT_4_14,
    KHULNASOFT_4_16,
    KHULNASOFT_4_18,
    KHULNASOFT_5_4,
    KHULNASOFT_5_10,
    KHULNASOFT_5_11,
    KHULNASOFT_5_14,
    KHULNASOFT_5_15,
    KHULNASOFT_5_16,
    KHULNASOFT_6_8,

    KHULNASOFT_VERSION_END
};

enum khulnasoft_thread_flag {
    KHULNASOFT_FLAG_BTRFS = 1 << 0,
    KHULNASOFT_FLAG_CACHESTAT = 1 << 1,
    KHULNASOFT_FLAG_DC = 1 << 2,
    KHULNASOFT_FLAG_DISK = 1 << 3,
    KHULNASOFT_FLAG_EXT4 = 1 << 4,
    KHULNASOFT_FLAG_FD = 1 << 5,
    KHULNASOFT_FLAG_SYNC = 1 << 6,
    KHULNASOFT_FLAG_HARDIRQ = 1 << 7,
    KHULNASOFT_FLAG_MDFLUSH = 1 << 8,
    KHULNASOFT_FLAG_MOUNT = 1 << 9,
    KHULNASOFT_FLAG_NETWORK_VIEWER = 1 << 10,
    KHULNASOFT_FLAG_OOMKILL = 1 << 11,
    KHULNASOFT_FLAG_PROCESS = 1 << 12,
    KHULNASOFT_FLAG_SHM = 1 << 13,
    KHULNASOFT_FLAG_SOCKET = 1 << 14,
    KHULNASOFT_FLAG_SOFTIRQ = 1 << 15,
    KHULNASOFT_FLAG_SWAP = 1 << 16,
    KHULNASOFT_FLAG_VFS = 1 << 17,
    KHULNASOFT_FLAG_NFS = 1 << 18,
    KHULNASOFT_FLAG_XFS = 1 << 19,
    KHULNASOFT_FLAG_ZFS = 1 << 20,
    KHULNASOFT_FLAG_LOAD_BINARY = 1 << 21,
    KHULNASOFT_FLAG_CONTENT = 1 << 22,

    KHULNASOFT_FLAG_FS =  (uint64_t)(KHULNASOFT_FLAG_BTRFS | KHULNASOFT_FLAG_EXT4 | KHULNASOFT_FLAG_VFS | KHULNASOFT_FLAG_NFS | KHULNASOFT_FLAG_XFS | KHULNASOFT_FLAG_ZFS),
    KHULNASOFT_FLAG_ALL = 0XFFFFFFFFFFFFFFFF
};

enum khulnasoft_thread_OPT {
    KHULNASOFT_OPT_BTRFS,
    KHULNASOFT_OPT_CACHESTAT,
    KHULNASOFT_OPT_DC,
    KHULNASOFT_OPT_DISK,
    KHULNASOFT_OPT_EXT4,
    KHULNASOFT_OPT_FD,
    KHULNASOFT_OPT_SYNC,
    KHULNASOFT_OPT_HARDIRQ,
    KHULNASOFT_OPT_MDFLUSH,
    KHULNASOFT_OPT_MOUNT,
    KHULNASOFT_OPT_NETWORK_VIEWER,
    KHULNASOFT_OPT_OOMKILL,
    KHULNASOFT_OPT_PROCESS,
    KHULNASOFT_OPT_SHM,
    KHULNASOFT_OPT_SOCKET,
    KHULNASOFT_OPT_SOFTIRQ,
    KHULNASOFT_OPT_SWAP,
    KHULNASOFT_OPT_VFS,
    KHULNASOFT_OPT_NFS,
    KHULNASOFT_OPT_XFS,
    KHULNASOFT_OPT_ZFS,

    KHULNASOFT_OPT_HELP,
    KHULNASOFT_OPT_ALL,
    KHULNASOFT_OPT_COMMON,
    KHULNASOFT_OPT_LOAD_BINARY,
    KHULNASOFT_OPT_KHULNASOFT_PATH,
    KHULNASOFT_OPT_LOG_PATH,
    KHULNASOFT_OPT_CONTENT,
    KHULNASOFT_OPT_ITERATION,
    KHULNASOFT_OPT_PID
};

typedef struct ebpf_specify_name {
    char *program_name;
    char *function_to_attach;
    char *optional;
    bool retprobe;
} ebpf_specify_name_t;

typedef struct ebpf_module {
    uint32_t kernels;
    uint64_t flags;
    char *name;
    ebpf_specify_name_t *update_names;
    char *ctrl_table;
} ebpf_module_t ;

typedef struct ebpf_attach {
    struct bpf_link **links;
    size_t success;
    size_t fail;
} ebpf_attach_t;

typedef struct ebpf_table_data {
    void *key;
    void *next_key;
    void *value;
    void *def_value;

    long key_length;
    long value_length;

    size_t filled;
    size_t zero;
} ebpf_table_data_t;

#endif  /* KHULNASOFT_LEGACY_TESTER */

