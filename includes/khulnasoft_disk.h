// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _KHULNASOFT_DISK_H_
#define _KHULNASOFT_DISK_H_ 1

#include "khulnasoft_fs.h"

#define KHULNASOFT_DISK_MAX_HD 256L
#define KHULNASOFT_DISK_HISTOGRAM_LENGTH  (KHULNASOFT_FS_MAX_BINS * KHULNASOFT_DISK_MAX_HD)

// Decode function extracted from: https://elixir.bootlin.com/linux/v5.10.8/source/include/linux/kdev_t.h#L7
#define KHULNASOFT_MINORBITS       20
#define KHULNASOFT_MINORMASK	((1U << KHULNASOFT_MINORBITS) - 1)

#define KHULNASOFT_MAJOR(dev)	((unsigned int) ((dev) >> KHULNASOFT_MINORBITS))
#define KHULNASOFT_MINOR(dev)	((unsigned int) ((dev) & KHULNASOFT_MINORMASK))
#define KHULNASOFT_MKDEV(ma,mi)    (((ma) << MINORBITS) | (mi))

static __always_inline u32 khulnasoft_new_encode_dev(dev_t dev)
{
    unsigned major = KHULNASOFT_MAJOR(dev);
    unsigned minor = KHULNASOFT_MINOR(dev);
    return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

// /sys/kernel/debug/tracing/events/block/block_rq_issue/
struct khulnasoft_block_rq_issue {
    u64 pad;                    // This is not used with eBPF
    dev_t dev;                  // offset:8;       size:4; signed:0;
    sector_t sector;            // offset:16;      size:8; signed:0;
    unsigned int nr_sector;     // offset:24;      size:4; signed:0;
    unsigned int bytes;         // offset:28;      size:4; signed:0;
    char rwbs[8];               // offset:32;      size:8; signed:1;
    char comm[16];              // offset:40;      size:16;        signed:1;
    int data_loc_name;          // offset:56;      size:4; signed:1; (https://github.com/iovisor/bpftrace/issues/385)
};

// /sys/kernel/debug/tracing/events/block/block_rq_complete
// https://elixir.bootlin.com/linux/latest/source/include/trace/events/block.h
struct khulnasoft_block_rq_complete {
    u64 pad;                    // This is not used with eBPF
    dev_t dev;                  // offset:8;       size:4; signed:0;
    sector_t sector;            // offset:16;      size:8; signed:0;
    unsigned int nr_sector;     // offset:24;      size:4; signed:0;
    int error;                  // offset:28;      size:4; signed:1;
    char rwbs[8];               // offset:32;      size:8; signed:1;
    int data_loc_name;          // offset:40;      size:4; signed:1; 
                                //(https://lists.linuxfoundation.org/pipermail/iovisor-dev/2017-February/000627.html)
};

typedef struct khulnasoft_disk_key {
    dev_t dev;
    sector_t sector;
} khulnasoft_disk_key_t;

typedef struct block_key {
    __u32 bin;
    u32 dev;
} block_key_t;

#endif /* _KHULNASOFT_DISK_H_ */

