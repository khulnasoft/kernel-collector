// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _KHULNASOFT_SOFTIRQ_H_
#define _KHULNASOFT_SOFTIRQ_H_ 1

#define KHULNASOFT_SOFTIRQ_MAX_IRQS 10

// /sys/kernel/debug/tracing/events/irq/softirq_entry
struct khulnasoft_softirq_entry {
    u64 pad;                    // This is not used with eBPF
    u32 vec;                    // offset:8;       size:4; signed:0;
};

// /sys/kernel/debug/tracing/events/irq/softirq_exit
struct khulnasoft_softirq_exit {
    u64 pad;                    // This is not used with eBPF
    u32 vec;                    // offset:8;       size:4; signed:0;
};

typedef struct softirq_val {
    // incremental counter storing the total latency so far.
    u64 latency;

    // temporary timestamp stored at the entry handler, to be diff'd with a
    // timestamp at the exit handler, to get the latency to add to the
    // `latency` field.
    u64 ts;
} softirq_val_t;

#endif /* _KHULNASOFT_SOFTIRQ_H_ */
