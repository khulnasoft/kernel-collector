// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _KHULNASOFT_HARDIRQ_H_
#define _KHULNASOFT_HARDIRQ_H_ 1

#define KHULNASOFT_HARDIRQ_MAX_IRQS 1024L
#define KHULNASOFT_HARDIRQ_NAME_LEN 32

// /sys/kernel/debug/tracing/events/irq/irq_handler_entry/
struct khulnasoft_irq_handler_entry {
    u64 pad;                    // This is not used with eBPF
    int irq;                    // offset:8;       size:4; signed:1;
    int data_loc_name;          // offset:12;      size:4; signed:1; (https://github.com/iovisor/bpftrace/issues/385)
                                // (https://lists.linuxfoundation.org/pipermail/iovisor-dev/2017-February/000627.html)
};

// /sys/kernel/debug/tracing/events/irq/irq_handler_exit/
struct khulnasoft_irq_handler_exit {
    u64 pad;                    // This is not used with eBPF
    int irq;                    // offset:8;       size:4; signed:1;
    int ret;                    // offset:12;      size:4; signed:1;
};

typedef struct hardirq_key {
    int irq;
} hardirq_key_t;

/*
typedef struct hardirq_val {
    // incremental counter storing the total latency so far.
    u64 latency;

    // temporary timestamp stored at the IRQ entry handler, to be diff'd with a
    // timestamp at the IRQ exit handler, to get the latency to add to the
    // `latency` field.
    u64 ts;

    // identifies the IRQ with a human-readable string.
    // We are reading it direct from /proc avoiding in some kernels:
    //  #0  0x000055f9729eb725 in libbpf_err_errno ()
    // #1  0x000055f9729ec8a0 in bpf_map_lookup_elem ()
    // #2  0x000055f97298be21 in hardirq_read_latency_map (mapfd=69) at collectors/ebpf.plugin/ebpf_hardirq.c:259
 //   char name[KHULNASOFT_HARDIRQ_NAME_LEN];
} hardirq_val_t;
*/

/************************************************************************************
 *                                HARDIRQ STATIC
 ***********************************************************************************/

// all of the `irq_vectors` events, except `vector_*`, have the same format.
// cat /sys/kernel/debug/tracing/available_events | grep 'irq_vectors' | grep -v ':vector_'
struct khulnasoft_irq_vectors_entry {
    u64 pad;                    // This is not used with eBPF
    int vector;                 // offset:8;       size:4; signed:1;
};
struct khulnasoft_irq_vectors_exit {
    u64 pad;                    // This is not used with eBPF
    int vector;                 // offset:8;       size:4; signed:1;
};

// these represent static IRQs that aren't given an IRQ ID like the ones above.
// they each require separate entry/exit tracepoints to track.
enum khulnasoft_hardirq_static {
    KHULNASOFT_HARDIRQ_STATIC_APIC_THERMAL,
    KHULNASOFT_HARDIRQ_STATIC_APIC_THRESHOLD,
    KHULNASOFT_HARDIRQ_STATIC_APIC_ERROR,
    KHULNASOFT_HARDIRQ_STATIC_APIC_DEFERRED_ERROR,
    KHULNASOFT_HARDIRQ_STATIC_APIC_SPURIOUS,
    KHULNASOFT_HARDIRQ_STATIC_FUNC_CALL,
    KHULNASOFT_HARDIRQ_STATIC_FUNC_CALL_SINGLE,
    KHULNASOFT_HARDIRQ_STATIC_RESCHEDULE,
    KHULNASOFT_HARDIRQ_STATIC_LOCAL_TIMER,
    KHULNASOFT_HARDIRQ_STATIC_IRQ_WORK,
    KHULNASOFT_HARDIRQ_STATIC_X86_PLATFORM_IPI,

    // must be last; used as counter.
    KHULNASOFT_HARDIRQ_STATIC_END
};

typedef struct hardirq_val {
    // incremental counter storing the total latency so far.
    u64 latency;

    // temporary timestamp stored at the IRQ entry handler, to be diff'd with a
    // timestamp at the IRQ exit handler, to get the latency to add to the
    // `latency` field.
    u64 ts;
} hardirq_val_t;

#endif /* _KHULNASOFT_HARDIRQ_H_ */
