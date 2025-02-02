#define KBUILD_MODNAME "oomkill_khulnasoft"
#include <linux/ptrace.h>
#include <linux/oom.h>
#include <linux/threads.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <uapi/linux/bpf.h>
#else
#include <linux/bpf.h>
#endif
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "khulnasoft_ebpf.h"

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
struct {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    __uint(type, BPF_MAP_TYPE_HASH);
#else
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
#endif
    __type(key, int);
    __type(value, __u8);
    __uint(max_entries, KHULNASOFT_OOMKILL_MAX_ENTRIES);
} tbl_oomkill SEC(".maps");
#else
struct bpf_map_def SEC("maps") tbl_oomkill = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(__u8),
    .max_entries = KHULNASOFT_OOMKILL_MAX_ENTRIES
};
#endif

SEC("tracepoint/oom/mark_victim")
int khulnasoft_oom_mark_victim(struct khulnasoft_oom_mark_victim_entry *ptr) {
    int key = ptr->pid;
    u8 val = 0;
    bpf_map_update_elem(&tbl_oomkill, &key, &val, BPF_ANY);
    return 0;
}

char _license[] SEC("license") = "GPL";
