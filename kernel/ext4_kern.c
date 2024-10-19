#define KBUILD_MODNAME "ext4_khulnasoft"
#include <linux/version.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0))
#include <linux/genhd.h>
#endif

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <uapi/linux/bpf.h>
#else
#include <linux/bpf.h>
#endif
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "khulnasoft_ebpf.h"

/************************************************************************************
 *     
 *                                 MAP Section
 *     
 ***********************************************************************************/

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_FS_MAX_ELEMENTS);
} tbl_ext4 SEC(".maps");

struct {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    __uint(type, BPF_MAP_TYPE_HASH);
#else
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
#endif
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries,  4192);
} tmp_ext4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_CONTROLLER_END);
} ext4_ctrl SEC(".maps");

#else

struct bpf_map_def SEC("maps") tbl_ext4 = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = KHULNASOFT_FS_MAX_ELEMENTS
};

struct bpf_map_def SEC("maps") tmp_ext4 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 4192
};

struct bpf_map_def SEC("maps") ext4_ctrl = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = KHULNASOFT_CONTROLLER_END
};

#endif

/************************************************************************************
 *     
 *                                 ENTRY Section
 *     
 ***********************************************************************************/

static __always_inline int khulnasoft_ext4_entry()
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&tmp_ext4, &pid, &ts, BPF_ANY);

    libkhulnasoft_update_global(&ext4_ctrl, KHULNASOFT_CONTROLLER_TEMP_TABLE_ADD, 1);

    return 0;
}

SEC("kprobe/ext4_file_read_iter")
int khulnasoft_ext4_file_read_iter(struct pt_regs *ctx) 
{
    return khulnasoft_ext4_entry();
}

SEC("kprobe/ext4_file_write_iter")
int khulnasoft_ext4_file_write_iter(struct pt_regs *ctx) 
{
    return khulnasoft_ext4_entry();
}

SEC("kprobe/ext4_file_open")
int khulnasoft_ext4_file_open(struct pt_regs *ctx) 
{
    return khulnasoft_ext4_entry();
}

SEC("kprobe/ext4_sync_file")
int khulnasoft_ext4_sync_file(struct pt_regs *ctx) 
{
    return khulnasoft_ext4_entry();
}

/************************************************************************************
 *     
 *                                 END Section
 *     
 ***********************************************************************************/

static void khulnasoft_ext4_store_bin(__u32 bin, __u32 selection)
{
    __u64 *fill, data;
    __u32 idx = selection * KHULNASOFT_FS_MAX_BINS + bin;
    if (idx >= KHULNASOFT_FS_MAX_ELEMENTS)
        return;

    fill = bpf_map_lookup_elem(&tbl_ext4, &idx);
    if (fill) {
        libkhulnasoft_update_u64(fill, 1);
		return;
    } 

    data = 1;
    bpf_map_update_elem(&tbl_ext4, &idx, &data, BPF_ANY);

    libkhulnasoft_update_global(&ext4_ctrl, KHULNASOFT_CONTROLLER_TEMP_TABLE_DEL, 1);
}

SEC("kretprobe/ext4_file_read_iter")
int khulnasoft_ret_ext4_ext4_file_read_iter(struct pt_regs *ctx)
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 bin, pid = (__u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tmp_ext4, &pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_ext4, &pid);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;
    bin = libkhulnasoft_select_idx(data, KHULNASOFT_FS_MAX_BINS_POS);
    khulnasoft_ext4_store_bin(bin, KHULNASOFT_KEY_CALLS_READ);

    return 0;
}

SEC("kretprobe/ext4_file_write_iter")
int khulnasoft_ret_ext4_file_write_iter(struct pt_regs *ctx)
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 bin, pid = (__u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tmp_ext4, &pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_ext4, &pid);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;
    bin = libkhulnasoft_select_idx(data, KHULNASOFT_FS_MAX_BINS_POS);
    khulnasoft_ext4_store_bin(bin, KHULNASOFT_KEY_CALLS_WRITE);

    return 0;
}

SEC("kretprobe/ext4_file_open")
int khulnasoft_ret_ext4_file_open(struct pt_regs *ctx)
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 bin, pid = (__u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tmp_ext4, &pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_ext4, &pid);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;
    bin = libkhulnasoft_select_idx(data, KHULNASOFT_FS_MAX_BINS_POS);
    khulnasoft_ext4_store_bin(bin, KHULNASOFT_KEY_CALLS_OPEN);

    return 0;
}

SEC("kretprobe/ext4_sync_file")
int khulnasoft_ret_ext4_sync_file(struct pt_regs *ctx) 
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 bin, pid = (__u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tmp_ext4, &pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_ext4, &pid);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;
    bin = libkhulnasoft_select_idx(data, KHULNASOFT_FS_MAX_BINS_POS);
    khulnasoft_ext4_store_bin(bin, KHULNASOFT_KEY_CALLS_SYNC);

    return 0;
}

char _license[] SEC("license") = "GPL";

