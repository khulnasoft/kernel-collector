#define KBUILD_MODNAME "swap_khulnasoft"

#include <linux/threads.h>

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
 *                                 MAPS
 *     
 ***********************************************************************************/

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_SWAP_END);
} tbl_swap  SEC(".maps");

struct {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    __uint(type, BPF_MAP_TYPE_HASH);
#else
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
#endif
    __type(key, __u32);
    __type(value, khulnasoft_swap_access_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} tbl_pid_swap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_CONTROLLER_END);
} swap_ctrl SEC(".maps");
#else
struct bpf_map_def SEC("maps") tbl_swap = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = KHULNASOFT_SWAP_END
};

struct bpf_map_def SEC("maps") tbl_pid_swap = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(khulnasoft_swap_access_t),
    .max_entries = PID_MAX_DEFAULT
};

struct bpf_map_def SEC("maps") swap_ctrl = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = KHULNASOFT_CONTROLLER_END
};
#endif

/************************************************************************************
 *
 *                               SWAP SECTION
 *
 ***********************************************************************************/

#if (LINUX_VERSION_CODE > KERNEL_VERSION(6,7,255))
SEC("kprobe/swap_read_folio")
#else
SEC("kprobe/swap_readpage")
#endif
int khulnasoft_swap_readpage(struct pt_regs* ctx)
{
    khulnasoft_swap_access_t data = {};

    libkhulnasoft_update_global(&tbl_swap, KHULNASOFT_KEY_SWAP_READPAGE_CALL, 1);

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&swap_ctrl))
        return 0;

    khulnasoft_swap_access_t *fill = khulnasoft_get_pid_structure(&key, &tgid, &swap_ctrl, &tbl_pid_swap);
    if (fill) {
        libkhulnasoft_update_u32(&fill->read, 1);
    } else {
        data.ct = bpf_ktime_get_ns();
        libkhulnasoft_update_uid_gid(&data.uid, &data.gid);
        data.tgid = tgid;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
#else
        data.name[0] = '\0';
#endif

        data.read = 1;
        bpf_map_update_elem(&tbl_pid_swap, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&swap_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

SEC("kprobe/swap_writepage")
int khulnasoft_swap_writepage(struct pt_regs* ctx)
{
    khulnasoft_swap_access_t data = {};

    libkhulnasoft_update_global(&tbl_swap, KHULNASOFT_KEY_SWAP_WRITEPAGE_CALL, 1);

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&swap_ctrl))
        return 0;

    khulnasoft_swap_access_t *fill = khulnasoft_get_pid_structure(&key, &tgid, &swap_ctrl, &tbl_pid_swap);
    if (fill) {
        libkhulnasoft_update_u32(&fill->write, 1);
    } else {
        data.ct = bpf_ktime_get_ns();
        libkhulnasoft_update_uid_gid(&data.uid, &data.gid);
        data.tgid = tgid;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
#else
        data.name[0] = '\0';
#endif

        data.write = 1;
        bpf_map_update_elem(&tbl_pid_swap, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&swap_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

