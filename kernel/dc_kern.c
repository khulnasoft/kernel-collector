#define KBUILD_MODNAME "dc_kern"

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
 *                                   Maps Section
 *
 ***********************************************************************************/

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_DIRECTORY_CACHE_END);
} dcstat_global SEC(".maps");

struct {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    __uint(type, BPF_MAP_TYPE_HASH);
#else
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
#endif
    __type(key, __u32);
    __type(value, khulnasoft_dc_stat_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} dcstat_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_CONTROLLER_END);
} dcstat_ctrl SEC(".maps");

#else

struct bpf_map_def SEC("maps") dcstat_global = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = KHULNASOFT_DIRECTORY_CACHE_END
};

struct bpf_map_def SEC("maps") dcstat_pid = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(khulnasoft_dc_stat_t),
    .max_entries = PID_MAX_DEFAULT
};

struct bpf_map_def SEC("maps") dcstat_ctrl = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = KHULNASOFT_CONTROLLER_END
};

#endif

/************************************************************************************
 *
 *                                   Probe Section
 *
 ***********************************************************************************/

SEC("kprobe/lookup_fast")
int khulnasoft_lookup_fast(struct pt_regs* ctx)
{
    khulnasoft_dc_stat_t *fill, data = {};
    libkhulnasoft_update_global(&dcstat_global, KHULNASOFT_KEY_DC_REFERENCE, 1);

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&dcstat_ctrl))
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &dcstat_ctrl, &dcstat_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->references, 1);
    } else {
        data.ct = bpf_ktime_get_ns();
        libkhulnasoft_update_uid_gid(&data.uid, &data.gid);
        data.tgid = tgid;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
#else
        data.name[0] = '\0';
#endif

        data.references = 1;
        bpf_map_update_elem(&dcstat_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&dcstat_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

SEC("kretprobe/d_lookup")
int khulnasoft_d_lookup(struct pt_regs* ctx)
{
    khulnasoft_dc_stat_t *fill, data = {};
    libkhulnasoft_update_global(&dcstat_global, KHULNASOFT_KEY_DC_SLOW, 1);

    int ret = PT_REGS_RC(ctx);

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&dcstat_ctrl))
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &dcstat_ctrl, &dcstat_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->slow, 1);
    } else {
        data.ct = bpf_ktime_get_ns();
        libkhulnasoft_update_uid_gid(&data.uid, &data.gid);
        data.tgid = tgid;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
#else
        data.name[0] = '\0';
#endif

        data.slow = 1;
        bpf_map_update_elem(&dcstat_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&dcstat_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    // file not found
    if (ret == 0) {
        libkhulnasoft_update_global(&dcstat_global, KHULNASOFT_KEY_DC_MISS, 1);
        fill = khulnasoft_get_pid_structure(&key, &tgid, &dcstat_ctrl, &dcstat_pid);
        if (fill) {
            libkhulnasoft_update_u32(&fill->missed, 1);
        }
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

