#define KBUILD_MODNAME "syncfs_khulnasoft"

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
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_SYNC_END);
} tbl_syncfs SEC(".maps");
#else
struct bpf_map_def SEC("maps") tbl_syncfs = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = KHULNASOFT_SYNC_END
};
#endif

/************************************************************************************
 *
 *                               SYNCFS SECTION
 *
 ***********************************************************************************/

#if defined(LIBBPF_MAJOR_VERSION) && (LIBBPF_MAJOR_VERSION >= 1)
SEC("ksyscall/syncfs")
#else
SEC("kprobe/" KHULNASOFT_SYSCALL(syncfs))
#endif
int khulnasoft_syscall_sync(struct pt_regs* ctx)
{
    libkhulnasoft_update_global(&tbl_syncfs, KHULNASOFT_KEY_SYNC_CALL, 1);

    return 0;
}

/************************************************************************************
 *
 *                             END SYNCFS SECTION
 *
 ***********************************************************************************/

char _license[] SEC("license") = "GPL";

