#define KBUILD_MODNAME "fsync_khulnasoft"

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
} tbl_fsync SEC(".maps");
#else
struct bpf_map_def SEC("maps") tbl_fsync = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = KHULNASOFT_SYNC_END
};
#endif

/************************************************************************************
 *
 *                               FSYNC SECTION
 *
 ***********************************************************************************/

#if defined(LIBBPF_MAJOR_VERSION) && (LIBBPF_MAJOR_VERSION >= 1)
SEC("ksyscall/fsync")
#else
SEC("kprobe/" KHULNASOFT_SYSCALL(fsync))
#endif
int khulnasoft_syscall_sync(struct pt_regs* ctx)
{
    libkhulnasoft_update_global(&tbl_fsync, KHULNASOFT_KEY_SYNC_CALL, 1);

    return 0;
}

/************************************************************************************
 *
 *                             END FSYNC SECTION
 *
 ***********************************************************************************/

