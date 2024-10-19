#define KBUILD_MODNAME "mount_khulnasoft"

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
    __uint(max_entries, KHULNASOFT_MOUNT_END);
} tbl_mount SEC(".maps");
#else
struct bpf_map_def SEC("maps") tbl_mount = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = KHULNASOFT_MOUNT_END
};
#endif

/************************************************************************************
 *
 *                               MOUNT SECTION
 *
 ***********************************************************************************/

#if defined(LIBBPF_MAJOR_VERSION) && (LIBBPF_MAJOR_VERSION >= 1)
#if KHULNASOFTSEL < 2
SEC("kretsyscall/mount")
#else
SEC("ksyscall/mount")
#endif /* KHULNASOFTSEL < 2 */
#else
#if KHULNASOFTSEL < 2
SEC("kretprobe/" KHULNASOFT_SYSCALL(mount))
#else
SEC("kprobe/" KHULNASOFT_SYSCALL(mount))
#endif /* KHULNASOFTSEL < 2 */
#endif
int khulnasoft_syscall_mount(struct pt_regs* ctx)
{
    libkhulnasoft_update_global(&tbl_mount, KHULNASOFT_KEY_MOUNT_CALL, 1);
#if KHULNASOFTSEL < 2
    int ret = (int)PT_REGS_RC(ctx);
    if (ret < 0)
        libkhulnasoft_update_global(&tbl_mount, KHULNASOFT_KEY_MOUNT_ERROR, 1);
#endif

    return 0;
}

#if defined(LIBBPF_MAJOR_VERSION) && (LIBBPF_MAJOR_VERSION >= 1)
#if KHULNASOFTSEL < 2
SEC("kretsyscall/umount")
#else
SEC("ksyscall/umount")
#endif /* KHULNASOFTSEL < 2 */
#else
#if KHULNASOFTSEL < 2
SEC("kretprobe/" KHULNASOFT_SYSCALL(umount))
#else
SEC("kprobe/" KHULNASOFT_SYSCALL(umount))
#endif /* KHULNASOFTSEL < 2 */
#endif
int khulnasoft_syscall_umount(struct pt_regs* ctx)
{
    libkhulnasoft_update_global(&tbl_mount, KHULNASOFT_KEY_UMOUNT_CALL, 1);
#if KHULNASOFTSEL < 2
    int ret = (int)PT_REGS_RC(ctx);
    if (ret < 0)
        libkhulnasoft_update_global(&tbl_mount, KHULNASOFT_KEY_UMOUNT_ERROR, 1);
#endif

    return 0;
}

/************************************************************************************
 *
 *                             END MOUNT SECTION
 *
 ***********************************************************************************/

char _license[] SEC("license") = "GPL";

