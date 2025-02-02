#define KBUILD_MODNAME "fd_kern"
#include <linux/version.h>
#include <linux/sched.h>
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,10,17))
# include <linux/sched/task.h>
#endif

#include <linux/threads.h>
#include <linux/version.h>

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
 *                                 MAPS Section
 *     
 ***********************************************************************************/

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct khulnasoft_fd_stat_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} tbl_fd_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_FD_COUNTER);
} tbl_fd_global SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_CONTROLLER_END);
} fd_ctrl SEC(".maps");

#else

struct bpf_map_def SEC("maps") tbl_fd_pid = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct khulnasoft_fd_stat_t),
    .max_entries = PID_MAX_DEFAULT
};

struct bpf_map_def SEC("maps") tbl_fd_global = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries =  KHULNASOFT_FD_COUNTER
};

struct bpf_map_def SEC("maps") fd_ctrl = {
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

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(5,5,19))
#if KHULNASOFTSEL < 2
SEC("kretprobe/do_sys_open")
#else
SEC("kprobe/do_sys_open")
#endif
#else
#if KHULNASOFTSEL < 2
SEC("kretprobe/do_sys_openat2")
#else
SEC("kprobe/do_sys_openat2")
#endif // Endif KHULNASOFTSEL
#endif //ENDIF KERNEL VERSION
int khulnasoft_sys_open(struct pt_regs* ctx)
{
#if KHULNASOFTSEL < 2
    int ret = (ssize_t)PT_REGS_RC(ctx);
#endif
    struct khulnasoft_fd_stat_t *fill;
    struct khulnasoft_fd_stat_t data = { };

    libkhulnasoft_update_global(&tbl_fd_global, KHULNASOFT_KEY_CALLS_DO_SYS_OPEN, 1);
#if KHULNASOFTSEL < 2
    if (ret < 0) {
        libkhulnasoft_update_global(&tbl_fd_global, KHULNASOFT_KEY_ERROR_DO_SYS_OPEN, 1);
    } 
#endif

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&fd_ctrl))
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &fd_ctrl, &tbl_fd_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->open_call, 1) ;

#if KHULNASOFTSEL < 2
        if (ret < 0) {
            libkhulnasoft_update_u32(&fill->open_err, 1) ;
        } 
#endif
    } else {
        data.ct = bpf_ktime_get_ns();
        libkhulnasoft_update_uid_gid(&data.uid, &data.gid);
        data.tgid = tgid;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
#else
        data.name[0] = '\0';
#endif

#if KHULNASOFTSEL < 2
        if (ret < 0) {
            data.open_err = 1;
        } else {
#endif
            data.open_err = 0;
#if KHULNASOFTSEL < 2
        }
#endif
        data.open_call = 1;

        bpf_map_update_elem(&tbl_fd_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&fd_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)) 
# if KHULNASOFTSEL < 2
SEC("kretprobe/close_fd")
# else
SEC("kprobe/close_fd")
# endif /* KHULNASOFTSEL < 2 */
#else /* KERNEL > 5.11 */
# if KHULNASOFTSEL < 2
#  if defined(RHEL_MAJOR) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)) && (LINUX_VERSION_CODE <= KERNEL_VERSION(4,19,0))
SEC("kretprobe/close_fd")
#  else /* RHEL_MAJOR */
SEC("kretprobe/__close_fd")
#  endif /* RHEL_MAJOR */
# else /* KHULNASOFTSEL < 2 */
#  if defined(RHEL_MAJOR) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)) && (LINUX_VERSION_CODE <= KERNEL_VERSION(4,19,0))
SEC("kprobe/close_fd")
#  else /* RHEL_MAJOR */
SEC("kprobe/__close_fd")
#  endif /* RHEL_MAJOR */
# endif /* KHULNASOFTSEL < 2 */
#endif /* KERNEL > 5.11 */
int khulnasoft_close(struct pt_regs* ctx)
{
#if KHULNASOFTSEL < 2
    int ret = (int)PT_REGS_RC(ctx);
#endif
    struct khulnasoft_fd_stat_t data = { };
    struct khulnasoft_fd_stat_t *fill;

    libkhulnasoft_update_global(&tbl_fd_global, KHULNASOFT_KEY_CALLS_CLOSE_FD, 1);
#if KHULNASOFTSEL < 2
    if (ret < 0) {
        libkhulnasoft_update_global(&tbl_fd_global, KHULNASOFT_KEY_ERROR_CLOSE_FD, 1);
    } 
#endif

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&fd_ctrl))
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &fd_ctrl, &tbl_fd_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->close_call, 1) ;

#if KHULNASOFTSEL < 2
        if (ret < 0) {
            libkhulnasoft_update_u32(&fill->close_err, 1) ;
        } 
#endif
    } else {
        data.ct = bpf_ktime_get_ns();
        libkhulnasoft_update_uid_gid(&data.uid, &data.gid);
        data.tgid = tgid;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
#else
        data.name[0] = '\0';
#endif

        data.close_call = 1;
#if KHULNASOFTSEL < 2
        if (ret < 0) {
            data.close_err = 1;
        } 
#endif

        bpf_map_update_elem(&tbl_fd_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&fd_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

