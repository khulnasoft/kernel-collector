#define KBUILD_MODNAME "vfs_kern"
#include <linux/version.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,10,17))
# include <linux/sched/task.h>
#endif

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
 *                                 MAPS Section
 *     
 ***********************************************************************************/

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct khulnasoft_vfs_stat_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} tbl_vfs_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_VFS_COUNTER);
} tbl_vfs_stats  SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_CONTROLLER_END);
} vfs_ctrl SEC(".maps");
#else
struct bpf_map_def SEC("maps") tbl_vfs_pid = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct khulnasoft_vfs_stat_t),
    .max_entries = PID_MAX_DEFAULT
};

struct bpf_map_def SEC("maps") tbl_vfs_stats = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries =  KHULNASOFT_VFS_COUNTER
};

struct bpf_map_def SEC("maps") vfs_ctrl = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = KHULNASOFT_CONTROLLER_END
};
#endif

/************************************************************************************
 *     
 *                                   FILE Section
 *     
 ***********************************************************************************/

#if KHULNASOFTSEL < 2
SEC("kretprobe/vfs_write")
#else
SEC("kprobe/vfs_write")
#endif
int khulnasoft_sys_write(struct pt_regs* ctx)
{
    ssize_t ret;
#if KHULNASOFTSEL < 2
    ret = (ssize_t)PT_REGS_RC(ctx);
#endif
    struct khulnasoft_vfs_stat_t *fill;
    struct khulnasoft_vfs_stat_t data = { };
    __u64 tot;

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&vfs_ctrl))
        return 0;

    libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_CALLS_VFS_WRITE, 1);
#if KHULNASOFTSEL < 2
    if (ret < 0) {
        libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_ERROR_VFS_WRITE, 1);
    }
#endif

    ret = (ssize_t)PT_REGS_PARM3(ctx);
    tot = libkhulnasoft_log2l(ret);
    libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_BYTES_VFS_WRITE, tot);

    fill = khulnasoft_get_pid_structure(&key, &tgid, &vfs_ctrl, &tbl_vfs_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->write_call, 1) ;

#if KHULNASOFTSEL < 2
        if (ret < 0) {
            libkhulnasoft_update_u32(&fill->write_err, 1) ;
        } else {
#endif
            libkhulnasoft_update_u64(&fill->write_bytes, tot);
#if KHULNASOFTSEL < 2
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
            data.write_err = 1;
        } else {
#endif
            data.write_bytes = tot;
#if KHULNASOFTSEL < 2
        }
#endif
        data.write_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&vfs_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

#if KHULNASOFTSEL < 2
SEC("kretprobe/vfs_writev")
#else
SEC("kprobe/vfs_writev")
#endif
int khulnasoft_sys_writev(struct pt_regs* ctx)
{
    ssize_t ret;
#if KHULNASOFTSEL < 2
    ret = (ssize_t)PT_REGS_RC(ctx);
#endif
    struct khulnasoft_vfs_stat_t *fill;
    struct khulnasoft_vfs_stat_t data = { };
    __u64 tot;

    libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_CALLS_VFS_WRITEV, 1);

#if KHULNASOFTSEL < 2
    if (ret < 0) {
        libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_ERROR_VFS_WRITEV, 1);
    }
#endif

    ret = (ssize_t)PT_REGS_PARM3(ctx);
    tot = libkhulnasoft_log2l(ret);
    libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_BYTES_VFS_WRITEV, tot);

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&vfs_ctrl))
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &vfs_ctrl, &tbl_vfs_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->writev_call, 1) ;

#if KHULNASOFTSEL < 2
        if (ret < 0) {
            libkhulnasoft_update_u32(&fill->writev_err, 1) ;
        } else {
#endif
            libkhulnasoft_update_u64(&fill->writev_bytes, tot);
#if KHULNASOFTSEL < 2
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
            data.writev_err = 1;
        } else {
#endif
            data.writev_bytes = (unsigned long)tot;
#if KHULNASOFTSEL < 2
        }
#endif
        data.writev_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&vfs_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

#if KHULNASOFTSEL < 2
SEC("kretprobe/vfs_read")
#else
SEC("kprobe/vfs_read")
#endif
int khulnasoft_sys_read(struct pt_regs* ctx)
{
    ssize_t ret;
#if KHULNASOFTSEL < 2
    ret = (ssize_t)PT_REGS_RC(ctx);
#endif
    struct khulnasoft_vfs_stat_t *fill;
    struct khulnasoft_vfs_stat_t data = { };
    __u64 tot;

    libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_CALLS_VFS_READ, 1);

#if KHULNASOFTSEL < 2
    if (ret < 0) {
        libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_ERROR_VFS_READ, 1);
    }
#endif

    ret = (ssize_t)PT_REGS_PARM3(ctx);
    tot = libkhulnasoft_log2l(ret);
    libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_BYTES_VFS_READ, tot);

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&vfs_ctrl))
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &vfs_ctrl, &tbl_vfs_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->read_call, 1) ;

#if KHULNASOFTSEL < 2
        if (ret < 0) {
            libkhulnasoft_update_u32(&fill->read_err, 1) ;
        } else {
#endif
            libkhulnasoft_update_u64(&fill->read_bytes, tot);
#if KHULNASOFTSEL < 2
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
            data.read_err = 1;
        } else {
#endif
            data.read_bytes = (unsigned long)tot;
#if KHULNASOFTSEL < 2
        }
#endif
        data.read_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&vfs_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

#if KHULNASOFTSEL < 2
SEC("kretprobe/vfs_readv")
#else
SEC("kprobe/vfs_readv")
#endif
int khulnasoft_sys_readv(struct pt_regs* ctx)
{
    ssize_t ret;
#if KHULNASOFTSEL < 2
    ret = (ssize_t)PT_REGS_RC(ctx);
#endif
    struct khulnasoft_vfs_stat_t *fill;
    struct khulnasoft_vfs_stat_t data = { };
    __u64 tot;

    libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_CALLS_VFS_READV, 1);

#if KHULNASOFTSEL < 2
    if (ret < 0) {
        libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_ERROR_VFS_READV, 1);
    }
#endif

    ret = (ssize_t)PT_REGS_PARM3(ctx);
    tot = libkhulnasoft_log2l(ret);
    libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_BYTES_VFS_READV, tot);

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&vfs_ctrl))
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &vfs_ctrl, &tbl_vfs_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->readv_call, 1) ;

#if KHULNASOFTSEL < 2
        if (ret < 0) {
            libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_ERROR_VFS_READV, 1);
            libkhulnasoft_update_u32(&fill->readv_err, 1) ;
        } else {
#endif
            libkhulnasoft_update_u64(&fill->readv_bytes, tot);
#if KHULNASOFTSEL < 2
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
            data.readv_err = 1;
        } else {
#endif
            data.readv_bytes = (unsigned long)tot;
#if KHULNASOFTSEL < 2
        }
#endif
        data.readv_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&vfs_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

#if KHULNASOFTSEL < 2
SEC("kretprobe/vfs_unlink")
#else
SEC("kprobe/vfs_unlink")
#endif
int khulnasoft_sys_unlink(struct pt_regs* ctx)
{
#if KHULNASOFTSEL < 2
    int ret = (int)PT_REGS_RC(ctx);
#endif
    struct khulnasoft_vfs_stat_t data = { };
    struct khulnasoft_vfs_stat_t *fill;

    libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_CALLS_VFS_UNLINK, 1);

#if KHULNASOFTSEL < 2
    if (ret < 0) {
        libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_ERROR_VFS_UNLINK, 1);
    } 
#endif

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&vfs_ctrl))
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &vfs_ctrl, &tbl_vfs_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->unlink_call, 1) ;

#if KHULNASOFTSEL < 2
        if (ret < 0) {
            libkhulnasoft_update_u32(&fill->unlink_err, 1) ;
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
            data.unlink_err = 1;
        } else {
#endif
            data.unlink_err = 0;
#if KHULNASOFTSEL < 2
        }
#endif
        data.unlink_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&vfs_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

#if KHULNASOFTSEL < 2
SEC("kretprobe/vfs_fsync")
#else
SEC("kprobe/vfs_fsync")
#endif
int khulnasoft_vfs_fsync(struct pt_regs* ctx)
{
#if KHULNASOFTSEL < 2
    int ret = (int)PT_REGS_RC(ctx);
#endif
    struct khulnasoft_vfs_stat_t data = { };
    struct khulnasoft_vfs_stat_t *fill;

    libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_CALLS_VFS_FSYNC, 1);

#if KHULNASOFTSEL < 2
    if (ret < 0) {
        libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_ERROR_VFS_FSYNC, 1);
    } 
#endif

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&vfs_ctrl))
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &vfs_ctrl, &tbl_vfs_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->fsync_call, 1) ;

#if KHULNASOFTSEL < 2
        if (ret < 0) {
            libkhulnasoft_update_u32(&fill->fsync_err, 1) ;
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
            data.fsync_err = 1;
        } else {
#endif
            data.fsync_err = 0;
#if KHULNASOFTSEL < 2
        }
#endif
        data.fsync_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&vfs_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

#if KHULNASOFTSEL < 2
SEC("kretprobe/vfs_open")
#else
SEC("kprobe/vfs_open")
#endif
int khulnasoft_vfs_open(struct pt_regs* ctx)
{
#if KHULNASOFTSEL < 2
    int ret = (int)PT_REGS_RC(ctx);
#endif
    struct khulnasoft_vfs_stat_t data = { };
    struct khulnasoft_vfs_stat_t *fill;

    libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_CALLS_VFS_OPEN, 1);
    
#if KHULNASOFTSEL < 2
    if (ret < 0) {
        libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_ERROR_VFS_OPEN, 1);
    } 
#endif

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&vfs_ctrl))
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &vfs_ctrl, &tbl_vfs_pid);
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

        bpf_map_update_elem(&tbl_vfs_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&vfs_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

#if KHULNASOFTSEL < 2
SEC("kretprobe/vfs_create")
#else
SEC("kprobe/vfs_create")
#endif
int khulnasoft_vfs_create(struct pt_regs* ctx)
{
#if KHULNASOFTSEL < 2
    int ret = (int)PT_REGS_RC(ctx);
#endif
    struct khulnasoft_vfs_stat_t data = { };
    struct khulnasoft_vfs_stat_t *fill;

    libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_CALLS_VFS_CREATE, 1);

#if KHULNASOFTSEL < 2
    if (ret < 0) {
        libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_ERROR_VFS_CREATE, 1);
    } 
#endif

    __u32 key = 0;
    __u32 tgid = 0;
    if (!monitor_apps(&vfs_ctrl))
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &vfs_ctrl, &tbl_vfs_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->create_call, 1) ;

#if KHULNASOFTSEL < 2
        if (ret < 0) {
            libkhulnasoft_update_u32(&fill->create_err, 1) ;
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
            data.create_err = 1;
        } else {
#endif
            data.create_err = 0;
#if KHULNASOFTSEL < 2
        }
#endif
        data.create_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&vfs_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

