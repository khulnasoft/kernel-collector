// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _KHULNASOFT_VFS_H_
#define _KHULNASOFT_VFS_H_ 1

struct khulnasoft_vfs_stat_t {
    __u64 ct;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    char name[TASK_COMM_LEN];

    //Counter
    __u32 write_call;                   
    __u32 writev_call;                   
    __u32 read_call;                    
    __u32 readv_call;                   
    __u32 unlink_call;                  
    __u32 fsync_call;                  
    __u32 open_call;                  
    __u32 create_call;                  

    //Accumulator
    __u64 write_bytes;
    __u64 writev_bytes;
    __u64 readv_bytes;
    __u64 read_bytes;

    //Counter
    __u32 write_err;
    __u32 writev_err;
    __u32 read_err;
    __u32 readv_err;
    __u32 unlink_err;
    __u32 fsync_err;
    __u32 open_err;
    __u32 create_err;
};

enum vfs_counters {
    KHULNASOFT_KEY_CALLS_VFS_WRITE,
    KHULNASOFT_KEY_ERROR_VFS_WRITE,
    KHULNASOFT_KEY_BYTES_VFS_WRITE,

    KHULNASOFT_KEY_CALLS_VFS_WRITEV,
    KHULNASOFT_KEY_ERROR_VFS_WRITEV,
    KHULNASOFT_KEY_BYTES_VFS_WRITEV,

    KHULNASOFT_KEY_CALLS_VFS_READ,
    KHULNASOFT_KEY_ERROR_VFS_READ,
    KHULNASOFT_KEY_BYTES_VFS_READ,

    KHULNASOFT_KEY_CALLS_VFS_READV,
    KHULNASOFT_KEY_ERROR_VFS_READV,
    KHULNASOFT_KEY_BYTES_VFS_READV,

    KHULNASOFT_KEY_CALLS_VFS_UNLINK,
    KHULNASOFT_KEY_ERROR_VFS_UNLINK,

    KHULNASOFT_KEY_CALLS_VFS_FSYNC,
    KHULNASOFT_KEY_ERROR_VFS_FSYNC,

    KHULNASOFT_KEY_CALLS_VFS_OPEN,
    KHULNASOFT_KEY_ERROR_VFS_OPEN,

    KHULNASOFT_KEY_CALLS_VFS_CREATE,
    KHULNASOFT_KEY_ERROR_VFS_CREATE,

    // Keep this as last and don't skip numbers as it is used as element counter
    KHULNASOFT_VFS_COUNTER
};

enum khulnasoft_vfs_calls_name {
    KHULNASOFT_VFS_WRITE,
    KHULNASOFT_VFS_WRITEV,
    KHULNASOFT_VFS_READ,
    KHULNASOFT_VFS_READV,
    KHULNASOFT_VFS_UNLINK,
    KHULNASOFT_VFS_FSYNC,
    KHULNASOFT_VFS_OPEN,
    KHULNASOFT_VFS_CREATE,

    KHULNASOFT_VFS_END_LIST
};

#endif /* _KHULNASOFT_VFS_H_ */

