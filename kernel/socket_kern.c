#define KBUILD_MODNAME "socket_khulnasoft"
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_vlan.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <uapi/linux/bpf.h>
#else
#include <linux/bpf.h>
#endif
#include "bpf_tracing.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "khulnasoft_ebpf.h"

/************************************************************************************
 *
 *                              Hash Table Section
 *
 ***********************************************************************************/

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_SOCKET_COUNTER);
} tbl_global_sock SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, khulnasoft_socket_idx_t);
    __type(value, khulnasoft_socket_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} tbl_nd_socket SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u64);
    __type(value, void *);
    __uint(max_entries, 4096);
} tbl_nv_udp SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, khulnasoft_passive_connection_idx_t);
    __type(value, khulnasoft_passive_connection_t);
    __uint(max_entries, 1024);
} tbl_lports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_CONTROLLER_END);
} socket_ctrl SEC(".maps");

#else
struct bpf_map_def SEC("maps") tbl_global_sock = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries =  KHULNASOFT_SOCKET_COUNTER
};

struct bpf_map_def SEC("maps") tbl_nd_socket = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(khulnasoft_socket_idx_t),
    .value_size = sizeof(khulnasoft_socket_t),
    .max_entries =  PID_MAX_DEFAULT,
};

struct bpf_map_def SEC("maps") tbl_nv_udp = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(void *),
    .max_entries = 4096
};

struct bpf_map_def SEC("maps") tbl_lports = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(khulnasoft_passive_connection_idx_t),
    .value_size = sizeof(khulnasoft_passive_connection_t),
    .max_entries =  1024
};

struct bpf_map_def SEC("maps") socket_ctrl = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = KHULNASOFT_CONTROLLER_END
};

#endif

/************************************************************************************
 *
 *                                 Common Section
 *
 ***********************************************************************************/

static __always_inline __u16 set_idx_value(khulnasoft_socket_idx_t *nsi, struct inet_sock *is)
{
    __u16 family;

    // Read Family
    bpf_probe_read(&family, sizeof(u16), &is->sk.__sk_common.skc_family);
    // Read source and destination IPs
    if ( family == AF_INET ) { //AF_INET
        // bpf_probe_read(&nsi->saddr.addr32[0], sizeof(u32), &is->inet_rcv_saddr); // bind to local address
        bpf_probe_read(&nsi->saddr.addr32[0], sizeof(u32), &is->inet_saddr);
        bpf_probe_read(&nsi->daddr.addr32[0], sizeof(u32), &is->inet_daddr);

        if ((nsi->saddr.addr32[0] == 16777343 || nsi->daddr.addr32[0] == 16777343) || // Loopback
            (nsi->saddr.addr32[0] == 0 || nsi->daddr.addr32[0] == 0)) // Zero
            return AF_UNSPEC;
    }
    // Check necessary according https://elixir.bootlin.com/linux/v5.6.14/source/include/net/sock.h#L199
#if IS_ENABLED(CONFIG_IPV6)
    else if ( family == AF_INET6 ) {
        // struct in6_addr *addr6 = &is->sk.sk_v6_rcv_saddr; // bind to local address
        struct in6_addr *addr6 = &is->sk.__sk_common.skc_v6_rcv_saddr.s6_addr;
        bpf_probe_read(&nsi->saddr.addr8,  sizeof(__u8)*16, &addr6->s6_addr);

        addr6 = &is->sk.__sk_common.skc_v6_daddr.s6_addr;
        bpf_probe_read(&nsi->daddr.addr8,  sizeof(__u8)*16, &addr6->s6_addr);

        if (((nsi->saddr.addr64[0] == 0) && (nsi->saddr.addr64[1] == 72057594037927936)) ||  // Loopback
            ((nsi->daddr.addr64[0] == 0) && (nsi->daddr.addr64[1] == 72057594037927936)))
            return AF_UNSPEC;

        if (((nsi->saddr.addr64[0] == 0) && (nsi->saddr.addr64[1] == 0)) ||
            ((nsi->daddr.addr64[0] == 0) && (nsi->daddr.addr64[1] == 0))) // Zero addr
            return AF_UNSPEC;
    }
#endif
    else {
        return AF_UNSPEC;
    }

    //Read destination port
    bpf_probe_read(&nsi->dport, sizeof(u16), &is->inet_dport);
 //   bpf_probe_read(&nsi->sport, sizeof(u16), &is->inet_num);

    // Socket for nowhere or system looking for port
    // This can be an attack vector that needs to be addressed in another opportunity
    //if (nsi->sport == 0 || nsi->dport == 0)
    if (nsi->dport == 0)
        return AF_UNSPEC;


    __u32 tgid = 0;
    nsi->pid = khulnasoft_get_pid(&socket_ctrl, &tgid);

    return family;
}

// Update time and bytes sent and received
static __always_inline void update_socket_stats(khulnasoft_socket_t *ptr,
                                                __u64 sent,
                                                __u64 received,
                                                __u32 retransmitted,
                                                __u16 protocol)
{
    ptr->ct = bpf_ktime_get_ns();

    if (sent) {
        if (protocol == IPPROTO_TCP) {
            libkhulnasoft_update_u32(&ptr->tcp.call_tcp_sent, 1);
            libkhulnasoft_update_u64(&ptr->tcp.tcp_bytes_sent, sent);

            libkhulnasoft_update_u32(&ptr->tcp.retransmit, retransmitted);
        } else {
            libkhulnasoft_update_u32(&ptr->udp.call_udp_sent, 1);
            libkhulnasoft_update_u64(&ptr->udp.udp_bytes_sent, sent);
        }
    }

    if (received) {
        if (protocol == IPPROTO_TCP) {
            libkhulnasoft_update_u32(&ptr->tcp.call_tcp_received, 1);
            libkhulnasoft_update_u64(&ptr->tcp.tcp_bytes_received, received);
        } else {
            libkhulnasoft_update_u32(&ptr->udp.call_udp_received, 1);
            libkhulnasoft_update_u64(&ptr->udp.udp_bytes_received, received);
        }
    }
}

static __always_inline void update_socket_common(khulnasoft_socket_t *data, __u16 protocol, __u16 family)
{
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
    bpf_get_current_comm(&data->name, TASK_COMM_LEN);
#else
    data->name[0] = '\0';
#endif

    data->first = bpf_ktime_get_ns();
    data->protocol = protocol;
    data->family = family;
}


// Use __always_inline instead inline to keep compatiblity with old kernels
// https://docs.cilium.io/en/v1.8/bpf/
static __always_inline  void update_socket_table(struct pt_regs* ctx,
                                                __u64 sent,
                                                __u64 received,
                                                __u32 retransmitted,
                                                __u16 protocol,
                                                __u32 state)
{
    __u16 family;
    struct inet_sock *is = inet_sk((struct sock *)PT_REGS_PARM1(ctx));
    khulnasoft_socket_idx_t idx = { };

    // Safety condition
    if (!is)
        return;

    family = set_idx_value(&idx, is);
    if (family == AF_UNSPEC)
        return;

    khulnasoft_socket_t *val;
    khulnasoft_socket_t data = { };

    val = (khulnasoft_socket_t *) bpf_map_lookup_elem(&tbl_nd_socket, &idx);
    if (val) {
        update_socket_stats(val, sent, received, retransmitted, protocol);
        val->tcp.state = state;
    } else {
        update_socket_common(&data, protocol, family);
        data.tcp.state = state;
        update_socket_stats(&data, sent, received, retransmitted, protocol);

        libkhulnasoft_update_global(&socket_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);

        bpf_map_update_elem(&tbl_nd_socket, &idx, &data, BPF_ANY);
    }
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0))
static __always_inline u8 select_protocol(struct sock *sk)
{
    u8 protocol = 0;

    int gso_max_segs_offset = offsetof(struct sock, sk_gso_max_segs);
    int sk_lingertime_offset = offsetof(struct sock, sk_lingertime);

    if (sk_lingertime_offset - gso_max_segs_offset == 4)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        bpf_probe_read(&protocol, sizeof(u8), (void *)((long)&sk->sk_gso_max_segs) - 3);
    else
        bpf_probe_read(&protocol, sizeof(u8), (void *)((long)&sk->sk_wmem_queued) - 3);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        bpf_probe_read(&protocol, sizeof(u8), (void *)((long)&sk->sk_gso_max_segs) - 1);
    else
        bpf_probe_read(&protocol, sizeof(u8), (void *)((long)&sk->sk_wmem_queued) - 1);
#endif

    return protocol;
}
#endif // Kernel version 5.6.0

static __always_inline void update_pid_connection(struct pt_regs* ctx)
{
    khulnasoft_socket_idx_t idx = { };

    khulnasoft_socket_t *stored;
    khulnasoft_socket_t data = { };

    struct inet_sock *is = inet_sk((struct sock *)PT_REGS_PARM1(ctx));

    __u16 family = set_idx_value(&idx, is);
    if (family == AF_UNSPEC)
        return;

    stored = (khulnasoft_socket_t *) bpf_map_lookup_elem(&tbl_nd_socket, &idx);
    if (stored) {
        stored->ct = bpf_ktime_get_ns();

        if (family == AF_INET)
            libkhulnasoft_update_u32(&stored->tcp.ipv4_connect, 1);
        else
            libkhulnasoft_update_u32(&stored->tcp.ipv6_connect, 1);
    } else {
        update_socket_common(&data, IPPROTO_TCP, family);
        if (family == AF_INET)
            data.tcp.ipv4_connect = 1;
        else
            data.tcp.ipv6_connect = 1;

        bpf_map_update_elem(&tbl_nd_socket, &idx, &data, BPF_ANY);

        libkhulnasoft_update_global(&socket_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }
}

/************************************************************************************
 *
 *                                 General Socket Section
 *
 ***********************************************************************************/

SEC("kretprobe/inet_csk_accept")
int khulnasoft_inet_csk_accept(struct pt_regs* ctx)
{
    khulnasoft_passive_connection_t data = { };
    khulnasoft_passive_connection_idx_t idx = { };
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    u16 protocol;
    if (!sk)
        return 0;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0))
    protocol = 0;
    bpf_probe_read(&protocol, sizeof(u16), &sk->sk_protocol);
#else
    protocol = (u16) select_protocol(sk);
#endif

    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
        return 0;

    idx.protocol = protocol;
    bpf_probe_read(&idx.port, sizeof(u16), &sk->__sk_common.skc_num);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)pid_tgid >>32;
    __u32 pid = (__u32)pid_tgid;

    khulnasoft_passive_connection_t *value = (khulnasoft_passive_connection_t *)bpf_map_lookup_elem(&tbl_lports, &idx);
    if (value) {
        // Update PID, because process can die.
        value->tgid = tgid;
        value->pid = pid;
        libkhulnasoft_update_u64(&value->counter, 1);
    } else {
        data.tgid = tgid;
        data.pid = pid;
        data.counter = 1;
        bpf_map_update_elem(&tbl_lports, &idx, &data, BPF_ANY);

        libkhulnasoft_update_global(&socket_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    struct inet_sock *is = inet_sk(sk);
    khulnasoft_socket_idx_t nv_idx = { };
    __u16 family = set_idx_value(&nv_idx, is);
    if (family == AF_UNSPEC)
        return 0;

    khulnasoft_socket_t *val;
    khulnasoft_socket_t nv_data = { };

    val = (khulnasoft_socket_t *) bpf_map_lookup_elem(&tbl_nd_socket, &nv_idx);
    if (val) {
        libkhulnasoft_update_u32(&val->external_origin, 1);
    } else {
        update_socket_common(&nv_data, protocol, family);
        nv_data.external_origin = 1;

        bpf_map_update_elem(&tbl_nd_socket, &nv_idx, &nv_data, BPF_ANY);
    }

    return 0;
}

/************************************************************************************
 *
 *                                 TCP Section
 *
 ***********************************************************************************/

#if KHULNASOFTSEL < 2
SEC("kretprobe/tcp_sendmsg")
#else
SEC("kprobe/tcp_sendmsg")
#endif
int khulnasoft_tcp_sendmsg(struct pt_regs* ctx)
{
    libkhulnasoft_update_global(&tbl_global_sock, KHULNASOFT_KEY_CALLS_TCP_SENDMSG, 1);

    size_t sent;
#if KHULNASOFTSEL < 2
    int ret = (int)PT_REGS_RC(ctx);
    if (ret < 0) {
        libkhulnasoft_update_global(&tbl_global_sock, KHULNASOFT_KEY_ERROR_TCP_SENDMSG, 1);
        return 0;
    }

    sent = (size_t) ret;
#else
    sent = (size_t)PT_REGS_PARM3(ctx);
#endif

    libkhulnasoft_update_global(&tbl_global_sock, KHULNASOFT_KEY_BYTES_TCP_SENDMSG, sent);

    update_socket_table(ctx, sent, 0, 0, IPPROTO_TCP, 0);

    return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int khulnasoft_tcp_retransmit_skb(struct pt_regs* ctx)
{
    libkhulnasoft_update_global(&tbl_global_sock, KHULNASOFT_KEY_TCP_RETRANSMIT, 1);

    update_socket_table(ctx, 0, 0, 1, IPPROTO_TCP, 0);

    return 0;
}

SEC("kprobe/tcp_set_state")
int khulnasoft_tcp_set_state(struct pt_regs* ctx)
{
    libkhulnasoft_update_global(&tbl_global_sock, KHULNASOFT_KEY_CALLS_TCP_SET_STATE, 1);
    int state = PT_REGS_PARM2(ctx);

    update_socket_table(ctx, 0, 0, 1, IPPROTO_TCP, state);

    return 0;
}

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/tcp.c#L1528
SEC("kprobe/tcp_cleanup_rbuf")
int khulnasoft_tcp_cleanup_rbuf(struct pt_regs* ctx)
{
    libkhulnasoft_update_global(&tbl_global_sock, KHULNASOFT_KEY_CALLS_TCP_CLEANUP_RBUF, 1);

    int copied = (int)PT_REGS_PARM2(ctx);
    if (copied < 0) {
        libkhulnasoft_update_global(&tbl_global_sock, KHULNASOFT_KEY_ERROR_TCP_CLEANUP_RBUF, 1);
        return 0;
    }

    __u64 received = (__u64) PT_REGS_PARM2(ctx);
    libkhulnasoft_update_global(&tbl_global_sock, KHULNASOFT_KEY_BYTES_TCP_CLEANUP_RBUF, received);

    update_socket_table(ctx, 0, (__u64)copied, 1, IPPROTO_TCP, 0);

    return 0;
}

SEC("kprobe/tcp_close")
int khulnasoft_tcp_close(struct pt_regs* ctx)
{
    libkhulnasoft_update_global(&tbl_global_sock, KHULNASOFT_KEY_CALLS_TCP_CLOSE, 1);
    struct inet_sock *is = inet_sk((struct sock *)PT_REGS_PARM1(ctx));
    // Safety test only, in theory this is unecessary
    if (!is)
        return 0;

    khulnasoft_socket_idx_t idx = { };
    __u16 family = set_idx_value(&idx, is);
    if (family == AF_UNSPEC)
        return 0;

    khulnasoft_socket_t *val = (khulnasoft_socket_t *) bpf_map_lookup_elem(&tbl_nd_socket, &idx);
    if (val) {
        libkhulnasoft_update_u32(&val->tcp.close, 1);
    }

    return 0;
}

#if KHULNASOFTSEL < 2
SEC("kretprobe/tcp_v4_connect")
#else
SEC("kprobe/tcp_v4_connect")
#endif
int khulnasoft_tcp_v4_connect(struct pt_regs* ctx)
{
    libkhulnasoft_update_global(&tbl_global_sock, KHULNASOFT_KEY_CALLS_TCP_CONNECT_IPV4, 1);

#if KHULNASOFTSEL < 2
    int ret = (int)PT_REGS_RC(ctx);
    if (ret < 0) {
        libkhulnasoft_update_global(&tbl_global_sock, KHULNASOFT_KEY_ERROR_TCP_CONNECT_IPV4, 1);
        return 0;
    }
#endif

    update_pid_connection(ctx);

    return 0;
}

#if KHULNASOFTSEL < 2
SEC("kretprobe/tcp_v6_connect")
#else
SEC("kprobe/tcp_v6_connect")
#endif
int khulnasoft_tcp_v6_connect(struct pt_regs* ctx)
{
    libkhulnasoft_update_global(&tbl_global_sock, KHULNASOFT_KEY_CALLS_TCP_CONNECT_IPV6, 1);
#if KHULNASOFTSEL < 2
    int ret = (int)PT_REGS_RC(ctx);
    if (ret < 0) {
        libkhulnasoft_update_global(&tbl_global_sock, KHULNASOFT_KEY_ERROR_TCP_CONNECT_IPV6, 1);
        return 0;
    }
#endif

    update_pid_connection(ctx);

    return 0;
}

/************************************************************************************
 *
 *                                 UDP Section
 *
 ***********************************************************************************/

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/udp.c#L1726
SEC("kprobe/udp_recvmsg")
int trace_udp_recvmsg(struct pt_regs* ctx)
{
    libkhulnasoft_update_global(&tbl_global_sock, KHULNASOFT_KEY_CALLS_UDP_RECVMSG, 1);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock *sk = (struct sock*)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    bpf_map_update_elem(&tbl_nv_udp, &pid_tgid, &sk, BPF_ANY);

    return 0;
}

SEC("kretprobe/udp_recvmsg")
int trace_udp_ret_recvmsg(struct pt_regs* ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skpp = bpf_map_lookup_elem(&tbl_nv_udp, &pid_tgid);
    if (skpp == 0)
        return 0;

    bpf_map_delete_elem(&tbl_nv_udp, &pid_tgid);
    __u64 received = (__u64) PT_REGS_RC(ctx);

    libkhulnasoft_update_global(&tbl_global_sock, KHULNASOFT_KEY_BYTES_UDP_RECVMSG, received);

    update_socket_table(ctx, 0, received, 0, IPPROTO_UDP, 0);

    return 0;
}

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/udp.c#L965
#if KHULNASOFTSEL < 2
SEC("kretprobe/udp_sendmsg")
#else
SEC("kprobe/udp_sendmsg")
#endif
int trace_udp_sendmsg(struct pt_regs* ctx)
{
    libkhulnasoft_update_global(&tbl_global_sock, KHULNASOFT_KEY_CALLS_UDP_SENDMSG, 1);

    size_t sent;
#if KHULNASOFTSEL < 2
    int ret = (int)PT_REGS_RC(ctx);
    if (ret < 0) {
        libkhulnasoft_update_global(&tbl_global_sock, KHULNASOFT_KEY_ERROR_UDP_SENDMSG, 1);
        sent = 0;
    } else
        sent = (size_t)ret;
#else
    sent = (size_t)PT_REGS_PARM3(ctx);
#endif

    libkhulnasoft_update_global(&tbl_global_sock, KHULNASOFT_KEY_BYTES_UDP_SENDMSG, (__u64) sent);

    update_socket_table(ctx, sent, 0, 0, IPPROTO_UDP, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";

