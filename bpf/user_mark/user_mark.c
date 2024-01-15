// go:build ignore

#include <linux/bpf.h>
#include <linux/socket.h>
#include <asm/socket.h>
#include <bpf/bpf_helpers.h>

SEC("cgroup/sock_create")
int set_user_id_as_so_mark(struct bpf_sock *ctx)
{
    __u32 uid = bpf_get_current_uid_gid();
    ctx->mark = uid;
    return 1;
}

char __license[] SEC("license") = "Dual MIT/GPL";
