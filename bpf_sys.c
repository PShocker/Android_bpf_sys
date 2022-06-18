#include <linux/bpf.h>
#include <stdbool.h>
#include <stdint.h>
#include <bpf_helpers.h>

DEFINE_BPF_MAP(sys_enter_map, HASH, int, uint32_t, 1024);

struct syscalls_enter_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

    long id;
    unsigned long args[6];
};

struct task_struct {
	int pid;
	int tgid;
	char comm[16];
	struct task_struct *group_leader;
};


// SEC("raw_syscalls/sys_enter")
DEFINE_BPF_PROG("tracepoint/raw_syscalls/sys_enter", AID_ROOT, AID_NET_ADMIN, sys_enter)
(struct syscalls_enter_args *args)
{
    //获取进程信息
    // struct task_struct *task = (void *)bpf_get_current_task();

    // int key = bpf_get_smp_processor_id();
	int key = bpf_get_current_pid_tgid();//这里是强制取低32位,也就是pid
    uint32_t syscall_id=args->id;

    bpf_sys_enter_map_update_elem(&key, &syscall_id, BPF_ANY);
    return 0;
}

// char _license[] SEC("license") = "GPL";
LICENSE("Apache 2.0");