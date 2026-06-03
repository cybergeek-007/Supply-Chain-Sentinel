#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>

struct event_t {
    u32 pid;
    u32 uid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    char syscall_name[32];
    char path[256];
    u32 dest_ip;
    u16 dest_port;
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    __builtin_memcpy(&event.syscall_name, "openat", 7);
    bpf_probe_read_user_str(&event.path, sizeof(event.path), (void *)args->filename);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    __builtin_memcpy(&event.syscall_name, "execve", 7);
    bpf_probe_read_user_str(&event.path, sizeof(event.path), (void *)args->filename);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

