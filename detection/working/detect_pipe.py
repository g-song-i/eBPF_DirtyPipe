from bcc import BPF
from time import sleep

bpf_source = """ 
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct fd_array_t {
    int fds[2];
    int __user *fildes;
};

struct event_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    int fd0;
    int fd1;
    int can_merge;
    int write;
    int read;
};

BPF_HASH(fd_store, u32, struct fd_array_t);
BPF_HASH(event_store, u32, struct event_t);
BPF_PERF_OUTPUT(events);

int kprobe__do_pipe2(struct pt_regs *ctx, int __user *fildes, int flags) {
    struct fd_array_t fd_array = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    fd_array.fildes = fildes;
    bpf_probe_read_user(&fd_array.fds, sizeof(fd_array.fds), fildes);
    fd_store.update(&pid, &fd_array);

    return 0;
}

int kretprobe__do_pipe2(struct pt_regs *ctx) {
    struct event_t event = {};
    struct fd_array_t *fd_array;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.pid = task->tgid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    fd_array = fd_store.lookup(&pid);
    if (fd_array) {
        bpf_probe_read_user(&fd_array->fds, sizeof(fd_array->fds), fd_array->fildes);
        event.fd0 = fd_array->fds[0];
        event.fd1 = fd_array->fds[1];
    }

    event.can_merge = 0;
    event.write = 0;
    event.read = 0;

    events.perf_submit(ctx, &event, sizeof(event));
    event_store.update(&pid, &event);

    fd_store.delete(&pid);
    
    return 0;
}
"""

bpf = BPF(text=bpf_source)

def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    print("Event:")
    print(f"  PID: {event.pid}")
    print(f"  Comm: {event.comm.decode('utf-8')}")
    print(f"  FD0: {event.fd0}, FD1: {event.fd1}")
    print(f"  Can Merge: {event.can_merge}")
    print(f"  Write: {event.write}, Read: {event.read}")

bpf["events"].open_perf_buffer(print_event)

print("Attaching kprobe and waiting for events...")
try:
    while True:
        bpf.perf_buffer_poll()
except KeyboardInterrupt:
    print("Detaching kprobe and exiting...")
