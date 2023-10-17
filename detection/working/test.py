from bcc import BPF
from time import sleep

bpf_source = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/pipe_fs_i.h>
#include <linux/uio.h>

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
    unsigned int head;
    unsigned int mask;
    void *buf_ptr;
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

// Pipe_Write related probes
int kprobe__pipe_write(struct pt_regs *ctx, struct kiocb *iocb, struct iov_iter *from) {
    bpf_trace_printk("kprobe__pipe_write called\n");

    struct file *filp;
    struct pipe_inode_info *pipe_info;
    void *buf_ptr;
    u32 pid = bpf_get_current_pid_tgid();

    unsigned int head, mask, tail;
    bool was_empty = false;

    bpf_probe_read_kernel(&filp, sizeof(filp), &iocb->ki_filp);
    bpf_probe_read_kernel(&pipe_info, sizeof(pipe_info), &filp->private_data);
    bpf_probe_read_kernel(&head, sizeof(head), &pipe_info->head);
    bpf_probe_read_kernel(&tail, sizeof(tail), &pipe_info->tail);
    bpf_probe_read_kernel(&mask, sizeof(mask), &pipe_info->ring_size);
    bpf_probe_read_kernel(&buf_ptr, sizeof(buf_ptr), &pipe_info->bufs);

    bpf_trace_printk("Head: %u, Tail: %u, Mask: %u\n", head, tail, mask);

    mask -= 1;
    was_empty = pipe_empty(head, tail);

    if (!was_empty) {
        // means can't writable, pass this event
        bpf_trace_printk("pipe isn't empty\n");
        return 0;
    }

    struct event_t event = {};
    unsigned int save_head = head;
    unsigned int save_mask = mask;

    struct fd_array_t *fd_array;
    fd_array = fd_store.lookup(&pid);
    if (fd_array) {
        event.fd0 = fd_array->fds[0];
        event.fd1 = fd_array->fds[1];
    } else {
        return 0;
    }

    event.pid = pid;
    event.buf_ptr = buf_ptr;

    bpf_trace_printk("Before storing event - PID: %u, Head: %u\n", event.pid, event.head);
    bpf_trace_printk("Before storing event - Mask: %u, pipe_buf: %p\n", event.mask, event.buf_ptr);

    event_store.update(&pid, &event);

    return 0;
}

int kretprobe__pipe_write(struct pt_regs *ctx) {
    bpf_trace_printk("kretprobe__pipe_write called\n");
    u32 pid = bpf_get_current_pid_tgid();
    struct event_t *eventp = event_store.lookup(&pid);

    if (eventp) {
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct files_struct *files;
        struct fdtable *fdt;
        struct file **fd_array;
        struct file *file;

        bpf_probe_read_kernel(&files, sizeof(files), &task->files);
        bpf_probe_read_kernel(&fdt, sizeof(fdt), &files->fdt);
        bpf_probe_read_kernel(&fd_array, sizeof(fd_array), &fdt->fd);
        bpf_probe_read_kernel(&file, sizeof(file), &fd_array[eventp->fd0]);

	if (file) {
            bpf_trace_printk("Found file for fd: %d\n", eventp->fd0);
        } else {
            bpf_trace_printk("File not found for fd: %d\n", eventp->fd0);
            return 0;  // Return early if file not found
        }

        bpf_trace_printk("eventp exists: %p\n", eventp);
        struct event_t event_copy = {};
        bpf_probe_read_kernel(&event_copy, sizeof(event_copy), eventp);

        unsigned int mask = event_copy.mask;
        unsigned int head = event_copy.head;

        bpf_trace_printk("Debug - PID: %u, Head: %u, Mask: %u\n", event_copy.pid, head, mask);

        unsigned int can_merge_index = 0;
        struct pipe_buffer *buf_copy = event_copy.buf_ptr;

        unsigned int index;
        index  = head & mask;
        unsigned int flags;
        bpf_probe_read_kernel(&flags, sizeof(flags), &buf_copy[index].flags);

        if (flags & PIPE_BUF_FLAG_CAN_MERGE) {
            can_merge_index = 1;
            bpf_trace_printk("flag is set to 16");
        }

        if (can_merge_index) {
            event_copy.can_merge = 1;
            event_copy.write = 1;
            event_store.update(&pid, &event_copy);
        }

    events.perf_submit(ctx, eventp, sizeof(struct event_t));
    return 0;
   
    } else {
        bpf_trace_printk("eventp is NULL\n");
        return 0;
    }
}
"""

def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    print(f"PID: {event.pid}, FD0: {event.fd0}, FD1: {event.fd1}, Can Merge: {event.can_merge}, Write: {event.write}")

bpf = BPF(text=bpf_source)
bpf["events"].open_perf_buffer(print_event)

print("Attaching kprobe and waiting for events...")
try:
    while True:
        bpf.perf_buffer_poll()
except KeyboardInterrupt:
    print("Detaching kprobe and exiting...")
