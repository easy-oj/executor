#include "main.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <linux/sched.h>

#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/wait.h>

// #define DEBUG

struct context c;
int in_exit = 0;

int main(int args, char **argv) {
    prepare(args, argv);
    do_execution();
    exit_execution(ES_EXEC_SUCCESS, 0);
}

void prepare(int args, char **argv) {
    if (args < 4) {
        exit_execution(ES_EXEC_ERROR, __COUNTER__);
    }
    memset(&c, 0, sizeof(struct context));
    c.time_max = parse_int(argv[1]);
    c.time_used = 1;
    c.mem_max = parse_int(argv[2]);
    c.mem_used = 4096;
    c.cmd = argv + 3;
    c.fd_i = dup(0);
    c.fd_o = dup(1);
}

int parse_int(char *str) {
    char *end;
    int i = strtol(str, &end, 0);
    if (str == end || *end != '\0') {
        exit_execution(ES_EXEC_ERROR, __COUNTER__);
    }
    return i;
}

void do_execution() {
    if ((c.pid = fork()) < 0) {
        exit_execution(ES_EXEC_ERROR, __COUNTER__);
    }
    if (c.pid == 0) {
        close(0);
        close(1);
        dup2(c.fd_i, 0);
        dup2(c.fd_o, 1);
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        if (execv(c.cmd[0], c.cmd) < 0) {
            exit_execution(ES_EXEC_ERROR, __COUNTER__);
        }
    }
    waitpid(c.pid, 0, 0);
    ptrace(PTRACE_SETOPTIONS, c.pid, 0, PTRACE_O_EXITKILL);
    init_timer();
    trace_sc();
}

void init_timer() {
    if (gettimeofday(&c.start, NULL) < 0) {
        exit_execution(ES_EXEC_ERROR, __COUNTER__);
    }
    timer_t timer;
    timer_create(CLOCK_MONOTONIC, NULL, &timer);
    struct itimerspec timeout;
    timeout.it_interval.tv_sec = 0;
    timeout.it_interval.tv_nsec = 1000 * 1000;
    timeout.it_value = timeout.it_interval;
    timer_settime(timer, 0, &timeout, NULL);
    signal(SIGALRM, cron_task);
}

void cron_task(int sig) {
    cron_check_time();
    cron_check_mem();
}

void cron_check_time() {
    struct timeval current;
    if (gettimeofday(&current, NULL) < 0) {
        exit_execution(ES_EXEC_ERROR, __COUNTER__);
    }
    int time_used = 1000 * (current.tv_sec - c.start.tv_sec) + (current.tv_usec - c.start.tv_usec) / 1000;
    if (time_used > c.time_max) {
        exit_execution(ES_TIME_LIMIT_EXCEED, 0);
    } else {
        c.time_used = time_used;
    }
}

void cron_check_mem() {
    char str[32];
    sprintf(str, "/proc/%d/statm", c.pid);
    FILE *f = fopen(str, "r");
    if (f == NULL) {
        return;
    }
    int vm_size, vm_rss, vm_share, vm_text, vm_lib, vm_data, vm_dirty;
    fscanf(f, "%d %d %d %d %d %d %d", &vm_size, &vm_rss, &vm_share, &vm_text, &vm_lib, &vm_data, &vm_dirty);
    fclose(f);
    int mem_used = vm_rss * 4096;
    if (mem_used > c.mem_max) {
        exit_execution(ES_MEMORY_LIMIT_EXCEED, 0);
    } else if (mem_used > c.mem_used) {
        c.mem_used = mem_used;
    }
}

void trace_sc() {
    struct user_regs_struct crs, rrs;
    for (;;) {
        // Get syscall params
        if (ptrace(PTRACE_SYSCALL, c.pid, 0, 0) < 0) {
            exit_execution(ES_EXEC_ERROR, __COUNTER__);
        }
        if (waitpid(c.pid, 0, 0) < 0) {
            exit_execution(ES_EXEC_ERROR, __COUNTER__);
        }
        if (ptrace(PTRACE_GETREGS, c.pid, 0, &crs) < 0) {
            exit_execution(ES_EXEC_ERROR, __COUNTER__);
        }
        pre_check_sc(crs);
        // Get syscall return
        if (ptrace(PTRACE_SYSCALL, c.pid, 0, 0) < 0) {
            exit_execution(ES_EXEC_ERROR, __COUNTER__);
        }
        if (waitpid(c.pid, 0, 0) < 0) {
            exit_execution(ES_EXEC_ERROR, __COUNTER__);
        }
        if (ptrace(PTRACE_GETREGS, c.pid, 0, &rrs) < 0) {
            if (errno == ESRCH) {
                if (crs.rdi != 0) {
                    exit_execution(ES_RUNTIME_ERROR, crs.rdi);
                }
                break;
            }
            exit_execution(ES_EXEC_ERROR, __COUNTER__);
        }
        post_check_sc(crs, rrs);
    }
}

void pre_check_sc(struct user_regs_struct crs) {
    switch (crs.orig_rax) {
        case __NR_clone:
            if (crs.rdi & CLONE_VM && !(crs.rdi & CLONE_VFORK) && crs.rdi & CLONE_THREAD) {
                return;
            }
        case __NR_fork:
        case __NR_vfork:
            exit_execution(ES_ILLEGAL_SYSCALL, crs.orig_rax);
    }
}

void post_check_sc(struct user_regs_struct crs, struct user_regs_struct rrs) {
#ifdef DEBUG
    printf("SYSCALL: %llu(%lld, %lld, %lld, %lld, %lld, %lld) = %llu\n",
           crs.orig_rax, crs.rdi, crs.rsi, crs.rdx, crs.r10, crs.r8, crs.r9, rrs.rax);
#endif
}

void exit_execution(int es, int ext) {
    if (atomic_exchange(&in_exit, 1) != 0) {
        return;
    }
    printf("#%d:%d:%d\n", c.time_used, c.mem_used, ext);
    exit(es);
}
