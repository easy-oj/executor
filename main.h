#include <unistd.h>

#include <sys/time.h>
#include <sys/user.h>

#ifndef EXECUTOR_MAIN_H
#define EXECUTOR_MAIN_H

#define ES_EXEC_SUCCESS 0
#define ES_EXEC_ERROR 1
#define ES_RUNTIME_ERROR 2
#define ES_TIME_LIMIT_EXCEED 3
#define ES_MEMORY_LIMIT_EXCEED 4
#define ES_ILLEGAL_SYSCALL 5

struct context {
    char **cmd;

    int fd_i;
    int fd_o;

    pid_t pid;

    struct timeval start;
    int time_max;
    volatile int time_used;

    int mem_max;
    volatile int mem_used;
};

void prepare(int args, char **argv);

int parse_int(char *str);

void do_execution();

void init_timer();

void cron_task(int sig);

void cron_check_time();

void cron_check_mem();

void trace_sc();

void pre_check_sc(struct user_regs_struct crs);

void post_check_sc(struct user_regs_struct crs, struct user_regs_struct rrs);

void exit_execution(int es, int ext);

#endif //EXECUTOR_MAIN_H
