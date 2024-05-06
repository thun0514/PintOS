#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>

void syscall_init(void);

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t)-1)

/* Maximum characters in a filename written by readdir(). */
#define READDIR_MAX_LEN 14

#endif /* userprog/syscall.h */
