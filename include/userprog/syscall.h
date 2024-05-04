#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>

void syscall_init(void);

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t)-1)

/* Maximum characters in a filename written by readdir(). */
#define READDIR_MAX_LEN 14

/** #System Call */
void check_address(void *addr);
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int wait(pid_t);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned length);
int write(int fd, const void *buffer, unsigned length);
void seek(int fd, unsigned position);
unsigned tell(int fd);

#endif /* userprog/syscall.h */
