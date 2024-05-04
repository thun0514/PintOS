#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"

/** #System Call */
#include "filesys/filesys.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void) {
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
     * until the syscall_entry swaps the userland stack to the kernel
     * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK, FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED) {
    // TODO: Your implementation goes here.
    int sys_number = f->R.rax;

    // Argument 순서
    // %rdi %rsi %rdx %r10 %r8 %r9

    switch (sys_number) {
        case SYS_HALT:
            halt();
            break;
        case SYS_EXIT:
            exit(f->R.rdi);
            break;
        case SYS_FORK:
            fork(f->R.rdi);
            break;
        case SYS_EXEC:
            exec(f->R.rdi);
            break;
        case SYS_WAIT:
            process_wait(f->R.rdi);
            break;
        case SYS_CREATE:
            create(f->R.rdi, f->R.rsi);
            break;
        case SYS_REMOVE:
            remove(f->R.rdi);
            break;
        case SYS_OPEN:
            open(f->R.rdi);
            break;
        case SYS_FILESIZE:
            filesize(f->R.rdi);
            break;
        case SYS_READ:
            read(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_WRITE:
            write(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_SEEK:
            seek(f->R.rdi, f->R.rsi);
            break;
        case SYS_TELL:
            tell(f->R.rdi);
            break;
        case SYS_CLOSE:
            close(f->R.rdi);
            break;

        default:
            exit(-1);
    }
    thread_exit();
}

/** #System Call */
void check_address(void *addr) {
    if (is_user_vaddr(addr))
        exit(-1);
}

void halt(void) {
    power_off();
}

void exit(int status) {
    thread_t *t = thread_current();
    printf("%s: exit(%d)\n", t->name, status);
    thread_exit();
}

bool create(const char *file, unsigned initial_size) {
    return (filesys_create(file, initial_size) ? true : false);
}

bool remove(const char *file) {
    return (filesys_remove(file) ? true : false);
}

pid_t fork(const char *thread_name) {
    return (pid_t)syscall1(SYS_FORK, thread_name);
}

int exec(const char *file) {
    return (pid_t)syscall1(SYS_EXEC, file);
}

int wait(pid_t pid) {
    return syscall1(SYS_WAIT, pid);
}

bool create(const char *file, unsigned initial_size) {
    return syscall2(SYS_CREATE, file, initial_size);
}

bool remove(const char *file) {
    return syscall1(SYS_REMOVE, file);
}

int open(const char *file) {
    return syscall1(SYS_OPEN, file);
}

int filesize(int fd) {
    return syscall1(SYS_FILESIZE, fd);
}

int read(int fd, void *buffer, unsigned size) {
    return syscall3(SYS_READ, fd, buffer, size);
}

int write(int fd, const void *buffer, unsigned size) {
    return syscall3(SYS_WRITE, fd, buffer, size);
}

void seek(int fd, unsigned position) {
    syscall2(SYS_SEEK, fd, position);
}

unsigned tell(int fd) {
    return syscall1(SYS_TELL, fd);
}

void close(int fd) {
    syscall1(SYS_CLOSE, fd);
}

int dup2(int oldfd, int newfd) {
    return syscall2(SYS_DUP2, oldfd, newfd);
}

void *mmap(void *addr, size_t length, int writable, int fd, off_t offset) {
    return (void *)syscall5(SYS_MMAP, addr, length, writable, fd, offset);
}

void munmap(void *addr) {
    syscall1(SYS_MUNMAP, addr);
}

bool chdir(const char *dir) {
    return syscall1(SYS_CHDIR, dir);
}

bool mkdir(const char *dir) {
    return syscall1(SYS_MKDIR, dir);
}

bool readdir(int fd, char name[READDIR_MAX_LEN + 1]) {
    return syscall2(SYS_READDIR, fd, name);
}

bool isdir(int fd) {
    return syscall1(SYS_ISDIR, fd);
}

int inumber(int fd) {
    return syscall1(SYS_INUMBER, fd);
}

int symlink(const char *target, const char *linkpath) {
    return syscall2(SYS_SYMLINK, target, linkpath);
}

int mount(const char *path, int chan_no, int dev_no) {
    return syscall3(SYS_MOUNT, path, chan_no, dev_no);
}

int umount(const char *path) {
    return syscall1(SYS_UMOUNT, path);
}
