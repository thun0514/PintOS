#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"

/** #Project 2: System Call */
#include "filesys/filesys.h"
#include "threads/mmu.h"
#include "userprog/process.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

static int process_add_file(struct file *f);
static struct file *process_get_file(int fd);
static int process_close_file(int fd);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR         0xc0000081 /* Segment selector msr */
#define MSR_LSTAR        0xc0000082 /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void) {
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
     * until the syscall_entry swaps the userland stack to the kernel
     * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK, FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

    /** #Project 2: System Call - read & write 용 lock 초기화 */
    lock_init(&filesys_lock);
}

/* The main system call interface */
/** #Project 2: System Call - 시스템 콜 핸들러 */
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

void check_address(void *addr) {
    if (is_user_vaddr(addr))
        exit(-1);
}

void halt(void) {
    power_off();
}

void exit(int status) {
    thread_t *t = thread_current();
    t->exit_status = status;
    printf("%s: exit(%d)\n", t->name, t->exit_status);
    thread_exit();
}

pid_t fork(const char *thread_name) {
    return process_fork(thread_name, NULL);
}

int exec(const char *file) {
    check_address(file);

    return process_exec(file);
}

int wait(pid_t tid) {
    return process_wait(tid);
}

bool create(const char *file, unsigned initial_size) {
    check_address(file);

    return filesys_create(file, initial_size);
}

bool remove(const char *file) {
    check_address(file);

    return ilesys_remove(file);
}

int open(const char *file) {
}

int filesize(int fd) {
}

int read(int fd, void *buffer, unsigned length) {
}

int write(int fd, const void *buffer, unsigned length) {
}

void seek(int fd, unsigned position) {
}

unsigned tell(int fd) {
}

void close(int fd) {
}

/** #Project 2: System Call - 현재 스레드 fdt에 파일 추가 */
static int process_add_file(struct file *f) {
    thread_t *curr = thread_current();
    struct file **fdt = curr->fdt;

    while (curr->fd_idx < FDCOUNT_LIMIT && fdt[curr->fd_idx])
        curr->fd_idx++;

    if (curr->fd_idx > FDCOUNT_LIMIT)
        return -1;

    fdt[curr->fd_idx] = f;
    return curr->fd_idx;
}

/** #Project 2: System Call - 현재 스레드의 fd번째 파일 정보 얻기 */
static struct file *process_get_file(int fd) {
    thread_t *curr = thread_current();

    if (fd > FDCOUNT_LIMIT)
        return NULL;

    return curr->fdt[fd];
}

/** #Project 2: System Call - 현재 스레드의 fdt에서 파일 삭제 */
static int process_close_file(int fd) {
    thread_t *curr = thread_current();

    if (fd > FDCOUNT_LIMIT)
        return -1;

    curr->fdt[fd] = NULL;
    return 0;
}