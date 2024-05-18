#include "userprog/process.h"

#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "include/threads/vaddr.h"

#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup(void);
static bool load(const char *file_name, struct intr_frame *if_);
static void initd(void *f_name);
static void __do_fork(void *);

/* General process initializer for initd and other process. */
static void process_init(void) {
    struct thread *current = thread_current();
}

/* FILE_NAME에서 로드된 "initd"라는 첫 번째 사용자 영역 프로그램을 시작합니다.
 * 새 스레드는 process_create_initd()가 반환되기 전에 예약될 수 있습니다
 * (심지어 종료될 수도 있음). initd의 스레드 ID를 반환하거나 스레드를 생성할 수
 * 없는 경우 TID_ERROR를 반환합니다.
 * 이 호출은 한 번만 호출해야 합니다. */
tid_t process_create_initd(const char *file_name) {
    char *fn_copy;
    tid_t tid;

    /* FILE_NAME의 사본을 만듭니다.
     * 그렇지 않으면 호출자와 load() 사이에 race가 발생합니다. */
    fn_copy = palloc_get_page(0);
    if (fn_copy == NULL)
        return TID_ERROR;
    strlcpy(fn_copy, file_name, PGSIZE);

    /** Project2: for Test Case - 직접 프로그램을 실행할 때에는 이 함수를 사용하지 않지만 make
     * check에서 이 함수를 통해 process_create를 실행하기 때문에 이 부분을 수정해주지 않으면 Test
     * Case의 Thread_name이 커맨드 라인 전체로 바뀌게 되어 Pass할 수 없다.
     */
    char *ptr;
    strtok_r(file_name, " ", &ptr);
    /** --------------------------------------------------------------------------------------------- */

    /* FILE_NAME을 실행할 새 스레드를 만듭니다. */
    tid = thread_create(file_name, PRI_DEFAULT, initd, fn_copy);
    if (tid == TID_ERROR)
        palloc_free_page(fn_copy);
    return tid;
}

/* 첫 번째 사용자 프로세스를 시작하는 스레드 함수입니다. */
static void initd(void *f_name) {
#ifdef VM
    supplemental_page_table_init(&thread_current()->spt);
#endif

    process_init();

    if (process_exec(f_name) < 0)
        PANIC("Fail to launch initd\n");
    NOT_REACHED();
}

/** #Project 2: System Call - 현재 프로세스를 `name`으로 복제합니다. 새 프로세스의
 * 스레드 ID를 반환하거나 스레드를 생성할 수 없는 경우 TID_ERROR를 반환합니다.
 */
tid_t process_fork(const char *name, struct intr_frame *if_ UNUSED) {
    thread_t *curr = thread_current();

    struct intr_frame *f =
        (pg_round_up(rrsp())
         - sizeof(struct intr_frame));  // 현재 쓰레드의 if_는 페이지 마지막에 붙어있다.
    memcpy(&curr->parent_if, f,
           sizeof(struct intr_frame));  // 1. 부모를 찾기 위해서 2. do_fork에 전달해주기 위해서

    /* 현재 스레드를 새 스레드로 복제합니다.*/
    tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, curr);

    if (tid == TID_ERROR)
        return TID_ERROR;

    thread_t *child = get_child_process(tid);

    sema_down(&child->fork_sema);  // 생성만 해놓고 자식 프로세스가 __do_fork에서 fork_sema를
                                   // sema_up 해줄 때까지 대기

    if (child->exit_status == TID_ERROR)
        return TID_ERROR;

    return tid;  // 부모 프로세스의 리턴값 : 생성한 자식 프로세스의 tid
}

#ifndef VM
/* 이 함수를 pml4_for_each에 전달하여 상위 주소 공간을 복제합니다.
 * 이는 프로젝트 2에만 해당됩니다. */
static bool duplicate_pte(uint64_t *pte, void *va, void *aux) {
    struct thread *current = thread_current();
    struct thread *parent = (struct thread *) aux;
    void *parent_page;
    void *newpage;
    bool writable;

    /* 1. TODO: If the parent_page is kernel page, then return immediately. */
    if (is_kernel_vaddr(va))
        return true;

    /* 2. Resolve VA from the parent's page map level 4. */
    parent_page = pml4_get_page(parent->pml4, va);
    if (parent_page == NULL)
        return false;

    /* 3. TODO: Allocate new PAL_USER page for the child and set result to
     *    TODO: NEWPAGE. */
    newpage = palloc_get_page(PAL_ZERO);
    if (newpage == NULL)
        return false;

    /* 4. TODO: Duplicate parent's page to the new page and
     *    TODO: check whether parent's page is writable or not (set WRITABLE
     *    TODO: according to the result). */
    memcpy(newpage, parent_page, PGSIZE);
    writable = is_writable(pte);

    /* 5. Add new page to child's page table at address VA with WRITABLE
     *    permission. */
    if (!pml4_set_page(current->pml4, va, newpage, writable)) {
        /* 6. TODO: if fail to insert page, do error handling. */
        return false;
    }
    return true;
}
#endif

/** #Project 2: System Call - 부모의 실행 컨텍스트를 복사하는 스레드 함수입니다.
 *  Hint) parent->tf는 프로세스의 사용자 영역 컨텍스트를 보유하지 않습니다.
 *       즉, process_fork의 두 번째 인수를 이 함수에 전달해야 합니다.
 */
static void __do_fork(void *aux) {
    struct intr_frame if_;
    struct thread *parent = (struct thread *) aux;
    struct thread *current = thread_current();
    bool succ = true;

    /* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
    struct intr_frame *parent_if = &parent->parent_if;

    /* 1. Read the cpu context to local stack. */
    memcpy(&if_, parent_if, sizeof(struct intr_frame));
    if_.R.rax = 0;  // 자식 프로세스의 return값 (0)

    /* 2. Duplicate PT */
    current->pml4 = pml4_create();
    if (current->pml4 == NULL)
        goto error;

    process_activate(current);
#ifdef VM
    supplemental_page_table_init(&current->spt);
    if (!supplemental_page_table_copy(&current->spt, &parent->spt))
        goto error;
#else
    if (!pml4_for_each(parent->pml4, duplicate_pte, parent))  // Page Table 통째로 복제
        goto error;
#endif

    /* TODO: Your code goes here.
     * TODO: Hint) 파일 객체를 복제하려면 include/filesys/file.h에서 `file_duplicate`를 사용하세요.
         이 함수가 부모의 리소스를 성공적으로 복제할 때까지 부모는 fork()에서 반환되어서는 안
     됩니다. */
    if (parent->fd_idx >= FDCOUNT_LIMIT)
        goto error;

    /** #Project 2: Extend File Descriptor - fd 복제 */
    current->fd_idx = parent->fd_idx;  // fdt 및 idx 복제
    struct file *file;
    for (int fd = 0; fd < FDCOUNT_LIMIT; fd++) {
        file = parent->fdt[fd];
        if (file == NULL)
            continue;

        if (file > STDERR)
            current->fdt[fd] = file_duplicate(file);
        else
            current->fdt[fd] = file;
    }
    /** -------------------------------------------- */

    sema_up(
        &current->fork_sema);  // fork 프로세스가 정상적으로 완료됐으므로 현재 fork용 sema unblock

    process_init();

    /* Finally, switch to the newly created process. */
    if (succ)
        do_iret(&if_);  // 정상 종료 시 자식 Process를 수행하러 감

error:
    sema_up(&current->fork_sema);  // 복제에 실패했으므로 현재 fork용 sema unblock
    exit(TID_ERROR);
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int process_exec(void *f_name) {
    char *file_name = f_name;
    bool success;

    /* 스레드 구조에서는 intr_frame을 사용할 수 없습니다.
     * 현재 쓰레드가 재스케줄 되면 실행 정보를 멤버에게 저장하기 때문입니다. */
    struct intr_frame if_;
    if_.ds = if_.es = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;

    /* We first kill the current context */
    process_cleanup();

    /** #Project 2: Command Line Parsing - 문자열 분리 */
    char *ptr, *arg;
    int argc = 0;
    char *argv[64];

    for (arg = strtok_r(file_name, " ", &ptr); arg != NULL; arg = strtok_r(NULL, " ", &ptr))
        argv[argc++] = arg;

    /* And then load the binary */
    success = load(file_name, &if_);

    /* If load failed, quit. */
    if (!success)
        return -1;

    argument_stack(argv, argc, &if_);

    palloc_free_page(file_name);

    /** #Project 2: Command Line Parsing - 디버깅용 툴 */
    // hex_dump(if_.rsp, if_.rsp, USER_STACK - if_.rsp, true);

    /* Start switched process. */
    do_iret(&if_);
    NOT_REACHED();
}

/** #Project 2: System Call - 스레드 TID가 종료될 때까지 기다리고 종료 상태를 반환합니다.
 *  커널에 의해 종료된 경우 (즉, 예외로 인해 종료된 경우) -1을 반환합니다. TID가 유효하지
 *  않거나 호출 프로세스의 하위 프로세스가 아니거나 주어진 TID에 대해 process_wait()가
 *  이미 성공적으로 호출된 경우 기다리지 않고 즉시 -1을 반환합니다.
 */
int process_wait(tid_t child_tid UNUSED) {
    thread_t *child = get_child_process(child_tid);
    if (child == NULL)
        return -1;

    sema_down(&child->wait_sema);  // 자식 프로세스가 종료될 때 까지 대기.

    int exit_status = child->exit_status;
    list_remove(&child->child_elem);

    sema_up(&child->exit_sema);  // 자식 프로세스가 죽을 수 있도록 signal

    return exit_status;
}

/** #Project 2: System Call - Exit the process. This function is called by thread_exit (). */
void process_exit(void) {
    thread_t *curr = thread_current();
    /* TODO: Your code goes here.
     * TODO: Implement process termination message (see
     * TODO: project2/process_termination.html).
     * TODO: We recommend you to implement process resource cleanup here. */

    for (int fd = 0; fd < curr->fd_idx; fd++)  // FDT 비우기
        close(fd);

    file_close(curr->runn_file);  // 현재 프로세스가 실행중인 파일 종료

    palloc_free_multiple(curr->fdt, FDT_PAGES);

    process_cleanup();

    sema_up(&curr->wait_sema);  // 자식 프로세스가 종료될 때까지 대기하는 부모에게 signal

    sema_down(&curr->exit_sema);  // 부모 프로세스가 종료될 떄까지 대기
}

/* Free the current process's resources. */
static void process_cleanup(void) {
    struct thread *curr = thread_current();

#ifdef VM
    supplemental_page_table_kill(&curr->spt);
#endif

    uint64_t *pml4;
    /* Destroy the current process's page directory and switch back
     * to the kernel-only page directory. */
    pml4 = curr->pml4;
    if (pml4 != NULL) {
        /* Correct ordering here is crucial.  We must set
         * cur->pagedir to NULL before switching page directories,
         * so that a timer interrupt can't switch back to the
         * process page directory.  We must activate the base page
         * directory before destroying the process's page
         * directory, or our active page directory will be one
         * that's been freed (and cleared). */
        curr->pml4 = NULL;
        pml4_activate(NULL);
        pml4_destroy(pml4);
    }
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void process_activate(struct thread *next) {
    /* Activate thread's page tables. */
    pml4_activate(next->pml4);

    /* Set thread's kernel stack for use in processing interrupts. */
    tss_update(next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0          /* Ignore. */
#define PT_LOAD    1          /* Loadable segment. */
#define PT_DYNAMIC 2          /* Dynamic linking info. */
#define PT_INTERP  3          /* Name of dynamic loader. */
#define PT_NOTE    4          /* Auxiliary info. */
#define PT_SHLIB   5          /* Reserved. */
#define PT_PHDR    6          /* Program header table. */
#define PT_STACK   0x6474e551 /* Stack segment. */

#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
    unsigned char e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct ELF64_PHDR {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

/* Abbreviations */
#define ELF  ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack(struct intr_frame *if_);
static bool validate_segment(const struct Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool load(const char *file_name, struct intr_frame *if_) {
    struct thread *t = thread_current();
    struct ELF ehdr;
    struct file *file = NULL;
    off_t file_ofs;
    bool success = false;
    int i;

    /* Allocate and activate page directory. */
    t->pml4 = pml4_create();
    if (t->pml4 == NULL)
        goto done;
    process_activate(thread_current());

    /* Open executable file. */
    file = filesys_open(file_name);
    if (file == NULL) {
        printf("load: %s: open failed\n", file_name);
        goto done;
    }

    /** #Project 2: System Call - 파일 실행 명시 및 접근 금지 설정  */
    t->runn_file = file;
    file_deny_write(file); /** #Project 2: Denying Writes to Executables */

    /* Read and verify executable header. */
    if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr
        || memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2
        || ehdr.e_machine != 0x3E  // amd64
        || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) || ehdr.e_phnum > 1024) {
        printf("load: %s: error loading executable\n", file_name);
        goto done;
    }

    /* Read program headers. */
    file_ofs = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++) {
        struct Phdr phdr;

        if (file_ofs < 0 || file_ofs > file_length(file))
            goto done;
        file_seek(file, file_ofs);

        if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
            goto done;
        file_ofs += sizeof phdr;
        switch (phdr.p_type) {
            case PT_NULL:
            case PT_NOTE:
            case PT_PHDR:
            case PT_STACK:
            default:
                /* Ignore this segment. */
                break;
            case PT_DYNAMIC:
            case PT_INTERP:
            case PT_SHLIB:
                goto done;
            case PT_LOAD:
                if (validate_segment(&phdr, file)) {
                    bool writable = (phdr.p_flags & PF_W) != 0;
                    uint64_t file_page = phdr.p_offset & ~PGMASK;
                    uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
                    uint64_t page_offset = phdr.p_vaddr & PGMASK;
                    uint32_t read_bytes, zero_bytes;
                    if (phdr.p_filesz > 0) {
                        /* Normal segment.
                         * Read initial part from disk and zero the rest. */
                        read_bytes = page_offset + phdr.p_filesz;
                        zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
                    } else {
                        /* Entirely zero.
                         * Don't read anything from disk. */
                        read_bytes = 0;
                        zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
                    }
                    if (!load_segment(file, file_page, (void *) mem_page, read_bytes, zero_bytes,
                                      writable))
                        goto done;
                } else
                    goto done;
                break;
        }
    }

    /* Set up stack. */
    if (!setup_stack(if_))
        goto done;

    /* Start address. */
    if_->rip = ehdr.e_entry;

    success = true;

done:
    /* We arrive here whether the load is successful or not. */
    // file_close(file);

    return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Phdr *phdr, struct file *file) {
    /* p_offset and p_vaddr must have the same page offset. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
        return false;

    /* p_offset must point within FILE. */
    if (phdr->p_offset > (uint64_t) file_length(file))
        return false;

    /* p_memsz must be at least as big as p_filesz. */
    if (phdr->p_memsz < phdr->p_filesz)
        return false;

    /* The segment must not be empty. */
    if (phdr->p_memsz == 0)
        return false;

    /* The virtual memory region must both start and end within the
       user address space range. */
    if (!is_user_vaddr((void *) phdr->p_vaddr))
        return false;
    if (!is_user_vaddr((void *) (phdr->p_vaddr + phdr->p_memsz)))
        return false;

    /* The region cannot "wrap around" across the kernel virtual
       address space. */
    if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
        return false;

    /* Disallow mapping page 0.
       Not only is it a bad idea to map page 0, but if we allowed
       it then user code that passed a null pointer to system calls
       could quite likely panic the kernel by way of null pointer
       assertions in memcpy(), etc. */
    if (phdr->p_vaddr < PGSIZE)
        return false;

    /* It's okay. */
    return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page(void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */

/* UPAGE 주소의 FILE에 있는 오프셋 OFS에서 시작하는 세그먼트를 로드합니다.
 * 전체적으로 READ_BYTES + ZERO_BYTES 바이트의 가상 메모리가 다음과 같이 초기화됩니다.
 *
 * - UPAGE의 READ_BYTES 바이트는 오프셋 OFS에서 시작하는 FILE에서 읽어야 합니다.
 *
 * - UPAGE + READ_BYTES에서 ZERO_BYTES바이트를 0으로 설정해야 합니다.
 *
 * 이 함수에 의해 초기화된 페이지는 WRITABLE이 true인 경우 사용자 프로세스에서 쓸 수 있어야 하고,
 * 그렇지 않으면 읽기 전용이어야 합니다.
 *
 * 성공하면 true를 반환하고, 메모리 할당 오류나 디스크 읽기 오류가 발생하면 false를 반환합니다. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

    file_seek(file, ofs);
    while (read_bytes > 0 || zero_bytes > 0) {
        /* Do calculate how to fill this page.
         * We will read PAGE_READ_BYTES bytes from FILE
         * and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* Get a page of memory. */
        uint8_t *kpage = palloc_get_page(PAL_USER);
        if (kpage == NULL)
            return false;

        /* Load this page. */
        if (file_read(file, kpage, page_read_bytes) != (int) page_read_bytes) {
            palloc_free_page(kpage);
            return false;
        }
        memset(kpage + page_read_bytes, 0, page_zero_bytes);

        /* Add the page to the process's address space. */
        if (!install_page(upage, kpage, writable)) {
            printf("fail\n");
            palloc_free_page(kpage);
            return false;
        }

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }
    return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool setup_stack(struct intr_frame *if_) {
    uint8_t *kpage;
    bool success = false;

    kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kpage != NULL) {
        success = install_page(((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
        if (success)
            if_->rsp = USER_STACK;
        else
            palloc_free_page(kpage);
    }
    return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool install_page(void *upage, void *kpage, bool writable) {
    struct thread *t = thread_current();

    /* Verify that there's not already a page at that virtual
     * address, then map our page there. */
    return (pml4_get_page(t->pml4, upage) == NULL
            && pml4_set_page(t->pml4, upage, kpage, writable));
}

#else  /** PROJ 3 ========================================================= */

/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool lazy_load_segment(struct page *page, void *aux) {
    /* TODO: Load the segment from the file */
    /* TODO: This called when the first page fault occurs on address VA. */
    /* TODO: VA is available when calling this function. */

    /* TODO: 파일에서 세그먼트 로드 */
    /* TODO: 주소 VA에서 첫 번째 페이지 오류가 발생할 때 호출됩니다. */
    /* TODO: 이 함수를 호출하면 VA를 사용할 수 있습니다. */

    /* Get a page of memory. */
    struct vm_aux *vm_aux = (struct vm_aux *) aux;
    uint8_t *kpage = page->frame->kva;
    file_seek(vm_aux->file, vm_aux->ofs);  // FIXME: offset 어케하지

    if (kpage == NULL)
        return false;

    /* Load this page. */
    if (file_read(vm_aux->file, kpage, vm_aux->page_read_bytes) != (int) vm_aux->page_read_bytes) {
        palloc_free_page(kpage);
        return false;
    }
    memset(kpage + vm_aux->page_read_bytes, 0, PGSIZE - vm_aux->page_read_bytes);
    return true;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */

/* UPAGE 주소의 FILE에 있는 오프셋 OFS에서 시작하는 세그먼트를 로드합니다.
 * 전체적으로 READ_BYTES + ZERO_BYTES 바이트의 가상 메모리가 다음과 같이 초기화됩니다.
 *
 * - UPAGE의 READ_BYTES 바이트는 오프셋 OFS에서 시작하는 FILE에서 읽어야 합니다.
 *
 * - UPAGE + READ_BYTES에서 ZERO_BYTES바이트를 0으로 설정해야 합니다.
 *
 * 이 함수에 의해 초기화된 페이지는 WRITABLE이 true인 경우 사용자 프로세스에서 쓸 수 있어야 하고,
 * 그렇지 않으면 읽기 전용이어야 합니다.
 *
 * 성공하면 true를 반환하고, 메모리 할당 오류나 디스크 읽기 오류가 발생하면 false를 반환합니다. */

/**이 함수는 실행 파일의 내용을 페이지로 로딩하는 함수이며 첫번째 page fault가 발생될 때 호출된다.
 * 이 함수가 호출되기 이전의 매핑은 물리 프레임 매핑이므로, 물리 프레임에 내용을 로딩하는 작업만
 * 진행하면 된다. 함수는 페이지 구조체와 aux를 인자로 받는데, aux의 경우는 load_segment에서 로딩을
 * 위해 설정한 정보인 lazy_load_arg이며, 이 정보를 사용하여 읽어올 파일을 찾아서 메모리에 로딩을
 * 하는 형식으로 진행되어야한다.
 */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);
    /** PROJ 3 struct vm_aux,vm_aux->file while문 안으로 옮기는거 고려하기 이유는 lazy load떄문  */
    while (read_bytes > 0 || zero_bytes > 0) {
        /* Do calculate how to fill this page.
         * We will read PAGE_READ_BYTES bytes from FILE
         * and zero the final PAGE_ZERO_BYTES bytes. */

        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        struct vm_aux *vm_aux = (struct vm_aux *) calloc(1, sizeof(struct vm_aux));
        *vm_aux = (struct vm_aux){.file = file, .page_read_bytes = page_read_bytes, .ofs = ofs};

        /* TODO: Set up aux to pass information to the lazy_load_segment. */
        if (!vm_alloc_page_with_initializer(VM_ANON, upage, writable, lazy_load_segment,
                                            (void *) vm_aux)) {
            return false;
        }
        /* Advance. */
        ofs += page_read_bytes;
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }

    return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool setup_stack(struct intr_frame *if_) {
    bool success = false;
    void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);
    /** PROJ 3 첫스택 지연할당 못함, 스택확인 못함 , stack 마킹 못함
     * 스택 확인 못하면 첫스택인지 아닌지 몰라요~     */
    /* TODO: Map the stack on stack_bottom and claim the page immediately.
     * TODO: If success, set the rsp accordingly.
     * TODO: You should mark the page is stack. */
    /* TODO: Your code goes here */
    // struct page page;

    if (!vm_alloc_page(VM_ANON, stack_bottom, 1))
        return success;

    if (!vm_claim_page(stack_bottom))
        return success;

    if_->rsp = stack_bottom + PGSIZE;

    success = true;
    printf("%d",success);
    return success;
}
#endif /* VM */

/** #Project 2: Command Line Parsing - 유저 스택에 파싱된 토큰을 저장하는 함수 */
void argument_stack(char **argv, int argc, struct intr_frame *if_) {
    char *arg_addr[100];
    int argv_len;

    for (int i = argc - 1; i >= 0; i--) {
        argv_len = strlen(argv[i]) + 1;
        if_->rsp -= argv_len;
        memcpy(if_->rsp, argv[i], argv_len);
        arg_addr[i] = if_->rsp;
    }

    while (if_->rsp % 8)
        *(uint8_t *) (--if_->rsp) = 0;

    if_->rsp -= 8;
    memset(if_->rsp, 0, sizeof(char *));
    for (int i = argc - 1; i >= 0; i--) {
        if_->rsp -= 8;
        memcpy(if_->rsp, &arg_addr[i], sizeof(char *));
    }

    if_->rsp = if_->rsp - 8;
    memset(if_->rsp, 0, sizeof(void *));

    if_->R.rdi = argc;
    if_->R.rsi = if_->rsp + 8;
}

thread_t *get_child_process(int pid) {
    thread_t *curr = thread_current();
    thread_t *t;

    for (struct list_elem *e = list_begin(&curr->child_list); e != list_end(&curr->child_list);
         e = list_next(e)) {
        t = list_entry(e, thread_t, child_elem);

        if (pid == t->tid)
            return t;
    }

    return NULL;
}

/** #Project 2: System Call - 현재 스레드 fdt에 파일 추가 */
int process_add_file(struct file *f) {
    thread_t *curr = thread_current();
    struct file **fdt = curr->fdt;

    if (curr->fd_idx >= FDCOUNT_LIMIT)
        return -1;

    while (fdt[curr->fd_idx] != NULL)
        curr->fd_idx++;

    fdt[curr->fd_idx++] = f;

    return curr->fd_idx - 1;
}

/** #Project 2: System Call - 현재 스레드의 fd번째 파일 정보 얻기 */
struct file *process_get_file(int fd) {
    thread_t *curr = thread_current();

    if (fd < 0 || fd >= FDCOUNT_LIMIT)
        return NULL;

    return curr->fdt[fd];
}

/** #Project 2: System Call - 현재 스레드의 fdt에서 파일 삭제 */
int process_close_file(int fd) {
    thread_t *curr = thread_current();

    if (fd < 0 || fd >= FDCOUNT_LIMIT)
        return -1;

    curr->fdt[fd] = NULL;
    return 0;
}

process_insert_file(int fd, struct file *f) {
    thread_t *curr = thread_current();
    struct file **fdt = curr->fdt;

    if (fd < 0 || fd >= FDCOUNT_LIMIT)
        return -1;

    if (f > STDERR)
        f->dup_count++;

    fdt[fd] = f;

    return fd;
}