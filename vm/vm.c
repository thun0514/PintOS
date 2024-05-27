/* vm.c: Generic interface for virtual memory objects. */

#include "include/vm/vm.h"
#include "threads/malloc.h"
#include "vm/inspect.h"
#include "include/threads/vaddr.h"
#include "include/threads/mmu.h"
#include <string.h>

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */

struct frame_table frame_table;

void vm_init(void) {
    vm_anon_init();
    vm_file_init();
#ifdef EFILESYS /* For project 4 */
    pagecache_init();
#endif
    register_inspect_intr();
    /* DO NOT MODIFY UPPER LINES. */
    /* TODO: Your code goes here. */

    /** #Project 3: Memory MGMT*/
    list_init(&frame_table.frames);
    lock_init(&frame_table.ft_lock);
    /** end code - Memory MGMT*/
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type page_get_type(struct page *page) {
    int ty = VM_TYPE(page->operations->type);
    switch (ty) {
        case VM_UNINIT:
            return VM_TYPE(page->uninit.type);
        default:
            return ty;
    }
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
/*
🐯 위의 함수는 초기화되지 않은 주어진 type의 페이지를 생성합니다. 초기화되지 않은 페이지의 swap_in
핸들러는 자동적으로 페이지 타입에 맞게 페이지를 초기화하고 주어진 AUX를 인자로 삼는 INIT 함수를
호출합니다. 당신이 페이지 구조체를 가지게 되면 프로세스의 보조 페이지 테이블에 그 페이지를
삽입하십시오. vm.h에 정의되어 있는 VM_TYPE 매크로를 사용하면 편리할 것입니다. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
                                    vm_initializer *init, void *aux) {
    ASSERT(VM_TYPE(type) != VM_UNINIT)

    struct supplemental_page_table *spt = &thread_current()->spt;
    /* Check wheter the upage is already occupied or not. */
    if (spt_find_page(spt, upage) == NULL) {
        /** #Project 3: Anonymous Page */
        /* TODO: Create the page, fetch the initializer according to the VM type,
         * TODO: and then create "uninit" page struct by calling uninit_new. You
         * TODO: should modify the field after calling the uninit_new. and add writable field in
         * struct page*/

        /* TODO: 페이지를 생성하고 VM 유형에 따라 이니셜라이저를 가져온 다음 uninit_new를 호출하여
         * TODO: "uninit" 페이지 구조체를 생성합니다. uninit_new를 호출한 후 필드를 수정해야 합니다.
         * TODO: 구조체 페이지에 쓰기 가능한 필드를 추가합니다. */
        struct page *new_page = (struct page *) calloc(1, sizeof(struct page));
        if (!new_page)
            return false;

        switch (VM_TYPE(type)) {
            case VM_ANON:
                uninit_new(new_page, upage, init, type, aux, anon_initializer);
                break;
            case VM_FILE:
                uninit_new(new_page, upage, init, type, aux, file_backed_initializer);
                break;
            default:
                goto err;
        }
        new_page->writable = writable;

        /* TODO: Insert the page into the spt. */
        if (!spt_insert_page(spt, new_page)) {
            free(new_page);
            goto err;
        }
        return true;
        /** end code - Anonymous Page */
    }
err:
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
    /* TODO: Fill this function. */

    /** #Project 3: Memory MGMT */
    struct page *page = (struct page *) malloc(sizeof(struct page));
    page->va = pg_round_down(va);
    struct hash_elem *e = hash_find(&spt->spt_hash, &page->p_elem);

    free(page);

    return e != NULL ? hash_entry(e, struct page, p_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED, struct page *page UNUSED) {
    int succ = false;
    /* TODO: Fill this function. */

    /** #Project 3: Memory MGMT */
    if (!hash_insert(&spt->spt_hash, &page->p_elem))
        succ = true;
    /** end code - Memory MGMT*/

    return succ;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page) {
    vm_dealloc_page(page);
    return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *vm_get_victim(void) {
    struct frame *victim = NULL;
    struct list_elem *e;
    /* TODO: The policy for eviction is up to you. */

    if (!frame_table.next_victim)
        frame_table.next_victim = list_begin(&frame_table.frames);

    lock_acquire(&frame_table.ft_lock);
    for (e = frame_table.next_victim; e != list_end(&frame_table.frames); e = list_next(e)) {
        victim = list_entry(e, struct frame, f_elem);

        if (victim->page == NULL) {
            lock_release(&frame_table.ft_lock);
            return victim;
        }
        if (pml4_is_accessed(thread_current()->pml4, victim->page->va))
            pml4_set_accessed(thread_current()->pml4, victim->page->va, 0);
        else {
            lock_release(&frame_table.ft_lock);
            return victim;
        }

        pml4_set_accessed(thread_current()->pml4, victim->kva, 0);
    }
    lock_release(&frame_table.ft_lock);
    return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *vm_evict_frame(void) {
    struct frame *victim = vm_get_victim();
    /* TODO: swap out the victim and return the evicted frame. */

    if (!swap_out(victim->page))
        return NULL;

    memset(victim->kva, 0, PGSIZE);
    victim->page->frame = NULL;
    pml4_clear_page(thread_current()->pml4, victim->page->va);
    victim->page = NULL;

    return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *vm_get_frame(void) {
    struct frame *frame = NULL;
    /* TODO: Fill this function. */

    /** #Project 3: Memory MGMT */
    frame = (struct frame *) calloc(1, sizeof(struct frame));
    frame->kva = palloc_get_page(PAL_USER | PAL_ZERO);
    if (!frame->kva) {
        frame = vm_evict_frame();
        frame->page = NULL;
        return frame;
    }

    frame->page = NULL;
    lock_acquire(&frame_table.ft_lock);
    list_push_back(&frame_table.frames, &frame->f_elem);
    lock_release(&frame_table.ft_lock);

    ASSERT(frame != NULL);
    ASSERT(frame->page == NULL);
    return frame;
}

/* Growing the stack. */
static void vm_stack_growth(void *addr) {
    if (!vm_alloc_page(VM_ANON, addr, true) || !vm_claim_page(addr))
        return;
}

/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page *page UNUSED) {
}

/* Return true on success */
/* addr, user, write, not_present는 비트말하는거 */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED, bool user UNUSED,
                         bool write UNUSED, bool not_present UNUSED) {
    struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
    struct page *page = NULL;

    /* TODO: Validate the fault */
    /* TODO: Your code goes here */

    if ((is_kernel_vaddr(addr)) || addr == NULL)
        return false;

    if (not_present) {
        void *rsp = user ? f->rsp : thread_current()->usb;

        if (addr >= USER_STACK - USM_SIZE && (addr == rsp - 8 || addr == rsp)) {
            vm_stack_growth(pg_round_down(addr));
            return true;
        }

        page = spt_find_page(spt, addr);
        if ((write == 1 && page->writable == 0) || !page)
            return false;

        return vm_claim_page(addr);
    }
    return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page) {
    destroy(page);
    free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va UNUSED) {
    struct page *page = NULL;
    /* TODO: Fill this function */

    /** #Project 3: Memory MGMT */
    page = spt_find_page(&thread_current()->spt, va);
    if (page == NULL)
        return false;
    /** end code - Memory MGMT */

    return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
/* 당신은 MMU를 세팅해야 하는데, 이는 가상 주소와 물리 주소를 매핑한 정보를 페이지 테이블에
 * 추가해야 한다는 것을 의미합니다. 위의 함수는 앞에서 말한 연산이 성공적으로 수행되었을 경우에
 * true를 반환하고 그렇지 않을 경우에 false를 반환합니다.*/
static bool vm_do_claim_page(struct page *page) {
    struct frame *frame = vm_get_frame();

    /* Set links */
    frame->page = page;
    page->frame = frame;

    /* TODO: Insert page table entry to map page's VA to frame's PA. */

    /** #Project 3: Memory MGMT */
    if (!pml4_get_page(thread_current()->pml4, page->va)) {
        pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable);
    }
    /** end code - Memory MGMT */
    return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED) {
    /** #Project 3: Memory MGMT */
    hash_init(&spt->spt_hash, page_hash, page_less, NULL);
    /** end code - Memory MGMT */
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *child UNUSED,
                                  struct supplemental_page_table *parent UNUSED) {
    /** #Project 3: Anonymous Page */
    struct hash_iterator p_i;
    struct hash *p_h = &parent->spt_hash;
    hash_first(&p_i, p_h);  // p_i 초기화

    while (hash_next(&p_i)) {
        struct page *p_page = hash_entry(hash_cur(&p_i), struct page, p_elem);
        enum vm_type p_real_type = p_page->operations->type;

        if ((VM_TYPE(p_real_type)) == VM_UNINIT) {
            vm_alloc_page_with_initializer(p_page->uninit.type, p_page->va, p_page->writable,
                                           p_page->uninit.init, p_page->uninit.aux);
        } else {
            vm_alloc_page(p_real_type, p_page->va, p_page->writable);

            struct page *c_page = spt_find_page(child, p_page->va);

            if (!vm_do_claim_page(c_page))
                return false;

            memcpy(c_page->frame->kva, p_page->frame->kva, PGSIZE);
        }
    }
    return true;
    /** end code - Anonymous Page */
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED) {
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * TODO: writeback all the modified contents to the storage. */

    hash_clear(&spt->spt_hash, page_killer);
}

/** #Project 3: Memory MGMT */
void *page_killer(struct hash_elem *hash_elem, void *aux UNUSED) {
    struct page *page = hash_entry(hash_elem, struct page, p_elem);
    vm_dealloc_page(page);
}
/** end code - Memory MGMT */
