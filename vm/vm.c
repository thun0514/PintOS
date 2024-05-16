/* vm.c: Generic interface for virtual memory objects. */

#include "include/vm/vm.h"
#include "threads/malloc.h"
#include "vm/inspect.h"
#include "include/threads/vaddr.h"
#include "include/threads/mmu.h"

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
    list_init(&frame_table.frames);
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
        /* TODO: Create the page, fetch the initializer according to the VM type,
         * TODO: and then create "uninit" page struct by calling uninit_new. You
         * TODO: should modify the field after calling the uninit_new. and add writable field in
         * struct page*/

        /* TODO: 페이지를 생성하고 VM 유형에 따라 이니셜라이저를 가져온 다음 uninit_new를 호출하여
         * TODO: "uninit" 페이지 구조체를 생성합니다. uninit_new를 호출한 후 필드를 수정해야 합니다.
         * TODO: 구조체 페이지에 쓰기 가능한 필드를 추가합니다. */
        struct page *new_page = calloc(1, sizeof(struct page));
        new_page->va = upage;
        new_page->writable = writable;
        switch (type) {
            case 1:
                uninit_new(new_page, upage, init, type, aux, anon_initializer);
                break;
            case 2:
                uninit_new(new_page, upage, init, type, aux, file_backed_initializer);
                break;
            default:
                goto err;
        }
        /* TODO: Insert the page into the spt. */
        if (!hash_insert(&spt->spt_hash, &new_page->p_elem)) {
            free(new_page);
            goto err;
        }
        return true;
    }
err:
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
    struct page *page = NULL;
    /* TODO: Fill this function. */
    uint64_t page_va = pg_round_down(va);

    return page_lookup(page_va);
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED, struct page *page UNUSED) {
    int succ = false;
    /* TODO: Fill this function. */

    /** PROJ 3 : Memory MGMT */
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
    /* TODO: The policy for eviction is up to you. */

    return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *vm_evict_frame(void) {
    struct frame *victim UNUSED = vm_get_victim();
    /* TODO: swap out the victim and return the evicted frame. */

    return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *vm_get_frame(void) {
    struct frame *frame = NULL;
    /* TODO: Fill this function. */

    /** PROJ 3 : Memory MGMT */
    frame = (struct frame *) calloc(1, sizeof(struct frame));
    frame->kva = palloc_get_page(PAL_USER);

    if (!frame->kva)
        PANIC("TODO");  // TODO: PANIC~~~~~~~~~~~~~~~~!

    frame->page == NULL;
    list_push_back(&frame_table.frames, &frame->f_elem);

    /** end code - Memory MGMT */

    ASSERT(frame != NULL);
    ASSERT(frame->page == NULL);
    return frame;
}

/* Growing the stack. */
static void vm_stack_growth(void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page *page UNUSED) {
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED, bool user UNUSED,
                         bool write UNUSED, bool not_present UNUSED) {
    struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
    struct page *page = NULL;
    /* TODO: Validate the fault */
    /* TODO: Your code goes here */

    return vm_do_claim_page(page);
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

    /** PROJ 3 : Memory MGMT */
    page = page_lookup(va);
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

    /** PROJ 3 : Memory MGMT */
    if (!pml4_get_page(thread_current()->pml4, page->va)) {
        pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable);
    }
    /** end code - Memory MGMT */
    return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED) {
    /** PROJ 3 : Memory MGMT */
    hash_init(&spt->spt_hash, spt->spt_hash.hash, spt->spt_hash.less, NULL);
    /** end code - Memory MGMT */
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
                                  struct supplemental_page_table *src UNUSED) {
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED) {
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * TODO: writeback all the modified contents to the storage. */
}

/** PROJ 3 : Memory MGMT */
struct page *page_lookup(const void *address) {
    struct page p;
    struct hash_elem *e;
    p.va = address;
    e = hash_find(&thread_current()->spt.spt_hash, &p.p_elem);
    return e != NULL ? hash_entry(e, struct page, p_elem) : NULL;
}
/** end code - Memory MGMT */
