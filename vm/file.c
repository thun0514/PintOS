/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include <include/userprog/process.h>
#include <include/threads/vaddr.h>
#include <include/threads/mmu.h>

/** #Project 3: Swap In / Out */
#include <string.h>
#include "userprog/syscall.h"

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
    .swap_in = file_backed_swap_in,
    .swap_out = file_backed_swap_out,
    .destroy = file_backed_destroy,
    .type = VM_FILE,
};

/* The initializer of file vm */
void vm_file_init(void) {
}

/* Initialize the file backed page */
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva) {
    /* Set up the handler */
    struct file_page *file_page = &page->file;
    struct vm_aux *vm_aux = (struct vm_aux *) page->uninit.aux;
    file_page->vm_aux = vm_aux;
    page->operations = &file_ops;
}

/* Swap in the page by read contents from the file. */
static bool file_backed_swap_in(struct page *page, void *kva) {
    struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool file_backed_swap_out(struct page *page) {
    struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void file_backed_destroy(struct page *page) {
    struct vm_aux *vm_aux = page->uninit.aux;

    if (pml4_is_dirty(thread_current()->pml4, page->va)) {
        file_write_at(vm_aux->file, page->va, vm_aux->page_read_bytes, vm_aux->ofs);
        pml4_set_dirty(thread_current()->pml4, page->va, 0);
    }

    if (page->frame) {
        list_remove(&page->frame->f_elem);
        free(page->frame);
        page->frame = NULL;
    }

    pml4_clear_page(thread_current()->pml4, page->va);
}

/* Do the mmap */
void *do_mmap(void *addr, size_t length, int writable, struct file *file, off_t offset) {
    uint8_t *d_addr = addr;
    struct file *re_file = file_reopen(file);
    if (!re_file)
        return false;
    size_t read_bytes = length < file_length(re_file) ? length : file_length(re_file);
    size_t zero_bytes = PGSIZE - read_bytes % PGSIZE;
    while (read_bytes > 0 || zero_bytes > 0) {
        /* Do calculate how to fill this page.
         * We will read PAGE_READ_BYTES bytes from FILE
         * and zero the final PAGE_ZERO_BYTES bytes. */

        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        struct vm_aux *vm_aux = (struct vm_aux *) calloc(1, sizeof(struct vm_aux));
        *vm_aux =
            (struct vm_aux){.file = re_file, .page_read_bytes = page_read_bytes, .ofs = offset};

        /* TODO: Set up aux to pass information to the lazy_load_segment. */
        if (!vm_alloc_page_with_initializer(VM_FILE, d_addr, writable, lazy_load_segment,
                                            (void *) vm_aux)) {
            free(vm_aux);
            return NULL;
        }
        /* Advance. */
        offset += page_read_bytes;
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;

        d_addr += PGSIZE;
    }
    return addr;
}

/* Do the munmap */
void do_munmap(void *addr) {
    uint8_t *d_addr = addr;
    struct page *page = spt_find_page(&thread_current()->spt, d_addr);
    struct vm_aux *vm_aux = page->uninit.aux;
    struct file *orig_file = vm_aux->file;
    while (1) {
        page = spt_find_page(&thread_current()->spt, d_addr);
        if (!page)
            break;

        vm_aux = page->uninit.aux;
        struct file *next_file = vm_aux->file;
        if (!next_file || next_file != orig_file) 
            break;

        destroy(page);
        d_addr += PGSIZE;
    }
    free(page);
    return addr;
}
