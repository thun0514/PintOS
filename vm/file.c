/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include <include/userprog/process.h>
#include <include/threads/vaddr.h>

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
    page->operations = &file_ops;

    struct file_page *file_page = &page->file;
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
    struct file_page *file_page UNUSED = &page->file;
}

/* Do the mmap */
void *do_mmap(void *addr, size_t length, int writable, struct file *file, off_t offset) {
    uint8_t *d_addr = addr;
    size_t read_bytes = length < file_length(file) ? length : file_length(file);
    size_t zero_bytes = PGSIZE - read_bytes % PGSIZE;
    while (read_bytes > 0 || zero_bytes > 0) {
        /* Do calculate how to fill this page.
         * We will read PAGE_READ_BYTES bytes from FILE
         * and zero the final PAGE_ZERO_BYTES bytes. */

        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        struct vm_aux *vm_aux = (struct vm_aux *) calloc(1, sizeof(struct vm_aux));
        *vm_aux = (struct vm_aux){.file = file, .page_read_bytes = page_read_bytes, .ofs = offset};

        /* TODO: Set up aux to pass information to the lazy_load_segment. */
        if (!vm_alloc_page_with_initializer(VM_FILE, d_addr, writable, lazy_load_segment,
                                            (void *) vm_aux)) {
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
}
