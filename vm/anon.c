/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"

/** Project 3: Swap In / Out */
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "lib/kernel/bitmap.h"

static struct bitmap *bitmap;

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in(struct page *page, void *kva);
static bool anon_swap_out(struct page *page);
static void anon_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
    .swap_in = anon_swap_in,
    .swap_out = anon_swap_out,
    .destroy = anon_destroy,
    .type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void vm_anon_init(void) {
    /* TODO: Set up the swap_disk. */
    swap_disk = disk_get(1, 1);
    bitmap = bitmap_create(disk_size(swap_disk) / (PGSIZE / DISK_SECTOR_SIZE));  // 7560개
}

/* Initialize the file mapping */
bool anon_initializer(struct page *page, enum vm_type type, void *kva) {
    /* Set up the handler */
    page->operations = &anon_ops;
    struct anon_page *anon_page = &page->anon;
    anon_page->sec_no = -1;

    return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool anon_swap_in(struct page *page, void *kva) {
    struct anon_page *anon_page = &page->anon;
    disk_sector_t sec_no = anon_page->sec_no;
    if (!bitmap_test(bitmap, sec_no))
        return NULL;

    for (int i = 0; i < 8; i++)
        disk_read(swap_disk, sec_no * 8 + i, kva + DISK_SECTOR_SIZE * i);

    bitmap_reset(bitmap, sec_no);

    return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool anon_swap_out(struct page *page) {
    struct anon_page *anon_page = &page->anon;
    // return true;
    size_t sec_num = bitmap_scan_and_flip(bitmap, 0, 1, 0);
    if (sec_num == BITMAP_ERROR)
        return false;
    disk_sector_t sec_no = sec_num;

    for (int i = 0; i < 8; i++)  
        disk_write(swap_disk, sec_no * 8 + i, page->va + DISK_SECTOR_SIZE * i);

    anon_page->sec_no = sec_no;
    page->frame = NULL;

    pml4_clear_page(thread_current()->pml4, page->va);
    return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void anon_destroy(struct page *page) {
    struct anon_page *anon_page = &page->anon;
    if (!anon_page->sec_no)
        bitmap_reset(bitmap, anon_page->sec_no);

    if (page->frame) {
        list_remove(&page->frame->f_elem);
        page->frame->page = NULL;
        palloc_free_page(page->frame->kva);
        free(page->frame);
        page->frame = NULL;
    }

    pml4_clear_page(thread_current()->pml4, page->va);
}
