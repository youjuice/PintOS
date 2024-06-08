/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "lib/string.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
	struct load_info *file_info = (struct load_info *)page->uninit.aux;

	file_page->file = file_info->file;
	file_page->offset = file_info->offset;
	file_page->read_bytes = file_info->read_bytes;
	file_page->zero_bytes = file_info->zero_bytes;

	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;

	file_read_at(file_page->file, kva, file_page->read_bytes, file_page->offset);
	memset(kva + file_page->read_bytes, 0, file_page->zero_bytes);
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;

	if (pml4_is_dirty(thread_current()->pml4, page->va))
    {
        file_write_at(file_page->file, page->va, file_page->read_bytes, file_page->offset);
        pml4_set_dirty(thread_current()->pml4, page->va, false);
    }
    pml4_clear_page(thread_current()->pml4, page->va);

	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;

    if (pml4_is_dirty(thread_current()->pml4, page->va)) 
	{
        file_write_at(file_page->file, page->va, file_page->read_bytes, file_page->offset);
        pml4_set_dirty(thread_current()->pml4, page->va, false);
    }
    pml4_clear_page(thread_current()->pml4, page->va);
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	struct file *map_file = file_reopen(file);

	off_t file_bytes = file_length(map_file);
	size_t read_bytes = length > file_bytes ? file_bytes : length;
	size_t zero_bytes = PGSIZE - (read_bytes % PGSIZE);
	void *file_address = addr;
	int page_cnt = (length + PGSIZE - 1) / PGSIZE;

	while (read_bytes > 0 || zero_bytes > 0) {
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		struct load_info *map_info = malloc(sizeof(struct load_info));
		map_info->file = map_file;
		map_info->offset = offset;
		map_info->read_bytes = page_read_bytes;
		map_info->zero_bytes = page_zero_bytes;

		if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, lazy_load_segment, map_info)) {
			file_close(map_file);
			return NULL;
		}

		spt_find_page(&thread_current()->spt, addr)->map_page_cnt = page_cnt;

		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		offset += page_read_bytes;
		addr += PGSIZE;
	}
	return file_address;
}

/* Do the munmap */
void 
do_munmap (void *addr) {   
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page *page = spt_find_page(spt, addr);
	int count = page->map_page_cnt;

	for (int i = 0; i < count; i++) {
		if (page != NULL)
			destroy(page);
		addr += PGSIZE;
		page = spt_find_page(spt, addr);
	}	
}
