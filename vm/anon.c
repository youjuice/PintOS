/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "threads/mmu.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1, 1);

	// (PGSIZE / DISK_SECTOR_SIZE) -> swap 공간에 넣을 수 있는 페이지 개수 (8)
	int swap_disk_size = disk_size(swap_disk) / 8; 
	swap_table = bitmap_create(swap_disk_size);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;

	// 1. page 구조체에 sector index 설정
	disk_sector_t start_sector = anon_page->sector_index;
	anon_page->sector_index = -1;

	// 2. 저장해둔 sector의 page를 8개로 분할해 read
	for (int i = 0; i < 8; i++) {
		disk_read(swap_disk, start_sector + i, kva + (i * DISK_SECTOR_SIZE));
	}

	// 3. swap-in 했으니 해당 슬롯 false 처리
	int swap_index = start_sector / 8;
	bitmap_set(swap_table, swap_index, false);

	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;

	// 1. page가 들어갈 수 있는 sector 검색 (first-fit)
	int swap_index = bitmap_scan_and_flip(swap_table, 0, 1, false);
	if (swap_index == BITMAP_ERROR)		return false;

	// 2. 해당 sector에 page를 8개로 분할해 write
	disk_sector_t start_sector = swap_index * 8;
	uintptr_t *va = page->va;
	
	for (int i = 0; i < 8; i++) {
		disk_write(swap_disk, start_sector + i, va + (i * DISK_SECTOR_SIZE));
	}

	// 3. swap-out 한 페이지는 페이지 테이블에서 삭제
	pml4_clear_page(thread_current()->pml4, page->va);

	// 4. sector_index 업데이트
	anon_page->sector_index = start_sector;

	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
}
