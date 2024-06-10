/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "threads/mmu.h"
#include "lib/string.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&frame_table);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		struct page *page = malloc(sizeof(struct page));
		if (page == NULL)
			goto err;

		switch (VM_TYPE(type)) {
			case VM_ANON:
				uninit_new(page, upage, init, type, aux, anon_initializer);
				break;
			case VM_FILE:
				uninit_new(page, upage, init, type, aux, file_backed_initializer);
				break;
		}
		page->writable = writable;
		return spt_insert_page(spt, page);
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *search_page = malloc(sizeof(struct page));		// 검색용 page 할당
	search_page->va = pg_round_down(va);

	struct hash_elem *find_elem = hash_find(&spt->pages, &search_page->h_elem);
	free(search_page);											// 임시 page 메모리 해제

	if (find_elem == NULL)		return NULL;
	return hash_entry(find_elem, struct page, h_elem);
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	return hash_insert(&spt->pages, &page->h_elem) == NULL;
}

bool
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	hash_delete(&spt->pages, &page->h_elem);
	vm_dealloc_page (page);
	return true;
} 

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	 /* TODO: The policy for eviction is up to you. */
	struct frame *victim = NULL;

	for (struct list_elem *e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e)) {
		victim = list_entry(e, struct frame, f_elem);
		
		if (victim->page == NULL) 
			return victim;

		if (pml4_is_accessed(thread_current()->pml4, victim->page->va)) {
			pml4_set_accessed(thread_current()->pml4, victim->page->va, 0);
			list_remove(e);
			list_push_back(&frame_table, &victim->f_elem);
		}
		else 
			return victim;
	}
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	swap_out(victim->page);

	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	/* TODO: Fill this function. */
	struct frame *frame = (struct frame *)malloc(sizeof(struct frame)); 
	frame->kva = palloc_get_page(PAL_USER); 

	// 페이지 할당 실패 시, 페이지 교체
	if (frame->kva == NULL) {
		frame = vm_evict_frame();
		frame->page = NULL;
		return frame;
	}
								  
	list_push_back(&frame_table, &frame->f_elem);
	frame->page = NULL;

	ASSERT(frame != NULL);
	ASSERT(frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	vm_alloc_page(VM_ANON | VM_MARKER_0, addr, true);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;

	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	// 얘는 진짜 페이지 폴트!!
	if (addr == NULL || is_kernel_vaddr(addr))
		return false;
	
	// 얘는 가짜 페이지 폴트..
	if (not_present) {
		/* 
		 * [ Stack Growth ]
		 * - USER 모드에서의 페이지 폴트라면 현재 rsp를 그대로 사용 가능
		 * - But, KERNEL 모드에서의 페이지 폴트라면 유저 모드에서 커널 모드로 전환될 때 저장해둔 rsp를 가져와야 함!!
		 */
		void *rsp_stack = user ? f->rsp : thread_current()->rsp;
		if (USER_STACK > addr && addr > USER_STACK - (1 << 20)) {
			if (addr >= rsp_stack - 8)
				vm_stack_growth(pg_round_down(addr));
		}

		struct page *page = spt_find_page(spt, addr);
		if (page == NULL)
			return false;
		if (write == true && page->writable == false)
			return false;
		return vm_do_claim_page (page);
	}
	return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = spt_find_page(&thread_current()->spt, va);
	if (page == NULL) 	return false;
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	if(pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable)) 
		return swap_in (page, frame->kva);
	else
		return false;
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->pages, vm_hash_func, vm_less_func, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
			struct hash_iterator it;
			hash_first(&it, &src->pages);
			while(hash_next(&it)) {
				struct page *src_page = hash_entry(hash_cur(&it), struct page, h_elem);
				enum vm_type type = src_page->operations->type;

				switch(VM_TYPE(type)) {
					case VM_UNINIT:
						if (!vm_alloc_page_with_initializer(VM_ANON, src_page->va, src_page->writable, src_page->uninit.init, src_page->uninit.aux))
							return false;
						continue;
					case VM_ANON:
						if (!vm_alloc_page(VM_ANON, src_page->va, src_page->writable))
							return false;
						break;
					case VM_FILE: {
						struct load_info *copy_info = malloc(sizeof(struct load_info));
						copy_info->file = src_page->file.file;
						copy_info->offset = src_page->file.offset;
						copy_info->read_bytes = src_page->file.read_bytes;
						copy_info->zero_bytes = src_page->file.zero_bytes;

						if (!vm_alloc_page_with_initializer(VM_FILE, src_page->va, src_page->writable, NULL, copy_info))
							return false;
						continue;
					}
					default:
						return false;
				}
				if (vm_claim_page(src_page->va)) {
					struct page *new_page = spt_find_page(dst, src_page->va);
					memcpy(new_page->frame->kva, src_page->frame->kva, PGSIZE);
				}
				else
					return false;
			}
			return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->pages, page_destroy_func);
}

/* ========== Custom Function ========== */
unsigned
vm_hash_func (struct hash_elem *e, void *aux) {
	struct page *page_e = hash_entry(e, struct page, h_elem);
	return hash_bytes(&page_e->va, sizeof(page_e->va));
}

bool
vm_less_func (struct hash_elem *a, struct hash_elem *b, void *aux) {
	struct page *page_a = hash_entry(a, struct page, h_elem);
	struct page *page_b = hash_entry(b, struct page, h_elem);
	return page_a->va < page_b->va;
}

void 
page_destroy_func(struct hash_elem *hash_elem) {
	struct page *page = hash_entry(hash_elem, struct page, h_elem);
	destroy(page);
	free(page);
}

// For syscall.c
// void
// check_valid_buffer (void *buffer, unsigned size, void *rsp, bool to_write) {
// 	uint8_t *buf_addr = (uint8_t *)buffer;
// 	uint8_t *end_addr = buf_addr + size - 1;

// 	// Case 1. buffer의 크기가 한 페이지를 넘지 않는 경우
// 	if (pg_round_down(buf_addr) == pg_round_down(end_addr)) {
// 		struct page *page = check_address(buffer, rsp);
// 		if (page == NULL || page->writable != to_write) 
// 			exit(-1);
// 	}
// 	// Case 2. buffer의 크기가 한 페이지를 넘는 경우
// 	else {
// 		for (uint8_t *addr = buf_addr; addr <= end_addr; addr += PGSIZE) {
// 			struct page *page = check_address(addr, rsp);
// 			if (page == NULL || page->writable != to_write) 
// 				exit(-1);
// 		}
// 	}
// }

/* 참조 비트 쉬프트 알고리즘 */
/* Get the struct frame, that will be evicted. */
// static struct frame *
// vm_get_victim (void) {
// 	 /* TODO: The policy for eviction is up to you. */
// 	struct list_elem *min_reference_bit = list_min(&frame_table, bit_less_func, NULL);
// 	struct frame *victim = list_entry(min_reference_bit, struct frame, f_elem);
// 	return victim;
// }

// /* For min_reference_bit */
// bool
// bit_less_func (struct list_elem *a, struct list_elem *b, void *aux) {
// 	struct frame *frame_a = list_entry(a, struct frame, f_elem);
// 	struct frame *frame_b = list_entry(b, struct frame, f_elem);

// 	return frame_a->reference_bit < frame_b->reference_bit;
// }

// /* Set Reference Bit */
// void set_reference_bit(struct frame *frame) {
// 	for (struct list_elem *e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e)) {
// 		struct frame *f = list_entry(e, struct frame, f_elem);
// 		f->reference_bit >>= 1;
// 	}

// 	if (frame != NULL)
// 		frame->reference_bit |= (1 << 7);
// }