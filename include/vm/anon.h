#ifndef VM_ANON_H
#define VM_ANON_H
#include "vm/vm.h"
#include "kernel/bitmap.h"

struct page;
enum vm_type;
struct bitmap *swap_table;

struct anon_page {
    int sector_index;     // page가 저장된 sector 번호 (시작 번호)
};

void vm_anon_init (void);
bool anon_initializer (struct page *page, enum vm_type type, void *kva);

#endif
