#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/debug.h"

void syscall_init (void);
struct lock filesys_lock;
struct vm_entry *check_address (void *addr, void *rsp UNUSED);

#endif /* userprog/syscall.h */
