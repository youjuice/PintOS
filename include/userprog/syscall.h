#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/debug.h"

void syscall_init (void);
struct lock filesys_lock;
void check_address (void *addr);

#endif /* userprog/syscall.h */
