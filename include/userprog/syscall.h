#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/debug.h"

void syscall_init (void);
void check_address (void *addr);

/* File System Semaphore */
struct semaphore filesys_sema;

#endif /* userprog/syscall.h */
