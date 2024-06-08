#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "lib/string.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/init.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "userprog/process.h"
#include "lib/kernel/stdio.h"
#include "lib/string.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "intrinsic.h"
#include "vm/vm.h"

#define STDIN_FILENO	0
#define STDOUT_FILENO	1

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void check_address (void *addr);

/* System Call Function */
void halt (void);
void exit (int status);
tid_t fork (const char *thread_name);
int exec (const char *cmd_line);
int wait (tid_t tid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
void *mmap (void *addr, size_t length, int writable, int fd, off_t offset);
void munmap (void *addr);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	
	sema_init(&filesys_sema, 1);
}

void
check_address (void *addr) {
	if (addr == NULL || is_kernel_vaddr(addr))
		exit(-1);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	// TODO: Your implementation goes here.
	check_address(f->rsp);

	int syscall_number = f->R.rax;
	void *arg1 = f->R.rdi;
	void *arg2 = f->R.rsi;
	void *arg3 = f->R.rdx;
	void *arg4 = f->R.r10;
	void *arg5 = f->R.r8;

	thread_current()->rsp = f->rsp;		// For "Stack Growth"
	switch(syscall_number) {
		case SYS_HALT : 
			halt();
			break;
		case SYS_EXIT :
			exit(arg1);
			break;
		case SYS_FORK :
			thread_current()->saved_if = f;
			f->R.rax = fork(arg1);
			break;
		case SYS_EXEC :
			f->R.rax = exec(arg1);
			break;
		case SYS_WAIT :
			f->R.rax = wait(arg1);
			break;
		case SYS_CREATE :
			f->R.rax = create(arg1, arg2);
			break;
		case SYS_REMOVE :
			f->R.rax = remove(arg1);
			break;
		case SYS_OPEN :
			f->R.rax = open(arg1);
			break;
		case SYS_FILESIZE :
			f->R.rax = filesize(arg1);
			break;
		case SYS_READ :
			f->R.rax = read(arg1, arg2, arg3);
			break;
		case SYS_WRITE :
			f->R.rax = write(arg1, arg2, arg3);
			break;
		case SYS_SEEK :
			seek(arg1, arg2);
			break;
		case SYS_TELL :
			f->R.rax = tell(arg1);
			break;
		case SYS_CLOSE :
			close(arg1);
			break;
		case SYS_MMAP :
			f->R.rax = mmap(arg1, arg2, arg3, arg4, arg5);
			break;
		case SYS_MUNMAP :
			munmap(arg1);
			break;
	}
}

/* ========= System Call Function ========= */
/* =========== Process Related =========== */
void
halt (void) {
	power_off();
}

void
exit (int status) {
	struct thread *curr_thread = thread_current();
	curr_thread->exit_status = status;
	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
}

tid_t
fork (const char *thread_name) {
	return process_fork(thread_name);
}

int
exec (const char *cmd_line) {
	check_address(cmd_line);

	char *copy = palloc_get_page(PAL_ZERO);
	if (copy == NULL)	exit(-1);

	strlcpy(copy, cmd_line, PGSIZE);
	return process_exec(copy);
}

int 
wait (tid_t tid) {
	return process_wait(tid);
}

/* =========== File System Related =========== */
bool 
create (const char *file, unsigned initial_size) {
	check_address(file);
	
	sema_down(&filesys_sema);
	bool success = filesys_create(file, initial_size);
	sema_up(&filesys_sema);
	return success;
}

bool
remove (const char *file) {
	check_address(file);
	return filesys_remove(file);
}

int
open (const char *file) {
	check_address(file);
	sema_down(&filesys_sema);

	struct file *open_file = filesys_open(file);

	if (open_file == NULL) {
		sema_up(&filesys_sema);
		return -1;
	}

	int fd = add_file(open_file);
	if (fd == -1)	file_close(open_file);
	sema_up(&filesys_sema);
	return fd;
}

int
filesize (int fd) {
	struct file *file = get_file(fd);

	if (file == NULL)	return -1;
	return file_length(file);
}

int 
read (int fd, void *buffer, unsigned size) {
	check_address(buffer);
	// check_valid_buffer(buffer, size, NULL, true);

	sema_down(&filesys_sema);
	if (fd == STDIN_FILENO) {
		char *buf = buffer;
		for (int i = 0; i < size; i++) {
			buf[i] = input_getc();
		}
		sema_up(&filesys_sema);
		return size;
	}

	struct file *file = get_file(fd);
	if (file == NULL) {
		sema_up(&filesys_sema);
		return -1;
	}

	// for "page-merge" test
	struct page *page = spt_find_page(&thread_current()->spt, buffer);
    if (page && !page->writable) {
        sema_up(&filesys_sema);
        exit(-1);
    }

	int result = file_read(file, buffer, size);
	sema_up(&filesys_sema);
	return result;
}

int
write (int fd, const void *buffer, unsigned size) {
    // check_valid_buffer(buffer, size, NULL, false);
	check_address(buffer);

    sema_down(&filesys_sema);
	if (fd == STDOUT_FILENO) {
        putbuf(buffer, size);
		sema_up(&filesys_sema);
        return size;
    } 

    struct file *file = get_file(fd);
    if (file == NULL) {
		sema_up(&filesys_sema);
		return -1;
	}

	int result = file_write(file, buffer, size);
	sema_up(&filesys_sema);
    return result;
}

void 
seek (int fd, unsigned position) {
	struct file *file = get_file(fd);

	if (file == NULL)	return NULL;
	file_seek(file, position);
}

unsigned 
tell (int fd) {
	struct file *file = get_file(fd);

	if (file == NULL)	return -1;
	return file_tell(file);
}

void
close (int fd) {
	struct file *file = get_file(fd);

	if (file != NULL) {
		file_close(file);
		set_file(fd, NULL);
	}	
}

void *
mmap (void *addr, size_t length, int writable, int fd, off_t offset) {
	if ((int)length <= 0)
		return NULL;

	if (offset % PGSIZE != 0)
		return NULL;
	
	if (addr == NULL || addr != pg_round_down(addr)) 
		return NULL;
	
	if (!is_user_vaddr(addr) || !is_user_vaddr(addr + length))
		return NULL;
	
	if (spt_find_page(&thread_current()->spt, addr) != NULL) 
		return NULL;
	
	if (fd == STDIN_FILENO || fd == STDOUT_FILENO) 
		return NULL;
	
	struct file *file = get_file(fd);
	if (file == NULL) 
		return NULL;

	return do_mmap(addr, length, writable, file, offset);
}

void 
munmap (void *addr) {
	do_munmap(addr);
}