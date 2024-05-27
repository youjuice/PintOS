#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);
static void argument_stack(char *argv[], int argc, struct intr_frame *_if);

/* General process initializer for initd and other process. */
/* 
 * initd : 시스템 부팅 과정에서 최초로 실행되는 유저 모드 프로세스
 * process_init : initd 및 다른 프로세스를 위한 일반적인 프로세스 초기화 함수
 */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
/*
 * - 이 함수는 FILE_NAME에서 로드된 initd라는 첫번째 유저 프로그램을 시작
 * - 새 스레드가 생성되고 process_create_initd 함수가 반환되기 전에 스케줄링되거나 종료될 수 있음
 * - 함수는 initd의 스레드 ID를 반환하며 스레드를 생성할 수 없는 경우 TID_ERROR 반환
 * - 이 함수는 한번만 호출되어야 함!!
 */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;		// FILE_NAME의 복사본을 저장할 포인터
	tid_t tid;			// 새로 생성된 스레드 ID를 저장할 변수

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);			// 페이지를 할당하여 FILE_NAME의 복사본을 저장할 메모리 확보
	if (fn_copy == NULL)					// 메모리 할당에 실패한 경우,
		return TID_ERROR;					// TID_ERROR 반환
	strlcpy (fn_copy, file_name, PGSIZE);	// FIME_NAME을 fn_copy로 복사

	/* Create a new thread to execute FILE_NAME. */
	char *save_ptr;
	strtok_r(file_name, " ", &save_ptr);

	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);	// 스레드 생성
	if (tid == TID_ERROR)											// 실패한 경우, 
		palloc_free_page (fn_copy);									// fn_copy에 할당된 페이지 해제
	return tid;														// 새로 생성된 스레드 ID 반환
}

/* A thread function that launches first user process. */
/* 첫번째 사용자 프로세스를 시작하는 스레드 함수 */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();						// 프로세스 초기화

	if (process_exec (f_name) < 0)			// f_name에 지정된 프로그램 실행
		PANIC("Fail to launch initd\n");	// 실패하면, 시스템 중지 및 오류 메세지 출력
	NOT_REACHED ();		
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
/* 현재 프로세스를 name으로 복제하고 새 프로세스의 스레드 ID를 반환하는 함수 */
tid_t 
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
    struct thread *parent_thread = thread_current();
    
    tid_t child_pid = thread_create(name, PRI_DEFAULT, __do_fork, parent_thread);
    if (child_pid == TID_ERROR) 	return TID_ERROR;
    
    struct thread *child_thread = get_child_thread(child_pid);
    if (child_thread == NULL) 		return TID_ERROR;	
    
    sema_down(&child_thread->fork_sema); // 부모 스레드 대기 시킴
    return child_pid;
}


#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
/* pml4_for_each에 이 함수를 전달하여 부모의 주소 공간을 복제하는 함수 (for Project 2) */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;	// 부모 스레드를 가리키는 포인터를 aux에서 가져옴
	void *parent_page;								// 부모 페이지를 가리킬 포인터
	void *newpage;									// 새 페이지를 가리킬 포인터
	bool writable;									// 새 페이지의 쓰기 가능 여부를 나타내는 변수

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	/* 1. TODO: 부모 페이지가 커널 페이지인 경우 즉시 반환 */
	if (is_kernel_vaddr(va))	return true;

	/* 2. Resolve VA from the parent's page map level 4. */
	/* 2. 부모의 페이지 맵 레벨 4에서 VA 해결 */
	parent_page = pml4_get_page (parent->pml4, va);
	if (parent_page == NULL)	return false;

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	/* 3. TODO: 자식을 위한 새로운 PAL_USER 페이지를 할당하고 NEWPAGE에 결과 설정*/
	newpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if (newpage == NULL)		return false;

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	/* 4. 부모의 페이지를 새 페이지로 복제하고 부모의 페이지가 쓰기 가능한지 확인 (결과에 따라 WRITABLE 설정)*/
	memcpy(newpage, parent_page, PGSIZE);
	writable = is_writable(pte);

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	/* 5. 주소 VA에 WRITABLE 권한으로 새 페이지를 자식의 페이지 테이블에 추가 */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		/* 6. TODO: 만약 실패한 경우 에러 처리 */
		return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
/* 부모의 실행 컨텍스트를 복사하는 스레드 함수 */
static void
__do_fork (void *aux) {
	struct intr_frame if_;		// 인터럽트가 발생했을 때 스레드의 상태를 저장하는 구조체
	struct thread *parent = (struct thread *) aux;	// 보조 데이터로 전달된 포인터를 parent에 캐스팅
	struct thread *current = thread_current ();		
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if = parent->saved_if;
	bool succ = true;

	/* 1. Read the cpu context to local stack. */
	/* 1. 부모의 인터럽트 프레임을 현재 스레드의 인터럽트 프레임에 복사 */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));
	if_.R.rax = 0;

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();	// 새로운 페이지 테이블을 생성하여 현재 스레드의 페이지 맵 레벨 4에 할당
	if (current->pml4 == NULL) 		// 실패하면 error로 이동
		goto error;
	
	process_activate (current);		// 현재 스레드 활성화
	
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))	// 각 페이지 테이블 엔트리 복제
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent. */
	/* - 파일을 복제하는 코드를 여기에 추가.
	 * - 파일 객체를 복제하기 위해서는 file_duplicate 함수 사용 
	 * - 부모는 이 함수가 부모의 리소스를 성공적으로 복제할 때까지 fork()에서 반환해서는 안됨. */
	current->fd_table[0] = parent->fd_table[0];
	current->fd_table[1] = parent->fd_table[1];
	for (int i = 2; i < 128; i++) {
		if (parent->fd_table[i] != NULL)
			current->fd_table[i] = file_duplicate(parent->fd_table[i]);
	}
	
	sema_up(&current->fork_sema);	// 초기화 완료 -> 부모 스레드 진행 !!
	process_init();	// 프로세스 초기화

	/* Finally, switch to the newly created process. */
	if (succ)				// 성공하면,
		do_iret (&if_);		// 새로운 프로세스로 전환
error:						// 오류 발생시,
	current->exit_status = TID_ERROR;
	sema_up(&current->fork_sema);
	thread_exit ();			// 스레드 종료
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
/* 주어진 파일 이름으로부터 실행 컨텍스트를 변경하여 새로운 프로세스를 시작하는 함수 */
int
process_exec (void *f_name) {
	char *file_name = f_name;
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	/* 인터럽트 프레임 설정 */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;	// 사용자 데이터 세그먼트로 설정
	_if.cs = SEL_UCSEG;						// 사용자 코드 세그먼트로 설정
	_if.eflags = FLAG_IF | FLAG_MBS;		// 인터럽트 플래그와 모드 비트 설정

	/* We first kill the current context */
	process_cleanup ();						// 현재 실행 중인 컨텍스트 정리

	/* Parse the command line */
	char *token_list[100];		// token을 저장할 리스트 
	int token_index = 0;		// token index
	char *token, *save_ptr;

	for (token = strtok_r(file_name, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr))
		token_list[token_index++] = token;

	/* And then load the binary */
	success = load (file_name, &_if);		// 주어진 파일을 로드하여 새로운 프로세스 시작

	/* If load failed, quit. */
	if (!success) {
		return -1;		
	}

	/* Set up Stack & Push */ 
	argument_stack(&token_list, token_index, &_if);

	/* Debug Code */
	// hex_dump(_if.rsp, _if.rsp, USER_STACK - _if.rsp, true);
	
	palloc_free_page (file_name);			// 페이지 해제

	/* Start switched process. */
	do_iret (&_if);							// _if에 저장된 새로운 실행 컨텍스트로 전환
	NOT_REACHED ();
}

/* ======== Custom Function ======== */
// 인수들을 스택 구조에 맞게 push 하는 함수
static void
argument_stack(char *argv[], int argc, struct intr_frame *_if)
{
	uintptr_t argv_address[argc];

	// Section 1 : argv[i] 데이터 push
	for (int i = argc - 1; i >= 0; i--)
	{
		_if->rsp -= (strlen(argv[i]) + 1);
		memcpy(_if->rsp, argv[i], strlen(argv[i]) + 1);
		argv_address[i] = _if->rsp;
	}

	// Section 2 : word-align (주소값 8의 배수로 맞춰주기)
	while (_if->rsp % 8 != 0)
	{
		_if->rsp --;
		memset(_if->rsp, 0, sizeof(uint8_t));
	}

	// Section 3 : argv[i] 주솟값 push
	for (int i = argc; i >= 0; i--)
	{
		_if->rsp -= sizeof(uintptr_t);
		if (i == argc)	memset(_if->rsp, 0, sizeof( uintptr_t));
		else			memcpy(_if->rsp, &argv_address[i], sizeof(uintptr_t));
	}

	// Section 4 : %rsi, %rdi 세팅
	_if->R.rsi = _if->rsp;
	_if->R.rdi = argc;

	// Section 5 : Return Address
	_if->rsp -= sizeof(uintptr_t);
	memset(_if->rsp, 0, sizeof(uintptr_t));
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
/*
 * 스레드 ID가 종료될 때까지 대기하고 종료 상태를 반환하는 함수
 * 1. 만약 스레드가 커널에 의해 종료되었다면(예외) -1 반환
 * 2. 만약 스레드 ID가 유효하지 않거나 호출하는 프로세스의 자식이 아니거나 
 * 3. 이미 주어진 스레드 ID에 대해 process_wait()가 호출되었다면, 즉시 -1 반환
 * -> 현재는 아무 동작도 하지 않고 그냥 -1 반환 (실제로 동작하도록 구현해라.)
 */
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	struct thread *child_thread = get_child_thread(child_tid);
	if (child_thread == NULL) 	return -1;

	sema_down(&child_thread->wait_sema);
	list_remove(&child_thread->child_elem);
	sema_up(&child_thread->free_sema);

	return child_thread->exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
/* 프로세스를 종료하는 함수 thread_exit() 함수에 의해 호출 */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */

	// 1. 파일 디스크립터 정리
	for (int i = 2; i < 128; i++) {
        if (curr->fd_table[i] != NULL) {
            file_close(curr->fd_table[i]);
            curr->fd_table[i] = NULL; 
        }
    }

	// 2. 남은 자원 정리
	process_cleanup ();

	// 3. 동기화 (wait_sema & free_sema)
	sema_up(&curr->wait_sema);
	sema_down(&curr->free_sema);
}

/* Free the current process's resources. */
/* 현재 프로세스의 자원을 정리하는 함수 */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
/* 다음 스레드의 유저 코드를 실행하기 위해 CPU 설정을 처리하는 함수 (모든 문맥 전환시 호출)*/
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);		// 다음 스레드의 페이지 테이블 활성화 (즉, 다음 스레드의 주소 공간에 접근할 수 있도록 설정)

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);				// 현재 스레드의 커널 스택 설정 (인터럽트 처리를 위해 사용됨)
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
/* ELF 파일을 현재 스레드로 로드하는 함수 */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	/* 페이지 디렉토리를 할당하고 활성화 */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	/* Open executable file. */
	/* 실행 파일을 open */
	file = filesys_open (file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	/* Read and verify executable header. */
	/* ELF 헤더를 읽고 검증, 올바른 ELF 파일인지 확인 */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	/* 프로그램 헤더를 읽어들임. 각 프로그램 헤더에 따라 세그먼트 로드 */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {				// 현재 프로그램 헤더의 유효성 검증
					bool writable = (phdr.p_flags & PF_W) != 0;		// 현재 세그먼트가 쓰기 가능한지 체크
					uint64_t file_page = phdr.p_offset & ~PGMASK;	// ELF 파일에서 세그먼트의 시작 페이지 오프셋 계산
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;		// 메모리에서 세그먼트가 로드될 시작 주소 계산
					uint64_t page_offset = phdr.p_vaddr & PGMASK;	// 세그먼트 시작 주소에서 페이지 내의 오프셋 계산
					uint32_t read_bytes, zero_bytes;				// 읽을 바이트 수와 0으로 초기화할 바이트 수 저장
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	file_close (file);
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */
