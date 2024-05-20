#include "devices/timer.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include "threads/interrupt.h"
#include "threads/io.h"
#include "threads/synch.h"
#include "threads/thread.h"

/* See [8254] for hardware details of the 8254 timer chip. */

#if TIMER_FREQ < 19
#error 8254 timer requires TIMER_FREQ >= 19
#endif
#if TIMER_FREQ > 1000
#error TIMER_FREQ <= 1000 recommended
#endif

/* Number of timer ticks since OS booted. */
static int64_t ticks;

/* Number of loops per timer tick.
   Initialized by timer_calibrate(). */
static unsigned loops_per_tick;

static intr_handler_func timer_interrupt;
static bool too_many_loops (unsigned loops);
static void busy_wait (int64_t loops);
static void real_time_sleep (int64_t num, int32_t denom);

/* Sets up the 8254 Programmable Interval Timer (PIT) to
   interrupt PIT_FREQ times per second, and registers the
   corresponding interrupt. */
// 시스템 타이머 설정하는 함수
void
timer_init (void) {
	/* 8254 input frequency divided by TIMER_FREQ, rounded to
	   nearest. */
	uint16_t count = (1193180 + TIMER_FREQ / 2) / TIMER_FREQ;		// 타이머가 발생하는 주기 설정

	// 하드웨어 제어 및 데이터 전송
	outb (0x43, 0x34);    /* CW: counter 0, LSB then MSB, mode 2, binary. */
	outb (0x40, count & 0xff);	// 0x40 레지스터에 하위 8비트 전송
	outb (0x40, count >> 8);	// 0x40 레지스터에 상위 8비트 전송

	intr_register_ext (0x20, timer_interrupt, "8254 Timer");	// 인터럽트 번호 : 0x20 (타이머 인터럽트), 인터럽트 핸들러 함수, 설명
}

/* Calibrates loops_per_tick, used to implement brief delays. */
// loops_per_tick 값을 보정하는 함수
void
timer_calibrate (void) {
	unsigned high_bit, test_bit;

	ASSERT (intr_get_level () == INTR_ON);
	printf ("Calibrating timer...  ");

	/* Approximate loops_per_tick as the largest power-of-two
	   still less than one timer tick. 
	   타이머 인터럽트 주기보다 큰 값을 선택하여, 정확도를 유지하면서도 최대한 많은 루프를 수행하도록 할 것
	*/
	loops_per_tick = 1u << 10;		// 2의 10제곱으로 초기화 (타이머 인터럽트 한번에 수행되는 루프 횟수)
	while (!too_many_loops (loops_per_tick << 1)) {		// 너무 많은 반복이 발생하지 않을 때까지 2배씩 증가
		loops_per_tick <<= 1;
		ASSERT (loops_per_tick != 0);
	}

	/* Refine the next 8 bits of loops_per_tick. */
	// 다음 8비트를 보정 (더 정밀하게)
	high_bit = loops_per_tick;
	for (test_bit = high_bit >> 1; test_bit != high_bit >> 10; test_bit >>= 1)	// 8비트 차례대로 확인
		if (!too_many_loops (high_bit | test_bit))
			loops_per_tick |= test_bit;

	printf ("%'"PRIu64" loops/s.\n", (uint64_t) loops_per_tick * TIMER_FREQ);
}

/* Returns the number of timer ticks since the OS booted. */
// 현재 시스템에서 발생한 타이머 틱의 수 반환 (현재 시간 측정)
int64_t
timer_ticks (void) {
	enum intr_level old_level = intr_disable ();		// 현재 인터럽트 비활성화 (시간을 체크하는 동안 인터럽트가 발생하지 않도록 보장)
	int64_t t = ticks;									// 현재 타이머 틱수 저장
	intr_set_level (old_level);							// 이전의 인터럽트 상태로 돌아감
	barrier ();											// 코드 재배치 방지
	return t;
}

/* Returns the number of timer ticks elapsed since THEN, which
   should be a value once returned by timer_ticks(). */
// 경과한 시간을 측정하는 함수
int64_t
timer_elapsed (int64_t then) {
	return timer_ticks () - then;
}

/* Suspends execution for approximately TICKS timer ticks. */
// 주어진 tick 수만큼 대기하고, 대기 중에는 다른 스레드에게 CPU 양보
void
timer_sleep (int64_t ticks) {
	int64_t start = timer_ticks ();				// 현재 시간 저장

	ASSERT (intr_get_level () == INTR_ON);		// 현재 인터럽트가 활성화된 상태인지 확인

	if (timer_elapsed (start) < ticks)
		thread_sleep(start + ticks);
}

/* Suspends execution for approximately MS milliseconds. */
void
timer_msleep (int64_t ms) {				// 밀리초 동안 sleep하는 함수
	real_time_sleep (ms, 1000);
}

/* Suspends execution for approximately US microseconds. */
void
timer_usleep (int64_t us) {				// 마이크로초 동안 sleep하는 함수
	real_time_sleep (us, 1000 * 1000);
}

/* Suspends execution for approximately NS nanoseconds. */
void
timer_nsleep (int64_t ns) {				// 나노초 동안 sleep하는 함수
	real_time_sleep (ns, 1000 * 1000 * 1000);
}

/* Prints timer statistics. */
void
timer_print_stats (void) {
	printf ("Timer: %"PRId64" ticks\n", timer_ticks ());
}

/* Timer interrupt handler. */
static void
timer_interrupt (struct intr_frame *args UNUSED) {
	ticks++;							// 타이머 인터럽트가 발생한 횟수 업데이트
	thread_tick ();						// 현재 실행 중인 스레드의 실행 시간 측정

	if (thread_mlfqs)
	{
		increase_recent_cpu();

		if (timer_ticks() % TIMER_FREQ == 0) {
			calculate_load_avg(thread_current());
			recalculate_recent_cpu();
		}
		if (timer_ticks() % 4 == 0)
			recalculate_priority();
	}
	thread_wakeup(ticks);

}

/* Returns true if LOOPS iterations waits for more than one timer
   tick, otherwise false. */
// 실행 시간이 1 timer tick 보다 오래 걸렸는지 체크하는 함수
static bool
too_many_loops (unsigned loops) {
	/* Wait for a timer tick. */
	// 타이머 인터럽트 대기
	int64_t start = ticks;
	while (ticks == start)
		barrier ();

	/* Run LOOPS loops. */
	start = ticks;
	busy_wait (loops);

	/* If the tick count changed, we iterated too long. */
	barrier ();
	return start != ticks;
}

/* Iterates through a simple loop LOOPS times, for implementing
   brief delays.

   Marked NO_INLINE because code alignment can significantly
   affect timings, so that if this function was inlined
   differently in different places the results would be difficult
   to predict. */
// 특정 조건이 충족될 때까지 무한 루프를 돌며 대기하는 함수 (다른 스레드가 CPU를 사용할 수 없음)
static void NO_INLINE
busy_wait (int64_t loops) {
	while (loops-- > 0)
		barrier ();
}

/* Sleep for approximately NUM/DENOM seconds. */
// denom이 단위, num이 sleep할 시간
static void
real_time_sleep (int64_t num, int32_t denom) {
	/* Convert NUM/DENOM seconds into timer ticks, rounding down.

	   (NUM / DENOM) s
	   ---------------------- = NUM * TIMER_FREQ / DENOM ticks.
	   1 s / TIMER_FREQ ticks
	   */
	int64_t ticks = num * TIMER_FREQ / denom;									// 타이머 틱으로 변환 (TIMER_FREQ : 시스템의 타이머 주파수)

	ASSERT (intr_get_level () == INTR_ON);										// 현재 인터럽트가 활성화된 상태인지 확인 (타이머 인터럽트 체크)
	if (ticks > 0) {															// 최소 하나의 tick 이상을 기다려야 함
		/* We're waiting for at least one full timer tick.  Use
		   timer_sleep() because it will yield the CPU to other
		   processes. */
		timer_sleep (ticks);													// CPU를 다른 프로세스에게 양보
	} else {
		/* Otherwise, use a busy-wait loop for more accurate
		   sub-tick timing.  We scale the numerator and denominator
		   down by 1000 to avoid the possibility of overflow. */
		ASSERT (denom % 1000 == 0);												// denom이 1000의 배수인지 체크
		busy_wait (loops_per_tick * num / 1000 * TIMER_FREQ / (denom / 1000));	// 1000으로 나눠서 정밀하게 계산
	}
}
