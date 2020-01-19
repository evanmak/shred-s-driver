#include <stdio.h>
#include <stdlib.h>	/* exit */
#include <pthread.h>
#include "shred_wrapper.h"	/* shred_* */

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>	/* getttid */

#define SID_SHARE	15
#define SHARE		1
#define NO_SHARE	0

#define THREAD_NUM	10
#define STRESS_DEGREE	100

#define COLORS		8
#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

#define TEST_S_POOL_ALLOC
#define TEST_SPL_COUNT		1	
#define ALLOC_SIZE		10

/* for create threads use */
pthread_t threads[THREAD_NUM];

void* test_shared_shred_conc(void *ss_pool) {
	int i;
	pid_t tid;
	int *addr;
	char *colors[COLORS] = {KRED, KGRN, KBLU, KMAG, KNRM, KYEL, KCYN, KWHT};

#ifdef TEST_S_POOL_ALLOC
	int size_array[ALLOC_SIZE] = {1, 1, 4, 5, 8, 11, 100, 1000, 10000, 50000};
#endif

	/* get thread_id */
	tid = syscall(__NR_gettid);

	/* choose a place to write in shared s_pool, hopefully tid%101 won't collude */
	addr = (int *)ss_pool + (tid % 101);

	printf("%stid = %d, concurrent test of shared shred begin.\n", colors[tid % COLORS], tid);
	shred_enter(SID_SHARE, SHARE);
	printf("%stid = %d, test write ss_pool, addr = 0x%p, val = %d\n", colors[tid % COLORS], tid, addr, tid);
	*addr = tid;
	printf("%stid = %d, test read ss_pool, addr = 0x%p, val = %d\n", colors[tid % COLORS], tid, addr, *addr);
	shred_exit(SID_SHARE);
	printf("%stid = %d, concurrent test of shared shred end.\n", colors[tid % COLORS], tid);

	printf("\n");
	printf("%stid = %d, stress test of shared shred begin\n", colors[tid % COLORS], tid);
	for (i = 0; i < STRESS_DEGREE; i++) {
		shred_enter(SID_SHARE, SHARE);
		printf("%stid = %d stress test times = %d\n", colors[tid % COLORS], tid, i);
		shred_exit(SID_SHARE);

	} 

#ifdef TEST_S_POOL_ALLOC
	printf("%stid = %d, stress test of s_pool_alloc start\n", colors[tid % COLORS], tid);
	shred_enter(tid, NO_SHARE);

	void *s_addr[TEST_SPL_COUNT];
	for (i = 0; i < TEST_SPL_COUNT; i++) {
		s_addr[i] = s_pool_alloc(size_array[i % ALLOC_SIZE]);
		printf("%stid = %d s_pool_alloc: alloc_size:%d, s_addr:0x%p\n", colors[tid % COLORS], tid, size_array[i], s_addr[i]);
	}

	for (i = 0; i < TEST_SPL_COUNT; i++) {
		s_pool_free(s_addr[i]);
		printf("%stid = %d s_pool_free: alloc_size:%d, s_addr:0x%p\n", colors[tid % COLORS], tid, size_array[i], s_addr[i]);
	}

	shred_exit(tid);
	printf("%stid = %d, stress test of s_pool_alloc end\n", colors[tid % COLORS], tid);
#endif

	printf("%stid = %d, stress test of shared shred end\n", colors[tid % COLORS], tid);
	printf("\n");

	return NULL;
}

int main (int argc, char *argv[]) {
	/**
	 * shared shred test:
	 *	1. basic test: enter, alloc, write, exit;
	 * 	2. concurrency test: create a bounch of threads, with each enter and write and exit;
	 *	3. stress test: enter/exit continuously.
	 */
	int i;
	void *ss_pool;

	printf("shared shred test -- basic test begin: enter, alloc, write, exit.\n");
	shred_enter(SID_SHARE, SHARE);

	/**
	 * ss_pool: shared s_pool;
	 * shred_alloc(int size) : size = 1 means 1MB
	 */
	ss_pool = shred_alloc(1);
	if (ss_pool == NULL) {
		printf("shred_alloc: failed, return NULL!\n");
		exit(-1);
	} else if ((int)ss_pool < 0) {
		printf("shred_alloc: failed, ret_val = %d, which < 0 indicates error!\n", (int)ss_pool);
		exit(-1);
	} else {
		printf("shred_alloc: succeed! ss_pool = 0x%p\n", ss_pool);
	}

	shred_exit(SID_SHARE);
	printf("shared shred test -- basic test end!\n");

	printf("\n");
	printf("shared shred test -- concurrency test begin:\n");
	printf("test process :\n");
	printf("\t1. create four threads, each enter the same shared shred, and write ss_pool, and then exit\n");
	printf("\t2. Stress test under concurrent execution: enter/exit continuously for a given number: %d\n", STRESS_DEGREE);

	for (i = 0; i < THREAD_NUM; i++)
		pthread_create(&threads[i], NULL, &test_shared_shred_conc, (void *)ss_pool);

	/* wait for all child thread terminate */
	for (i = 0; i < THREAD_NUM; i++)
		pthread_join(threads[i], NULL);

	printf("shared shred test -- concurrency test end!\n");

	return 0;
}
