#include<sys/types.h>
#include<stdlib.h>
#include<stdio.h>
#include<unistd.h>
#include<sched.h>
#include<pthread.h>
#include"shred_wrapper.h"
#define THREAD_NUM 5 
#define TEST_SHARE

#define WRITE_SPOOL(tid, share) \
	shred_enter(tid,share);\
	*((int *)(addrs[0])) = 4321+tid;\
	printf("\nthread #%d the num is %d\n",(int)getpid() ,*((int *)(addrs[0])));\
	shred_exit(tid);


//#define PRESSURE_TEST(tid,share,times);

#define PRESSURE_TEST(tid,share,times)\
	i= 0;\
	for(; i<30; i++){\
		shred_enter(tid,share);\
		printf("################ tid #%d : %dth time \n", tid,i);\
		shred_exit(tid);\
	}

void *addrs[THREAD_NUM];
pthread_t threads[THREAD_NUM];
void f1(){
    printf("i am f0\n");
}
void f2(){
label2:
    printf("i am f1\n");
}
void f3(){
label3:
    printf("i am f2\n");
}
void f4(){
label4:
    printf("i am f3\n");
}
void f5(){
label5:
    printf("i am f4\n");
}

int share_alloc_flag = 0;
void (*fptr[5])();
void *do_thread(void* id){
	int i;
	int tid = (int)id;
	printf("id#%d @@@@@@@@@@@@@@@@@@  \n", tid);
	
	switch (tid) {
#ifndef TEST_SHARE		
		case 0:
			shred_enter(1,0);
			addrs[tid] = shred_alloc(1);
			fptr[tid] = f1;
			fptr[tid] ();
			shred_exit(1);
			WRITE_SPOOL(1,0);
			PRESSURE_TEST(1,0,10);
			break;
		case 1:
			shred_enter(2,0);
			addrs[tid] = shred_alloc(1);
			fptr[tid] = f2;
			fptr[tid] ();
			shred_exit(2);
			WRITE_SPOOL(2,0);
			PRESSURE_TEST(2,0,10);
			break;
		case 2:
			shred_enter(3,0);
			addrs[tid] = shred_alloc(1);
			fptr[tid] = f3;
			fptr[tid] ();
			shred_exit(3);
			WRITE_SPOOL(3,0);
			PRESSURE_TEST(3,0,10);
			break;
		case 3:
			shred_enter(4,0);
			addrs[tid] = shred_alloc(1);
			fptr[tid] = f4;
			fptr[tid] ();
			shred_exit(4);
			WRITE_SPOOL(4,0);
			PRESSURE_TEST(4,0,10);
			break;
#endif 		

		default:
#ifdef TEST_SHARE
			shred_enter(5,1);
			fptr[tid] = f5;
			fptr[tid] ();
			shred_exit(5);
			WRITE_SPOOL(5,1); 
			PRESSURE_TEST(5,1,10);
#endif
			;
	}
	return NULL;


}

int main(int argc, char **argv){
	int i = 0;
    /*printf("%p, %p\n", &_shred_start, &_shred_end);*/
#ifdef TEST_SHARE
	shred_enter(5,1);
	addrs[0] = shred_alloc(1);
	shred_exit(5);
#endif
	sleep(5);
	for(;i<THREAD_NUM;i++){
		printf("Parent: creating thread #%d\n", i);
		pthread_create(&threads[i], NULL, do_thread, (void *)i);
	}

	sleep(3);
//	pthread_exit(NULL);
	return 0;
}
