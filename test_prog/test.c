#include<sys/syscall.h>
#include<stdlib.h>
#include<stdio.h>
#include<unistd.h>
#include<sched.h>
#include"shred_wrapper.h"
#define THREAD_NUM 4
void *addrs[THREAD_NUM];
int tid[5] = {1,2,3,4,5};
#define WRITE_SPOOL(tid, share) \
	shred_enter(tid,share);\
printf("@@@@@@@@@@@@@@@@@@\n");\
*((int *)(addrs[tid])) = 4321+tid;\
printf("################  \n");\
printf("\nthread #%d the num is %d\n",tid ,*((int *)(addrs[tid])));\
shred_exit(tid);


#define PRESSURE_TEST(tid,share,times)\
	i= 0;\
for(; i<30; i++){\
	shred_enter(tid,share);\
	printf("################ tid #%d : %dth time \n", tid,i);\
	shred_exit(tid);\
}
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

void (*fptr[5])();
void do_thread(int id){
	int i;
	printf("id#%d @@@@@@@@@@@@@@@@@@  \n",id);
	switch (id) {
		case 1:
			shred_enter(1,0);
			addrs[id] = shred_alloc(1);
			fptr[id] = f1;
			fptr[id] ();
			shred_exit(1);
			WRITE_SPOOL(1,0);
			PRESSURE_TEST(1,0,10);
			break;
		case 2:
			shred_enter(2,0);
			addrs[id] = shred_alloc(1);
			fptr[id] = f2;
			fptr[id] ();
			shred_exit(2);
			WRITE_SPOOL(2,0);
			PRESSURE_TEST(2,0,10);
			break;
		case 3:
			shred_enter(3,0);
			addrs[id] = shred_alloc(1);
			fptr[id] = f3;
			fptr[id] ();
			shred_exit(3);
			WRITE_SPOOL(3,0);
			PRESSURE_TEST(3,0,10);
			break;
		case 4:
			shred_enter(4,0);
			addrs[id] = shred_alloc(1);
			fptr[id] = f4;
			fptr[id] ();
			shred_exit(4);
			WRITE_SPOOL(4,0);
			PRESSURE_TEST(4,0,10);
			break;
		default:
			shred_enter(5,0);
			fptr[id] = f5;
			fptr[id] ();
			addrs[id] = shred_alloc(1);
			shred_exit(5);
			WRITE_SPOOL(5,0);
			PRESSURE_TEST(5,0,10);
	}
}

int main(int argc, char **argv){
	int i = 0;
	/*printf("%p, %p\n", &_shred_start, &_shred_end);*/
	sleep(4);
	for(;i<THREAD_NUM;i++){
		do_thread((tid[i]));
	}

	return 0;
}
