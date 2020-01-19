#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include "shred_wrapper.h"
#include "dp_malloc.h"

//#define DEBUG_TEST_DMM
//#define TEST_MAIN

#define MAJOR_NUM       99      /* choose major number for char device */

/**
 * ioctl_enter needs two parameters: s_pool_id, is_shared, both are int type, in order
 * to make interface compact, we combine s_pool_id and is_shared into one parameter
 * using macro PARAM_ENTER(s_pool_id, is_shared)
 * THIS MACRO puts limitation on s_pool_id, which require it's 31 bit should be 0 TODO
 */
#define PARAM_ENTER(s_pool_id, is_shared)       (s_pool_id<<1 | is_shared)
#define GET_SID(param_enter)    (param_enter>>1)
#define GET_SHD(param_enter)    (param_enter & 1)

#define IOCTL_ENTER             _IOR(MAJOR_NUM, 0, int)

/* ioctl_alloc needs one input int size, one output addr */
#define IOCTL_ALLOC             _IOWR(MAJOR_NUM, 1, unsigned long)

/* ioctl_exit needs one parameter: s_pool_id */
#define IOCTL_EXIT              _IOR(MAJOR_NUM, 2, int)

/* ioctl_getsid needs no parameter, but return current s_pool_id */
#define IOCTL_GETSID              _IOWR(MAJOR_NUM, 3, int)

#define DEVICE_FILE_NAME	"/dev/dmm0"

/* /dev/dmm0 state */
static int dmm_open = 0;
static int fd;

void ioctl_enter(int fd, int s_pool_id, int is_shared);
void *ioctl_alloc(int fd, int size); 
void ioctl_exit(int fd, int s_pool_id);
int ioctl_getsid(int fd);

extern void __shred_info_check(unsigned int, unsigned int);
static inline unsigned int __attribute__((always_inline))get_lr()
{
	unsigned int lr;
	asm volatile(
	"mov %[lr], r14"
	  :[lr] "=&r" (lr) : :"memory");
	return lr;
}

void shred_enter(int s_pool_id, int is_shared) {
//	unsigned int lr = get_lr();
//	__shred_info_check(lr, s_pool_id);
	if (dmm_open == 0) {
		fd = open(DEVICE_FILE_NAME, 0);
		if (fd < 0) {
			printf("Can't open device file %s\n", DEVICE_FILE_NAME);
			exit(-1);
		}
		dmm_open = 1;
	}

	ioctl_enter(fd, s_pool_id, is_shared);
}

void* shred_alloc(int size) {
	void *addr;

	if (dmm_open == 0) {
		fd = open(DEVICE_FILE_NAME, 0);
		if (fd < 0) {
			printf("Can't open device file %s\n", DEVICE_FILE_NAME);
			exit(-1);
		}
		dmm_open = 1;
	}

	addr = ioctl_alloc(fd, size);

	return addr;
}

void shred_exit(int s_pool_id) {
	if (dmm_open == 0) {
		fd = open(DEVICE_FILE_NAME, 0);
		if (fd < 0) {
			printf("Can't open device file %s\n", DEVICE_FILE_NAME);
			exit(-1);
		}
		dmm_open = 1;
	}

	ioctl_exit(fd, s_pool_id);
}

int get_current_s_pool_id(void) {
	int sid;

	if (dmm_open == 0) {
		fd = open(DEVICE_FILE_NAME, 0);
		if (fd < 0) {
			printf("Can't open device file %s\n", DEVICE_FILE_NAME);
			exit(-1);
		}
		dmm_open = 1;
	}

	sid = ioctl_getsid(fd);

	return sid;
}

void *s_pool_alloc(int size) {
	int s_pool_id = get_current_s_pool_id();
	extern __thread size_t cur_dp_heap_index;

	if (s_pool_id >= 0) {
		set_heap_index_by_region_id(s_pool_id);
		if (dp_heap_array[cur_dp_heap_index].ini_flag == true)
			return dp_malloc(size);
		else {
			if (dp_initialize(s_pool_id) == 0)
				return dp_malloc(size);
			else
				printf("ERROR: dp_initialize failed!\n");
		}
	}

	return NULL;
}

void s_pool_free(void *ptr) {
        int s_pool_id = get_current_s_pool_id();
        if (s_pool_id >= 0) {
                set_heap_index_by_region_id(s_pool_id);
                if(dp_free(ptr) == 0) // check if ptr in our range
                        return;
		else
			printf("ERROR: dp_free failed! s_pool_id:%d\n", s_pool_id);
        } else
		printf("ERROR: s_pool_free not in shred! invalid s_pool_id:%d\n", s_pool_id);
}

void ioctl_enter(int fd, int s_pool_id, int is_shared) {
	int ret_val;
	int param_enter;

	param_enter = PARAM_ENTER(s_pool_id, is_shared);
	ret_val = 0;
	ret_val = ioctl(fd, IOCTL_ENTER, param_enter);

	if (ret_val < 0) {
		printf("ioctl_enter failed :%d\n", ret_val);
		exit(-1);
	}

#ifdef DEBUG_TEST_DMM
	printf("ioctl_enter succeed! ret:%d, s_pool_id:%d, is_shared:%d\n", ret_val, s_pool_id, is_shared);
#endif
}

void ioctl_exit(int fd, int s_pool_id) {
	int ret_val;

	ret_val = ioctl(fd, IOCTL_EXIT, s_pool_id);

	if (ret_val < 0) {
		printf("ioctl_exit failed :%d\n", ret_val);
		exit(-1);
	}

#ifdef DEBUG_TEST_DMM
	printf("ioctl_exit succeed! ret: %d, s_pool_id : %d\n", ret_val, s_pool_id);
#endif

}

void *ioctl_alloc(int fd, int size) {
	void *addr;
	int ret_val;

#ifdef DEBUG_TEST_DMM
	printf("[user mode]ioctl_alloc size: %d\n", size);
#endif

	addr = (void *)ioctl(fd, IOCTL_ALLOC, size);

	if (addr < 0) {
		printf("ioctl_size failed :%d\n", ret_val);
		exit(-1);
	}

#ifdef DEBUG_TEST_DMM
	printf("ioctl_alloc succeed ! addr : 0x%p size: %d\n", addr, size);
	*(int *)addr = 1;
	printf("test write *addr = 1,test read *addr = %d, addr = 0x%p\n", *(int *)addr, addr);
#endif
	return addr;
}

int ioctl_getsid(int fd) {
	int sid;

#ifdef DEBUG_TEST_DMM
	printf("[user mode]ioctl_getsid.\n");
#endif

	sid = ioctl(fd, IOCTL_GETSID, 0);

	if (sid < 0) {
		printf("ioctl_getsid failed :%d\n", sid);
		exit(-1);
	}

	return sid;
}

#ifdef TEST_MAIN
int main() {
	int fd, ret_val;
	void *addr;

	fd = open(DEVICE_FILE_NAME, 0);
	if (fd < 0) {
		printf("Can't open device file %s\n", DEVICE_FILE_NAME);
		exit(-1);
	}

	ioctl_enter(fd, 1, 0);
	printf("before alloc\n");
	addr = ioctl_alloc(fd, 1);
	printf("after alloc\n");
	ioctl_exit(fd, 1);

	printf("accesss addr out of shred: *addr: %d\n", *(int *)addr);
	close(fd);
}
#endif
