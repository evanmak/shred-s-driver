#ifndef _DMM_H
#define _DMM_H
#include <linux/hashtable.h>
#include <asm/pgtable.h>	/* isb() */
#include <linux/spinlock.h>	/* spinlock */
#include <linux/rwsem.h>	/* semaphore */

#define assert(cond) do {								\
                if (!(cond)) {								\
                        printk(KERN_INFO "assert fail in %s, at line %d\n",__func__, __LINE__);	\
                }									\
        } while (0)


#define DMM_HASH_BITS	16	/* 16 means 2**16 = 64K entries */
#define CORE_NUM	4	/* Raspberry Pi 2 use ARMV7 quad-core CPU */
#define MB(n)   	(n << 20)
#define S_POOL_START_ADDR       0x30000000      /* starting address for s_pool allocation */

/* configure lock option: spinlock or read/write lock */
#define SPINLOCK
//#define SEMAPHORE

/* map mm_struct(address space) to a dmm_struct */
DEFINE_HASHTABLE(dmm_hashtable, DMM_HASH_BITS);

struct s_pool_struct;
struct section_struct;
struct active_thread;
/* Domain Memory Management, per address space */
struct dmm_struct {
	/* used by dmm_hashtable */
	struct hlist_node node;
	struct mm_struct *mm;

	/**
	 * each core has an active s_pool list, when domain fault happen, we need to close all
	 * active s_pool on the list.
	 */
	struct list_head core_array[CORE_NUM];

	/* record the toppest address that has been allocated, shared among threads */
	uint32_t s_pool_top;
	spinlock_t s_pool_top_lock;

	/* s_pool list, keep track all s_pool, shared or normal */
	struct list_head s_pool_list_head;
	/* s_pool_list is shared among all threads, lock it before use */
#ifdef SPINLOCK
	spinlock_t s_pool_list_lock;
#elif defined(SEMAPHORE)
	struct rw_semaphore s_pool_list_lock;
#endif

	/* active_thread_list, record only thread has active s_pool, used to detect reenter s_pool */
	struct list_head active_thread_list_head;
	/* active_thread_list is shared among all threads, lock it before use */
#ifdef SPINLOCK
	spinlock_t active_thread_list_lock;
#elif defined(SEMAPHORE)
	struct rw_semaphore active_thread_list_lock;
#endif
};

/* active threads that have active s_pool */
struct active_thread_struct {
	struct list_head active_thread_list;

	int thread_id;

	/* only one active s_pool is allowed at one time per thread */
	struct s_pool_struct *active;
};

/* each shred has a s_pool, a secure memory pool protected by memory domain. Refer to ARM DACR register */
struct s_pool_struct {
	uint32_t s_pool_id;

	/* each s_pool is on this global s_pool_list */
	struct list_head s_pool_list;

	/* active s_pool resides also on per-core active list, refer to dmm_struct.core_array[CORE_NUM] */
	struct list_head active_s_pool_list_array[CORE_NUM];

	/**
	 * when active, means we do shred_enter, but not shred_exit yet, s_pool may not be accessible
	 * due to context switch.
	 */
	int is_active;

	/* when open, memory in s_pool is accessable to user thread */
	int is_open;

	/* owner means thread_id, when not shared, s_pool belongs to only one thread */
	int owner;

	/* when not shared, it records which cpu it runs on, relate to domain_id */
	int cpu_id;

	/* s_pool can be shared by different shreds, shared s_pool don't needs lock,no concurrent write to it TODO */
	int is_shared;
	int ref_count;
#ifdef SPINLOCK
	spinlock_t s_pool_lock;
#elif defined(SEMAPHORE)
	struct rw_semaphore s_pool_lock;
#endif

	/* domain fault on the same s_pool may happen, race exists, add lock */
	spinlock_t domain_fault_lock;

	/* each s_pool contains a section list */
	struct list_head section_list_head;
};

struct section_struct {
	struct list_head section_list;

	/* each section is a piece of MB aligned memory, size=N means N MB continuous memory */
	void *start_addr;
	int size;
};

/*
 * DACR, namely the Domain Control Access Register, is a 32-bit per-core register,
 * it contains 16 domains, with 2-bits per domain.  It looks like this:
 *
 * |31 |29 |27 |25 |23 |21 |19 |17 |15 |13 |11 |09 |07 |05 |03 |01 |
 * |D15|D14|D13|D12|D11|D10|D9 |D8 |D7 |D6 |D5 |D4 |D3 |D2 |D1 |D0 |
 *
 * The fields D15-D0 in the register define the access permissions for each one of the 16 domains.
 * b00 = No access. Any access generates a domain fault.
 * b01 = Client. Accesses are checked against the access permission bits in the TLB entry.
 * b10 = Reserved. Any access generates a domain fault.
 * b11 = Manager. Accesses are not checked against the access permission bits in the TLB entry
 * so a permission fault cannot be generated. Attempting to execute code in a page that has the  
 * TLB eXecute Never (XN) attribute set does not generate an abort.
 *
 * The initial 3 domain is reserved by kernel, namely D0, D1, D2
 * namely the first 3 domains, and the initial value in binary is 
 * b 00000000 00000000 00000000 00010101 which is 21 in decimal format and 0x15 in hex.
 * In Shred, we use domain is the following way:
 * 	D0 - D3 system reserved, default value b01,b01,b01
 * 	D3 is used as shared domain
 *	D4 - D7 maps to CPU 0 - 3
 */

#define DACR_DEFAULT			0x00000015
#define DACR_SHARED			0x00000055
#define DACR_CPU_0			0x00000115
#define DACR_CPU_1			0x00000415
#define DACR_CPU_2			0x00001015
#define DACR_CPU_3			0x00004015
#define DACR_CLIENT			0x1	/* actually 2 bits, that is b01 */
#define DACR_SHRED_START		4	/* shred per-cpu domain use D4 - D7 */
#define DOMAIN_SHIFT(cpu_id)		((cpu_id + DACR_SHRED_START) * 2)
#define DOMAIN_SHARED			3
#define DOMAIN_LOCKED			15
#define CPU_TO_DOM(cpu_id)		(cpu_id + 4)

/**
 * For ARM MMU, the level I page table entries looks like this:
 *
 *  31                            10 9 8   5 4 3 2 1 0
 *   page table base, bits[31:10]    I domid S N S 0 1
 *                                   M       B S B
 *                                   P       Z   Z
 */

#define DOMAIN_BITS			5
#define DOMAIN_MASK			0xfffffe1f

/* set DACR register, DACR is per-core 32-bit register */
static inline void set_DACR(unsigned int val)
{
        asm volatile(
        "mcr    p15, 0, %0, c3, c0,0    @ set domain"
          : : "r" (val));
        isb();
}

/* read DACR register */
static inline unsigned get_DACR(void)
{
        uint32_t val;
        asm volatile(
        "mrc    p15, 0, %0, c3, c0,0    @ get domain"
          :"=r" (val):);
        isb();
        return val;
}

/* get arm hardware pmd*/
#define PGDIR_HW_SHIFT		20
#define pgd_hw_index(addr)	(((addr) >> PGDIR_HW_SHIFT) & 1)

int dmm_enter(int region_id, int is_shared);
int dmm_exit(int region_id);
unsigned long dmm_alloc(int size);
int dmm_getsid(void);
int domain_fault_handler(unsigned long addr, unsigned int fsr, struct pt_regs *regs);
#endif
