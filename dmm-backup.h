/**
 * "dmm.h"
 */

/* to use linux hashtable */
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <asm/pgtable.h>

/* hashmap follows the instructions of https://lwn.net/Articles/510202/ */

DEFINE_HASHTABLE(dmm_hashtable, 16);
/**
 *    name: dmm_hashtable
 *    bits: 2**bits is the largest size of process supported by dmm,
 *           16 bits should be enough, namely 65536 entries,
 *            at most take up (2 ** 16) * sizeof(pointer) = 2**18 bytes(256KB)
 *    hashmap (key, value)
 *    key: current, a pointer to current task_struct
 *    value: node, which is contained in the struct dmm_struct;
 */

struct region_struct; 
struct section_struct;

/**
 * struct dmm_struct is used to store per-process memory domain info, which contains 
 * the following info, like whether this thread is in shred or not, current active region id,
 * 
 */
struct dmm_struct {
	/* used by dmm_hashtable */
	struct hlist_node *node; 

	/* whether this thread is in shred or not, 0 : not in shred, 1 : in shred */
	int in_shred;

	/* number of regions owned by this thread*/
	int region_num;

	/* region list head that manage all the regions exclusively owned by current thread */
	struct list_head region_list_head;

	/**
	 * current active region id, and its pointer 
	 * NOTE: at any time, there is at most one active region per-thread, it can either be at
	 * its own region_list, or on a shared region list. which is mapped through current->mm
	 * via a hashtable srl_hashtable.
	 */
	int curr_active_region_id;
	struct region_struct *active;
};

/**
 * For shared region list, different threads that belongs to the same process can share the same 
 * region. Those region are stored in the shared region list. As shared region are per address
 * space, that means each mm_struct maps to a shared region list, which is opposite to the
 * dmm_struct. In the case of dmm_struct, each task_struct map to a single dmm_struct, which is
 * per-thread. Access to shared region can happen at the same time, so we need lock to protect
 * the critical region.
 */

/* we need another hashtable to map mm_struct *mm to  shared region list. */
DEFINE_HASHTABLE(mm_hashtable, 16);

/**
 *    name: mm_hashtable
 *    bits: 2**bits is the largest size of process supported by dmm,
 *           16 bits should be enough, namely 65536 entries,
 *            at most take up (2 ** 16) * sizeof(pointer) = 2**18 bytes(256KB)
 *    hashmap (key, value)
 *    key: current->mm(mm_struct), a pointer to current address space
 *    value: node, which is contained in the struct dmm_mm_struct;
 */


/**
 * dmm_mm_struct records all per-address space data structures, which can be identified by
 * current->mm. We have two data structures that are per address space, as opposite to 
 * per-thread. The first one is the shared region list, which is shared by all threads in the same
 * address space. The other one is the address space itself, because when we allocate virtual
 * domain memory for different threads in the same address space, we need to know whether a
 * certain address is allocated or not.
 */

struct dmm_mm_struct {
	/* used by mm_hashtable */
	struct hlist_node *node; 

	/* per address space data structure : shared_region_list */
	struct shared_region_list * shared_region;
	
	/**
	* Because the vm allocator does not support mega-byte alignment requirement,
	* so we have to align it by ourselves by designating the starting address, thus we
	* we have to keep track of the used address space by ourselves.
	* per address space data structure : the address space itself, we use vm_mmap
	* to allocate virtual memory directly, so we need to keep track the virtual memory.
	* suppose we only alloc, not free, so we only need a start address and a count.
	* NOTE: count is in MB.
	* And we choose the starting address 0x70000000.
	*/
	int vm_count;
};

struct shared_region_list {    
	/* number of shared regions owned by this address space, namely the mm_struct * mm */
	int shreg_num;

	/* region list head that manage all the shared regions owned by current mm_struct *mm */
	struct list_head shreg_list_head;
};

/**
 * struct region_struct describes a region owned by a thread, which consists of a linked list of
 * sections. Each section is a piece of continuous 2MB aligned  memory, allocated via kernel
 * primitives. A region can be shared among different threads or owned exclusively by a certain
 * thread.
 */
struct region_struct {
	/**
	 * this region id is a random number that associate with a user-mode region ID, the User
	 * designated region ID may be a const string or const int number, user wrapper will
	 * transform it into a region ID used here, preventing attacker guessing the region ID.
	 */
	uint32_t region_id;

	/* a region can appear in a per-thread region-list or a shared region list */
	int is_shared;
	
	/**
	 * if a region is shared, ref_count records how many threads share it.
	 * it  can be modified by two thread on different core at the same time.
	 * So make it atomic.
	 */
	atomic_t ref_count;
	
	/**
	 * Access a shared region needs to obtain this lock first, it’s possible that two thread on 
	 * different core try to operate on the same shared region, for example, add new section.
	 * so it needs lock to prevent both or more threads operate on the same section list.
	 */
	raw_spinlock_t region_lock;

	/**
	 * section_list_head points to the section list owned by this region. When it’s shared,
	 * we need to obtain the region_lock to operate on it.
	 */
	struct list_head section_list_head;

	/* the number of sections that this region own */
	uint32_t sec_num;
};



/*
 * Each section_struct consist of the start address and the size of this section(in MB),
 * 1 MB corresponds to 1 pgd entry. 1 pgd entry is the granularity of the domain protection.
 */
struct section_struct {
	/* the sections that one region contains is organised in a linked section_list */
	struct list_head section_list;

	/* each section is a piece of 1 MB aligned continuous memory, here is the start address */
	void *start_addr;

	/**
	 * the number of MB this section contains, 3 means 3 MB continuous memory, 
	 * corresponding to 3 pgd entries.
	 * NOTE: linux and arm hardware have different idea on how many entries pgd contains!
	 */
	int num;
};

/*
 *  DACR, namely the Domain Control Access Register, is a 32-bit per-core register, 
 * it contains 16 domains, with 2-bits per domain.  It looks like this:
 *
 * |31    |29   | 27   | 25   | 23   | 21   | 19 | 17 |  15 |  13 |  11 | 09 |  07 | 05 | 03 | 01   |
 * |D15 |D14| D13 |D12 | D11| D10| D9 | D8|  D7|  D6 | D5 | D4 | D3 | D2| D1|   D0|
 *
 * The fields D15-D0 in the register define the access permissions for each one of the 16 domains.
 * b00 = No access. Any access generates a domain fault.
 * b01 = Client. Accesses are checked against the access permission bits in the TLB entry.
 * b10 = Reserved. Any access generates a domain fault.
 * b11 = Manager. Accesses are not checked against the access permission bits in the TLB entry
 * so a permission fault cannot be generated. Attempting to execute code in a page that has the  
 * TLB eXecute Never (XN) attribute set does not generate an abort.
 *
 * The initial 3 domain is reserved by kernel
 * namely the first 3 domains, and the initial value in binary is 
 * b 00000000 00000000 00000000 00010101 which is 21 in decimal format and 0x15 in hex.
 */

/* set DACR register, DACR is per-core 32-bit register */
static inline void set_DACR(unsigned int val)
{
        asm volatile(
        "mcr    p15, 0, %0, c3, c0,0    @ set domain"
          : : "r" (val));
        isb();
}

/* read DACR register */
static inline unsigned get_DACR(void )
{
        uint32_t val;
        asm volatile(
        "mrc    p15, 0, %0, c3, c0,0    @ set domain"
          :"=r" (val):);
        isb();
        return val;
}

int dmm_enter(int region_id, int is_shared);
int dmm_exit(int region_id);
long dmm_alloc(int size);
