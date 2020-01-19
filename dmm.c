/**
 *  dmm.c create a character device manipunated over ioctl.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/signal.h>	/* hook_fault_code:SEGV_ACCERR */
#include <linux/slab.h>		/* kmalloc */
#include <linux/mm.h>		/* vm_mmap */
#include <linux/mman.h>		/* vm_mmap:PROT_READ/WRITE */
#include <linux/ioctl.h>	/* ioctl:_IOWR */
#include "dmm.h"

MODULE_LICENSE("Dual BSD/GPL");

#define DEBUG

/* handle env difference */
#define ZC_SUN
//#define YH_CHEN

/* configure whether we lock s_pool before handle domain fault */
//#define STRICT_DOMAIN_FAULT

/* configure printk output level */
//#define KERN_LEVEL	KERN_ALERT
#define KERN_LEVEL	KERN_INFO

/**
 × configure whether s_pool_id per thread.
 * different threads enter the same s_pool_id, may mean different s_pools.
 * eg. one function may be called by different threads, if this function
 * enter the same sid, we should differentiate it.
 * s_pool_id range (0, 2**32)
 * thread_id (0, 2**16)
 * sid (designated by user) (0, 2**16)
 */
#define SID_PER_THREAD
#define THREAD_SID(sid)         (((current->pid) << 16) | (sid & ((1 << 16) - 1)))
#define USER_SID(thread_sid)    (thread_sid & ((1 << 16) - 1))

/* choose major number for char device TODO: dynamically alloc may be better */
#define MAJOR_NUM	99

#define SUCCESS	0
#define ERROR	-1
#define DEVICE_NAME	"dmm"

/**
 * ioctl_enter needs two parameters: s_pool_id, is_shared, both are int type, in order
 * to make interface compact, we combine s_pool_id and is_shared into one parameter
 * using macro PARAM_ENTER(s_pool_id, is_shared)
 */
#define PARAM_ENTER(s_pool_id, is_shared)	(s_pool_id<<1 | is_shared)
#define GET_SID(param_enter)	(param_enter>>1)
#define GET_SHD(param_enter)	(param_enter & 1)

/* ioctl_enter needs one input parameter, which is a combination of (s_pool_id<<1 | is_shared) */
#define IOCTL_ENTER		_IOR(MAJOR_NUM, 0, int)
/* ioctl_alloc needs one input int size, one output addr */
#define IOCTL_ALLOC		_IOWR(MAJOR_NUM, 1, unsigned long)
/* ioctl_exit needs one parameter: s_pool_id */
#define IOCTL_EXIT		_IOR(MAJOR_NUM, 2, int)
/* ioctl_getsid needs no parameter, but return current s_pool_id */
#define IOCTL_GETSID              _IOWR(MAJOR_NUM, 3, int)

#define PAGE_DOMAIN_FAULT_NUM	0xb	/* index of exception table is 11, refer to arch/arm/mm/fault.c#L469 */
#define SEC_DOMAIN_FAULT_NUM	0x9	/* index of exception table is 9, refer to arch/arm/mm/fault.c#L467 */

/* REALLY UGLY HARDCODED FSR STRUCT ADDR TODO */
#ifdef ZC_SUN
#define FSR_INFO_ADDR		0x80804014
#define IFSR_INFO_ADDR		0x80804214
#define DO_USER_FAULT_ADDR	0x8001e84c
#define FLUSH_TLB_ALL		0x80015e58
#define FLUSH_TLB_PAGE		0x80015f70
#elif defined(YH_CHEN)
#define FSR_INFO_ADDR		0x807ea904
#define IFSR_INFO_ADDR		0x807eab04
#define DO_USER_FAULT_ADDR	0x8001cb6c
#define FLUSH_TLB_ALL		0x80015e58
#define FLUSH_TLB_PAGE		0x80015f70
#endif

/* configure lock use:spinlock or semaphore */
#define READ_LOCK	0
#define WRITE_LOCK	1

#ifdef SPINLOCK
#define dmm_lock(lock, rw)		spin_lock(lock)
#define dmm_unlock(lock, rw)		spin_unlock(lock)
#define dmm_lock_init(lock)		spin_lock_init(lock)
#elif defined(SEMAPHORE)
#define dmm_lock(lock, rw)		(rw ? down_write(lock) : down_read(lock))
#define dmm_unlock(lock, rw)		(rw ? up_write(lock) : up_read(lock))
#define dmm_lock_init(lock)		init_rwsem(lock)
#endif

/**
 * NOTE: code piece copied and modified from linux kernel
 * Something tried to access memory that isn't in our memory map..
 * User mode accesses just cause a SIGSEGV
 */
void (*do_user_fault)(struct task_struct *tsk, unsigned long addr,
                unsigned int fsr, unsigned int sig, int code,
                struct pt_regs *regs);

/* steal kernel functions that forbid module use, UGLY TODO */
void (*my_flush_tlb_page)(struct vm_area_struct *vma, unsigned long uaddr);
void (*my_flush_tlb_all)(void);

/**
 * we borrow fsr_info from kernel in order to modify fsr_info array to
 * register domain_fault_handler UGLY TODO
 */
struct fsr_info {
	int (*fn) (unsigned long addr, unsigned int fsr, struct pt_regs *regs);
	int sig;
	int code;
	const char *name;
};

/* hard coded fsr_info struct address UGLY TODO */
struct fsr_info *my_fsr_info = (struct fsr_info *) FSR_INFO_ADDR;
struct fsr_info *my_ifsr_info = (struct fsr_info *) IFSR_INFO_ADDR;

/* declare our own hook_fault_code, kernel forbid module use it! UGLY TODO */
void my_hook_fault_code(struct fsr_info *fsr, int nr, int (*fn)(unsigned long, unsigned int, struct pt_regs *),
                int sig, int code, const char *name)
{
	struct fsr_info *p;
	p = (struct fsr_info *)((uint32_t)fsr + sizeof(struct fsr_info) * nr);

	p->fn   = fn;
	p->sig  = sig;
	p->code = code;
	p->name = name;
}

/* dump kernel fsr_info array for debugging */
void dump_fsr(int nr, struct fsr_info *fsr) {
	struct fsr_info *p;
	p = (struct fsr_info *)((uint32_t)fsr + sizeof(struct fsr_info) * nr);

	/* skip hooked entries to avoid crushing the kernel */
	if (nr == 0xb || nr == 0x9)
		return;

	printk(KERN_LEVEL "sfr_info[%d].fn   = 0x%p\n",nr, p->fn);
	printk(KERN_LEVEL "sfr_info[%d].sig  = %d\n", nr, p->sig);
	printk(KERN_LEVEL "sfr_info[%d].code = %d\n", nr, p->code);
	printk(KERN_LEVEL "sfr_info[%d].name = %s\n", nr, p->name);
}

static int Device_Open = 0;

/**
 * This dmm device only need to be opened once, and is shared among all process
 * dmm_open is responsible for initilize the meta data.
 */
static int dmm_open(struct inode *inode, struct file *file) {

#ifdef DEBUG
	printk(KERN_LEVEL "dmm_open(%p)\n", file);
#endif

	/* if already opened, ignore reopen request */
	if (Device_Open)
		return SUCCESS;

	/* hook the domain handler: both accurate and inaccurate page and section domain fault, namely fsr&ifsr entries */
	my_hook_fault_code(my_fsr_info, PAGE_DOMAIN_FAULT_NUM, domain_fault_handler,SEGV_ACCERR, 0, "page domain fault");
	my_hook_fault_code(my_fsr_info, SEC_DOMAIN_FAULT_NUM, domain_fault_handler,SEGV_ACCERR, 0, "section domain fault");
	my_hook_fault_code(my_ifsr_info, PAGE_DOMAIN_FAULT_NUM, domain_fault_handler,SEGV_ACCERR, 0, "page domain fault");
	my_hook_fault_code(my_ifsr_info, SEC_DOMAIN_FAULT_NUM, domain_fault_handler,SEGV_ACCERR, 0, "section domain fault");

	/* steal do_user_fault UGLY:TODO */
	do_user_fault = (void (*)(struct task_struct *, unsigned long, unsigned int, unsigned int, int, struct pt_regs *)) DO_USER_FAULT_ADDR;

	/* steal flush_tlb_all/flush_tlb_page UGLY:TODO */
	my_flush_tlb_all = (void (*)(void)) FLUSH_TLB_ALL;
	my_flush_tlb_page = (void (*)(struct vm_area_struct *, unsigned long)) FLUSH_TLB_PAGE;

	/* initilization is done here */
	hash_init(dmm_hashtable);

	Device_Open++;

	return SUCCESS;
}

/**
 * called on close file
 */
static int dmm_release(struct inode *inode, struct file *file) {

#ifdef DEBUG
	printk(KERN_LEVEL "dmm_release(%p)\n", file);
#endif
	Device_Open --;

	return 0;
}

/**
 * we use dmm_ioctl to control dmm device.
 */
long dmm_ioctl(	struct file *file,
		unsigned int ioctl_num,	/* num and parameter for ioctl */
		unsigned long param) {
	long res = -1;
	unsigned long addr;
#ifdef SID_PER_THREAD
	unsigned long tsid;
#endif

#ifdef DEBUG
//	printk(KERN_LEVEL "[dmm_ioctl]:ioctl_num:0x%x\n", ioctl_num);
#endif
	switch (ioctl_num) {
		case IOCTL_ENTER:
			/**
			 * dmm_enter(int s_pool_id, int is_shared)
			 */
#ifdef SID_PER_THREAD
			/* make sure sid designated by user fall in range(0, 1<<16) */
			assert(GET_SID(param) < (1 << 16));
			if (GET_SHD(param) == 0)
				tsid = THREAD_SID(GET_SID(param));
			else
				tsid = GET_SID(param);
			res = dmm_enter(tsid, GET_SHD(param));
#else
			res = dmm_enter(GET_SID(param), GET_SHD(param));
#endif
			break;

		case IOCTL_EXIT:
			/**
			 * dmm_exit(int s_pool_id)
			 */
#ifdef SID_PER_THREAD
			/* make sure sid designated by user fall in range(0, 1<<16) */
			assert(param < (1 << 16));
			tsid = THREAD_SID(param);
			res = dmm_exit(tsid);
#endif
			/**
			 * if defined SID_PER_THREAD, because we don't know whether sid is shared or not, 
			 * so if the first one isn't right, we try another.
			 */
			if (res < 0)
				res = dmm_exit(param);
			break;

		case IOCTL_ALLOC:
			/**
			 * dmm_alloc(int size), alloc size*MB memory, reture addr
			 */
			addr = dmm_alloc(param);
			res = (long)addr;
			break;

		case IOCTL_GETSID:
			/**
			 * dmm_getsid(void), return current s_pool_id.
			 */
			res = dmm_getsid();
			break;

		default:
			panic("[dmm]ERROR: Unreconized ioctl number!");
	}

	return res;
}

/**
 * This structure will hold the functions to be called when a process 
 * does something to this device.
 */
struct file_operations fops = {
	.open = dmm_open,
	.release = dmm_release,	/* a.k.a. close */
	.unlocked_ioctl = dmm_ioctl,
};

/**
 * Initialize the module - Register dmm device
 */
int init_dmm_module(void) {
	int ret_val;

#ifdef DEBUG
	int i;
	for (i = 0; i < 16; i++)
		dump_fsr(i, my_fsr_info);
#endif

	/**
	 * Register dmm device
	 */
	ret_val = register_chrdev(MAJOR_NUM, DEVICE_NAME, &fops);

	/**
	 * Negative values signify an error!
	 */
	if (ret_val < 0) {
		printk(KERN_ALERT "%s failed with %d\n",
				"Sorry, register the dmm char device ", ret_val);
		return ret_val;
	}

	printk(KERN_LEVEL "%s The major device number is %d.\n",
			"Register dmm char device succeed", MAJOR_NUM);

	return 0;
}

/**
 * execute on rmmod, we should reclaim all the resources allocated in dmm_open.
 */
void exit_dmm_module(void) {

	/**
	 * reclaim the resources
	 */
	//TODO

	/**
	 * Unregister dmm device
	 */

	unregister_chrdev(MAJOR_NUM, DEVICE_NAME);
}

struct hlist_head *find_dmm_struct_by_hash(unsigned long hash) {
	struct hlist_head *h;

	h = &dmm_hashtable[hash_min(hash, DMM_HASH_BITS)];
	if (hlist_empty(h))
		return NULL;

	return h;
}

/* use struct mm_struct *mm as hash key */
struct dmm_struct *find_dmm_struct(struct mm_struct *mm) {
	struct dmm_struct *d;
	struct hlist_head *h;

	h = find_dmm_struct_by_hash((unsigned long) mm);
	if (!h)
		return NULL;

	hlist_for_each_entry(d, h, node) {
		if (d->mm == mm)
			return d;
	}

	return NULL;
}

/* search for s_pool in a given address space by s_pool_id */
struct s_pool_struct *find_s_pool_by_id(int s_pool_id) {
	struct list_head *l;
	struct s_pool_struct *p;

	/* get current->mm, use it as key to lookup dmm_hashtable */
	struct mm_struct *mm= current->mm;
	struct dmm_struct *d;

	d = find_dmm_struct(mm);
	if (!d)
		return NULL;

	/* check list empty or not */
	if(list_empty(&d->s_pool_list_head))
		return NULL;

	/* the other thread may be change the s_pool_list, lock it */
	/* NOTE: we'd better use read/write lock, for we only block write thread TODO */
	dmm_lock(&d->s_pool_list_lock, READ_LOCK);
	list_for_each(l, &d->s_pool_list_head) {
		p = list_entry(l, struct s_pool_struct, s_pool_list);
		if (p->s_pool_id == s_pool_id) {
			dmm_unlock(&d->s_pool_list_lock, READ_LOCK);
			return p;
		}
	}
	dmm_unlock(&d->s_pool_list_lock, READ_LOCK);

	return NULL;
}

void set_section_domain(struct section_struct *s, int dom_id) {
	uint32_t i, addr;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	uint32_t pmd_value;

	for (i = 0; i < s->size; i++) {
		addr = (uint32_t)(s->start_addr) + MB(i);

		pgd = pgd_offset(current->mm, addr);
		/* arm hardware use different pgtables, linux fake it, refer to asm/pgtable-2level-types.h */
		pud = (pud_t *)&(*pgd)[pgd_hw_index(addr)];
		pmd = pmd_offset(pud, addr);

		/* pgd should be good, for we mmap section memory with MAP_POPULATE */
		assert (!pmd_none(*pmd) && !pmd_bad(*pmd));
		pmd_value = pmd_val(*pmd);
		pmd_val(*pmd) = (pmd_value & DOMAIN_MASK) | (dom_id << DOMAIN_BITS);

#ifdef DEBUG
		printk(KERN_LEVEL "[set_section_domain]old pmd_val:0x%x, new pmd_val:0x%x, dom_id:%d, addr:0x%x, cpu_id:%d\n", pmd_value, pmd_val(*pmd), dom_id, addr, smp_processor_id());
#endif
	}
}

/* open a section, set PDE for pgd entries inside this section */
void open_section(struct section_struct *s, int dom_id) {
	set_section_domain(s, dom_id);
}

/* close a section, set PDE for pgd entries inside this section to default domain value */
void close_section(struct section_struct *s) {
	set_section_domain(s, DOMAIN_LOCKED);
}

void set_s_pool_domain (struct s_pool_struct *p, int dom_id) {
	struct list_head *l;
	struct section_struct *s;

	list_for_each(l, &p->section_list_head) {
		s = list_entry(l, struct section_struct, section_list);
		open_section(s, dom_id);
	}
}

/**
 * open a s_pool, we should take is_share into consideration
 *	1. set is_open, cpu_id
 *	2. for each section, open it.
 */
void open_s_pool (struct s_pool_struct *p, int dom_id) {
	dmm_lock(&p->s_pool_lock, WRITE_LOCK);

#ifdef DEBUG
	printk(KERN_LEVEL "[open_s_pool] s_pool_id:%d, dom_id:%d, is_shared = %d, cpu_id:%d\n", p->s_pool_id, dom_id, p->is_shared, smp_processor_id());
#endif
	p->cpu_id = smp_processor_id();

	set_s_pool_domain (p, dom_id);
	p->is_open = 1;

	(*my_flush_tlb_all)();

	dmm_unlock(&p->s_pool_lock, WRITE_LOCK);
}

/* close a s_pool */
void close_s_pool (struct s_pool_struct *p) {
	dmm_lock(&p->s_pool_lock, WRITE_LOCK);

#ifdef DEBUG
	printk(KERN_LEVEL "[close_s_pool] s_pool_id:%d, is_shared = %d, cpu_id:%d\n", p->s_pool_id, p->is_shared, smp_processor_id());
#endif
	p->cpu_id = -1;

	set_s_pool_domain (p, DOMAIN_LOCKED);
	p->is_open = 0;

	(*my_flush_tlb_all)();

	dmm_unlock(&p->s_pool_lock, WRITE_LOCK);
}

/* alloc dmm_struct */
struct dmm_struct *alloc_dmm_struct(void) {
	int i;
	struct dmm_struct *d;

	d =  kmalloc(sizeof(struct dmm_struct), GFP_KERNEL);
	if (!d)
		return NULL;

#ifdef DEBUG
	printk(KERN_LEVEL "[alloc_dmm_struct] d:0x%p\n", d);
#endif
	/* initialize dmm_struct here */
	d->mm = current->mm;
	hash_add(dmm_hashtable, &d->node, (unsigned long)(d->mm));

	d->s_pool_top = S_POOL_START_ADDR;
	spin_lock_init(&d->s_pool_top_lock);

	for (i = 0; i < CORE_NUM; i++)
		INIT_LIST_HEAD(&d->core_array[i]);

	INIT_LIST_HEAD(&d->s_pool_list_head);
	dmm_lock_init(&d->s_pool_list_lock);

	INIT_LIST_HEAD(&d->active_thread_list_head);
	dmm_lock_init(&d->active_thread_list_lock);

	return d;
}

/* alloc s_pool_struct and initialized it */
struct s_pool_struct *alloc_s_pool_struct(int s_pool_id, int is_shared, struct dmm_struct *d) {
	int i;
	struct s_pool_struct *p;

	p = kmalloc(sizeof(struct s_pool_struct), GFP_KERNEL);
	if (!p)
		return NULL;

	INIT_LIST_HEAD(&p->s_pool_list);

	/* add this new node to s_pool_list */
	dmm_lock(&d->s_pool_list_lock, WRITE_LOCK);
	list_add_tail(&p->s_pool_list, &d->s_pool_list_head);
	dmm_unlock(&d->s_pool_list_lock, WRITE_LOCK);

	/* initialize active_s_pool_list_array */
	for (i = 0; i < CORE_NUM; i++)
		INIT_LIST_HEAD(&p->active_s_pool_list_array[i]);

	/* init section_list_head */
	INIT_LIST_HEAD(&p->section_list_head);

	p->s_pool_id = s_pool_id;

	/* NOTE: we only set active here, is_open flag is delayed until we alloc some memory */
	p->is_active = 1;
	p->is_shared = is_shared;
	p->ref_count = 1;
	p->is_open = 0;

	dmm_lock_init(&p->s_pool_lock);
	spin_lock_init(&p->domain_fault_lock);

	if (is_shared == 1) {
		/* for shared s_pool, it use shared_domain_id, owner and cpu_id doesn't apply to it */
		p->owner = -1;
		p->cpu_id = -1;
	} else {
		p->owner = current->pid;
		p->cpu_id = smp_processor_id();
	}

#ifdef DEBUG
	printk(KERN_LEVEL "[alloc_s_pool_struct] p:0x%p, cpu_id:%d\n", p, p->cpu_id);
#endif
	return p;
}

/* test DACR value is default or not, 1 :default, 0 :modified */
int is_DACR_default(void) {
	uint32_t dacr;

	dacr = get_DACR();
	if (dacr == DACR_DEFAULT)
		return 1;
	else
		return 0;
}

/**
 * check current cpu's active_s_pool_list, make sure all s_pool is closed, but if
 * s_pool is shared, we should allow it to be open. Refer to SHRED.Limitation.TODO
 */
int is_active_s_pool_closed(struct dmm_struct *d, int cpu_id) {
	struct list_head *l;
	struct s_pool_struct *p;

	list_for_each(l, &d->core_array[cpu_id]) {
		p = list_entry(l, struct s_pool_struct, active_s_pool_list_array[cpu_id]);
		if (p->is_shared == 0 && p->is_open == 1)
			return 0;
	}

	return 1;
}

struct active_thread_struct *find_active_thread_by_pid(int pid, struct dmm_struct *d) {
	struct list_head *l;
	struct active_thread_struct *a;

	/* active_thread_list is shared among all threads, lock before use */
	dmm_lock(&d->active_thread_list_lock, READ_LOCK);
	list_for_each(l, &d->active_thread_list_head) {
		a = list_entry(l, struct active_thread_struct, active_thread_list);
		if (a->thread_id == pid) {
			dmm_unlock(&d->active_thread_list_lock, READ_LOCK);
			return a;
		}
	}
	dmm_unlock(&d->active_thread_list_lock, READ_LOCK);

	return NULL;
}

/**
 * dmm_enter:
 *	enter/create a s_pool
 * 	Generally, when we enter a shred, we open the s_pool, when we exit, we close.
 *	But in order to guarantee security, we need to do a lot of checks here.
 * NOTE:
 *	1. if s_pool_id exist, we do the following check:
 *		a) To avoid the same thread enter two s_pool continuously without exit, we
 *		   check whether dmm_struct->active_thread_list contain current thread.
 *		b) To avoid multi-active s_pools on one core, we check per-core active s_pool list:
 *			I)  if DACR is default value(no domain fault yet, active s_pool list kept open),
 *			    we don'e need to check current core's active s_pool list.
 *			II) if DACR is restored(per-core domain is open now) for anytime, only one active
 *			    s_pool is allowed, otherwise security compromised.
 *		c) we check that if s_pool is not shared, it should only be accessed by its
 *		   owner thread.
 *		d) if s_pool is shared, we check the ref_count of it, if ref_count >= 1, we
 *		   only need to inc ref_count, otherwise we need to open it.
 *	2. if s_pool_id does not exist, we create a new s_pool, remember:
 *		a) if s_pool is not shared, set its owner to thread_id, set its domain to
 *		   current core.
 *		b) if s_pool is shared, set its owner to -1, set is_shared = 1, set its
 *		   domain to dom_shared.
 *	In both case, we should do:
 *		a) add current s_pool to current core active s_pool_pointer.
 *		b) add current thread to active_thread_list.
 *		c) activate this s_pool
 */

#define SUCCESS		0
#define ERROR_ENREENTER	1	/* error: thread reenter s_pool */
#define ERROR_ENCACTIVE	2	/* error: current core has more than one active s_pool, security compromised! */
#define ERROR_ENOWNER	3	/* error: current thread is not the owner of this non-shared s_pool */
#define ERROR_EN	4	/* error: general error, maybe alloc fail! */
int dmm_enter(int s_pool_id, int is_shared) {
	int cpu_id, dom_id;
	struct dmm_struct *d;
	struct s_pool_struct *p;
	struct active_thread_struct *a;

	/* we need cpu_id to do check per-core active s_pool_list. refer to dmm_struct.core_array[CORE_NUM] */
	cpu_id = smp_processor_id();
	assert(cpu_id >= 0 && cpu_id < CORE_NUM);

	/* lookup hash table to find the matching dmm_struct for current address space */
	d = find_dmm_struct(current->mm);

	if (!d)	{	// if d doesn't exist, create one and add to hashtable
		d = alloc_dmm_struct();
		if (!d)
			printk(KERN_LEVEL "[dmm_enter] ERROR: alloc_dmm_struct failed !\n");
	}

	p = find_s_pool_by_id(s_pool_id);

#ifdef DEBUG
	printk(KERN_LEVEL "[dmm_enter] s_pool_id: %d, is_shared: %d, cpu_id:%d, ref_count:%d\n", s_pool_id, is_shared, cpu_id, p != NULL? p->ref_count : 0);
#endif

	if (p) {	// s_pool exist

		/* check 1:a) reenter s_pool */
		a = find_active_thread_by_pid(current->pid, d);
		if (a != NULL)
			return -ERROR_ENCACTIVE;

		/**
		 * check 1:b) when DACR is default value, no check;
		 * otherwise, no active & open & non-shared s_pool is allowed on this core
		 */
		if (!is_DACR_default()) {
			/* concurrent active && open s_pool exist, security compromised!!! */
			if (!is_active_s_pool_closed(d, cpu_id))
				return -ERROR_ENCACTIVE;
		}

		/* check non-shared s_pool's owner */
		if (p->is_shared != 1) {
			dom_id = CPU_TO_DOM(cpu_id);

			if (p->owner != current->pid)
				return -ERROR_ENOWNER;

		} else {	/* shared s_pool */
			dom_id = DOMAIN_SHARED;

			dmm_lock(&p->s_pool_lock, WRITE_LOCK);
			p->ref_count++;
			/* someone opened it already, skip open_s_pool */
			if (p->ref_count >= 2) {
				dmm_unlock(&p->s_pool_lock, WRITE_LOCK);
				goto good_area;
			}
			dmm_unlock(&p->s_pool_lock, WRITE_LOCK);
		}
	} else {	/* s_pool does not exists, then alloc one */
		p = alloc_s_pool_struct(s_pool_id, is_shared, d);
		if (!p)
			return -ERROR_EN;
	}

	/**
	 * 1. if s_pool is not shared or is shared but not open yet, we need open it
	 * 2. if s_pool is newly allocated, open it.
	 * NOTE: delay open is possible. TODO
	 */
	//open_s_pool(p, dom_id);

	/* activate this s_pool */
	p->is_active = 1;

good_area:
	/* add current thread to active_thread_list */
	a = kmalloc(sizeof(struct active_thread_struct), GFP_KERNEL);
	INIT_LIST_HEAD(&a->active_thread_list);

	/* active s_pool of this thread */
	a->active = p;
	a->thread_id = current->pid;

	dmm_lock(&d->active_thread_list_lock, WRITE_LOCK);
	list_add_tail(&a->active_thread_list, &d->active_thread_list_head);
	dmm_unlock(&d->active_thread_list_lock, WRITE_LOCK);

	/**
	 * add current active s_pool to core_array[cpu_id], which is an active s_pool list.
	 * NOTE: we currently ignore shared s_pool TODO
	 */
	if (p->is_shared == 0) {
		dmm_lock(&p->s_pool_lock, WRITE_LOCK);
		list_add_tail(&p->active_s_pool_list_array[cpu_id], &d->core_array[cpu_id]);
		dmm_unlock(&p->s_pool_lock, WRITE_LOCK);
	}

#ifdef DEBUG
//	printk(KERN_LEVEL "[dmm_enter] return SUCCESS, cpu_id:%d\n", cpu_id);
#endif
	return SUCCESS;
}

/**
 * dmm_exit: exit a shred and close a s_pool
 * NOTE:
 *	1. if s_pool is shared:
 *		a) dec ref_count and if ref_count becomes 0, close all opened sections, set is_active
 *		b) otherwise, do nothing
 *	2. if s_pool is not shared :
 *		a) change the s_pool state and close all opened sections, set is_active
 * DEFAULT:
 *	3. remove s_pool from per-core active_list(no matter shared or not)
 *	4. remove current thread form active thread list
 */
#define ERROR_EPOOLNOTEXIST	1	/* s_pool_id not exist */
#define ERROR_ETHREADNOTFOUND	2	/* thread not on active thread list */
#define ERROR_EDMMNOTFOUND	3	/* dmm_struct not found in hashtable */
int dmm_exit(int s_pool_id) {
	int cpu_id;

	/* whether current thread is found on active thread list */
	int fflag;

	struct list_head *l;
	struct dmm_struct *d;
	struct s_pool_struct *p;
	struct active_thread_struct *a;

	/* we need cpu_id to do check per-core active s_pool_list. refer to dmm_struct.core_array[CORE_NUM] */
	cpu_id = smp_processor_id();
	assert(cpu_id >= 0 && cpu_id < CORE_NUM);

	d = find_dmm_struct(current->mm);
	if (!d)
		return -ERROR_EDMMNOTFOUND;

	p = find_s_pool_by_id(s_pool_id);
	if (!p)
		return -ERROR_EPOOLNOTEXIST;

#ifdef DEBUG
	printk(KERN_LEVEL "[dmm_exit] s_pool_id: %d, cpu_id:%d, ref_count:%d\n", s_pool_id, cpu_id, p->ref_count);
#endif

	/* do the job: close_s_pool if appliable */
	if (p->is_shared) {
		dmm_lock(&p->s_pool_lock, WRITE_LOCK);
		p->ref_count--;
		dmm_unlock(&p->s_pool_lock, WRITE_LOCK);

		if(p->ref_count == 0) {
			p->is_active = 0;
			close_s_pool(p);
		}
	} else {
		p->is_active = 0;
		close_s_pool(p);
	}

	/* remove s_pool from per-core active_list, NOTE: we don't maintain shared s_pool's active list TODO */
	dmm_lock(&p->s_pool_lock, WRITE_LOCK);
	if (p->is_shared == 0)
		list_del(&p->active_s_pool_list_array[cpu_id]);
	dmm_unlock(&p->s_pool_lock, WRITE_LOCK);

	/* remove thread from active thread list */
	fflag = 0;

	if (list_empty(&d->active_thread_list_head))
		return -ERROR_ETHREADNOTFOUND;

	dmm_lock(&d->active_thread_list_lock, WRITE_LOCK);
	list_for_each(l, &d->active_thread_list_head) {
		a = list_entry(l, struct active_thread_struct, active_thread_list);
		if (a->thread_id == current->pid) {
			list_del(&a->active_thread_list);
			fflag = 1;
			break;
		}
	}
	dmm_unlock(&d->active_thread_list_lock, WRITE_LOCK);

	/* current thread not on active list */
	if (fflag == 0)
		return -ERROR_ETHREADNOTFOUND;

	return 0;
}

/**
 * dmm_alloc:
 *	1. create a new section, alloc size N MB memory, and attach
 *	   new section to current s_pool.
 *	2. set s_pool->is_open on the first time
 *	3. open the section
 * 	4. return the address of memory piece
 */
#define ERROR_ANOMEM		1		/* kmalloc failed */
#define ERROR_ANOSPOOL		2		/* no s_pool found for current thread */
#define ERROR_ADMMNOTFOUND	3		/* dmm_struct not found in hashtable */
#define ERROR_AMAPFAIL		4		/* vm_mmap failed */
unsigned long dmm_alloc(int size) {
	uint32_t addr, start_addr;
	int cpu_id, dom_id;
	struct section_struct *s;
	struct dmm_struct *d;
	struct s_pool_struct *p;
	struct active_thread_struct *a;

	cpu_id = smp_processor_id();

	s = kmalloc(sizeof(struct section_struct), GFP_KERNEL);
	if (!s)
		return -ERROR_ANOMEM;

	d = find_dmm_struct(current->mm);
	if (!d)
		return -ERROR_ADMMNOTFOUND;

	a = find_active_thread_by_pid(current->pid, d);
	if (a == NULL)
		return -ERROR_ANOSPOOL;

	p = a->active;

#ifdef DEBUG
	printk(KERN_LEVEL "[dmm_alloc] size: %d, s_pool_id:%d, cpu_id:%d\n", size, p->s_pool_id, cpu_id);
#endif

	/**
	 * MAP_LOCKED	: page can't be swapped to disk
	 * MAP_POPULATE : page prefault, no pagefault later
	 * MAP_PRIVATE	: not visiable to other process
	 * MAP_ANONYMOUS: page initialized 0, no backing up file
	 * MAP_FIXED	: mapped addr fixed to giving start_addr
	 */
	/* cirtical region here, before we do vm_mmap, we should make sure only one thread can call it */
	spin_lock(&d->s_pool_top_lock);
	start_addr = d->s_pool_top;
	addr = vm_mmap(NULL, start_addr, MB(size), PROT_READ|PROT_WRITE, MAP_LOCKED|MAP_POPULATE| MAP_PRIVATE| MAP_ANONYMOUS |MAP_FIXED, 0);

	if (addr < 0) {	/* check ret_val, error code < 0 */
		spin_unlock(&d->s_pool_top_lock);
		return -ERROR_AMAPFAIL;
	}

	/* make sure addr fall in predefined range */
	assert(addr >= S_POOL_START_ADDR);

	/* if success, update s_pool_top */
	d->s_pool_top = addr + MB(size);
	spin_unlock(&d->s_pool_top_lock);

	/* initialize this section */
	s->start_addr = (void *)addr;
	s->size = size;

	/* add section to s_pool */
	dmm_lock(&p->s_pool_lock, WRITE_LOCK);
	list_add_tail(&s->section_list, &p->section_list_head);
	dmm_unlock(&p->s_pool_lock, WRITE_LOCK);

	dom_id = CPU_TO_DOM(cpu_id);
	if (p->is_shared == 1)
		dom_id = DOMAIN_SHARED;

	/* open the domain memory in this section */
	open_section(s, dom_id);
	(*my_flush_tlb_all)();

#ifdef DEBUG
	printk(KERN_LEVEL "[dmm_alloc] addr: 0x%x, s_pool_id:%d, s_pool_top:0x%x, cpu_id:%d\n", addr, p->s_pool_id, d->s_pool_top, cpu_id);
#endif
	return (unsigned long)addr;
}

/**
 * dmm_getsid(void)
 * 	return current s_pool_id.
 */
#define ERROR_GNOSPOOL		1		/* no s_pool found for current thread */
#define ERROR_GDMMNOTFOUND	2		/* dmm_struct not found in hashtable */
int dmm_getsid(void) {
	struct dmm_struct *d;
	struct s_pool_struct *p;
	struct active_thread_struct *a;
	int cpu_id;

	cpu_id = smp_processor_id();

#ifdef DEBUG
	printk(KERN_LEVEL "[dmm_getsid] cpu_id:%d\n", cpu_id);
#endif

	d = find_dmm_struct(current->mm);
	if (!d)
		return -ERROR_GDMMNOTFOUND;

	a = find_active_thread_by_pid(current->pid, d);
	if (a == NULL)
		return -ERROR_GNOSPOOL;

	p = a->active;

	return p->s_pool_id;
}

/* traverse sections to test whether addr locate in this s_pool */
int is_addr_in_s_pool(struct s_pool_struct *p, unsigned long addr) {
	struct list_head *l;
	struct section_struct *s;

	dmm_lock(&p->s_pool_lock, READ_LOCK);
	list_for_each(l, &p->section_list_head) {
		s = list_entry(l, struct section_struct, section_list);
		if ((unsigned long)(s->start_addr) <= addr
		    && ((unsigned long)(s->start_addr) + MB((s->size))) > addr) {
			dmm_unlock(&p->s_pool_lock, READ_LOCK);
			return 1;
		}
	}
	dmm_unlock(&p->s_pool_lock, READ_LOCK);

	return 0;
}

/**
 * traverse s_pool_list to find s_pool that contain addr
 * currently using this time-consuming traverse, TODO
 */
struct s_pool_struct *find_s_pool_by_addr(unsigned long addr, struct dmm_struct *d) {
	struct list_head *l;
	struct s_pool_struct *s_pool;

	/* s_pool_list is shared among all threads, lock before use */
	dmm_lock(&d->s_pool_list_lock, READ_LOCK);
	list_for_each(l, &d->s_pool_list_head) {
		s_pool = list_entry(l, struct s_pool_struct, s_pool_list);
		if (is_addr_in_s_pool(s_pool, addr)) {
			dmm_unlock(&d->s_pool_list_lock, READ_LOCK);
			return s_pool;
		}
	}
	dmm_unlock(&d->s_pool_list_lock, READ_LOCK);

	return NULL;
}

/* restore DACR value, check is_shared */
void restore_DACR(int cpu_id, int is_shared) {
	if (is_shared)
		set_DACR(DACR_SHARED);
	else {
		assert(cpu_id >= 0 && cpu_id < CORE_NUM);
		set_DACR(DACR_DEFAULT | (DACR_CLIENT << DOMAIN_SHIFT(cpu_id)));
	}
}

/**
 * close all other except current active s_pool list on this core
 * NOTE:
 * 	1. if s_pool is shared, we skip it
 */
void close_active_s_pool_list(int cpu_id, struct dmm_struct *d) {
	struct list_head *l;
	struct s_pool_struct *p;

	list_for_each(l, &d->core_array[cpu_id]) {
		p = list_entry(l, struct s_pool_struct, active_s_pool_list_array[cpu_id]);
		if (p->owner != current->pid) {
			if (p->is_shared)	/* TODO we don't close shared shred */
				continue;
			else {
				if (p->is_open == 1)
					close_s_pool(p);
			}
		}
	}
}

int get_s_pool_domid(struct s_pool_struct *p) {
	return CPU_TO_DOM(p->cpu_id);
}

/**
 * check whether domain fault should happen:
 *	1. check addr->pmd entry, whether domain is set correctly.
 *	2. check DACR value
 ×
 * return is_pmd_open.
 */
int check_domain_fault_condition(long unsigned addr) {
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	uint32_t pgd_value;
	uint32_t pud_value;
	uint32_t pmd_value;
	uint32_t dacr;
	int cpu_id;
	int is_pmd_open = 1;

	cpu_id = smp_processor_id();

	pgd = pgd_offset(current->mm, addr);
	/* arm hardware use different pgtables, linux fake it, refer to asm/pgtable-2level-types.h */
	pud = (pud_t *)&(*pgd)[pgd_hw_index(addr)];
	pmd = pmd_offset(pud, addr);
	/* pgd should be good, for we mmap section memory with MAP_POPULATE */
	assert (!pmd_none(*pmd) && !pmd_bad(*pmd));
	pgd_value = pgd_val(*pgd);
	pud_value = pud_val(*pud);
	pmd_value = pmd_val(*pmd);

	if ((pmd_value & ~DOMAIN_MASK) >> DOMAIN_BITS == 0xf)
		is_pmd_open = 0;

	dacr = get_DACR();

#ifdef DEBUG
	printk(KERN_LEVEL "[check_domain_fault_condition] pgd_value:0x%x,pud_value:0x%x,pmd_value:0x%x, dacr:0x%x, is_pmd_open:%d, cpu_id:%d\n", pgd_value, pud_value, pmd_value, dacr, is_pmd_open, cpu_id);
#endif
	return is_pmd_open;
}

/**
 * domain fault handler:
 *	find s_pool by addr, get s_pool owner and make sure:
 *		1. s_pool is active, otherwise real fault!
 *		2. if not shared, make sure current_thread is the owner of this s_pool, otherwise real fault!
 *	handle this fault:
 *		1. check whether s_pool is shared or not
 *		   if not shared:
 *			a) check whether s_pool is open
 *		   	   if opened, check domain_id == current domain_id,
 * 				I)  if yes, we don't need to reopen it, performance good here!
 *				II) otherwise, reopen it with current_domain_id.
 *		   	   if not open:
 *				I)  open it with current domain_id.(may schedled from other core)
 *		   else if shared:
 *			a) check whether s_pool is open
 *			   if opened, don't need to change domain_id
 *			   if not opened, open it with DOMAIN_SHARED
 *		2. restore DACR(cpu_id, is_shared)
 *		3. close other active s_pool list on current core_array[cpu_id] list.
 */
int domain_fault_handler(unsigned long addr, unsigned int fsr, struct pt_regs *regs) {
	struct s_pool_struct *p;
	struct dmm_struct *d;
	int cur_pid, owner_pid;
	int cpu_id, cur_domid, s_pool_domid;
	int is_pmd_open;

	/* get cpu_id first, make debug easier */
	cpu_id = smp_processor_id();


#ifdef DEBUG
	check_domain_fault_condition(addr);
#endif
	d = find_dmm_struct(current->mm);
	if(!d) {	/* dmm_struct not found */
		printk(KERN_LEVEL "[domain_fault_handler] real fault, no dmm_struct found!, cpu_id:%d\n", cpu_id);
		goto bad_area;
	}

	p = find_s_pool_by_addr(addr, d);
	if (!p) {	/* no s_pool found, real fault! */
		printk(KERN_LEVEL "[domain_fault_handler] real fault, no s_pool found! cpu_id:%d\n", cpu_id);
		goto bad_area;
	}

	printk(KERN_LEVEL "[domain_fault_handler] addr  0x%p, pc(r15)=0x%lx s_pool_id:%d, cpu_id:%d\n", (void *)addr, regs->ARM_pc, p->s_pool_id, cpu_id);

	/* check if it's active, if not, real fault! */
	if (p->is_active == 0) {
		printk(KERN_LEVEL "[domain_fault_handler] real fault, p->is_active == 0(inactive) ref_count:%d, s_pool_id:%d, cpu_id:%d\n",p->ref_count, p->s_pool_id, cpu_id);
		goto bad_area;
	}

	owner_pid = p->owner;
	cur_pid = current->pid;

	/* only s_pool owner is allowed to access s_pool, if not, real fault! */
	if (p->is_shared == 0 && cur_pid != owner_pid) {
		printk(KERN_LEVEL "[domain_fault_handler] real fault, s_pool not shared and cur_pid != owner_pid, cpu_id:%d\n", cpu_id);
		goto bad_area;
	}

#ifdef STRICT_DOMAIN_FAULT
	/* lock this s_pool before handle domain fault */
	spin_lock(&p->domain_fault_lock);
#endif
	/* now handle domain fault */
	cur_domid = CPU_TO_DOM(cpu_id);
	s_pool_domid = get_s_pool_domid(p);

	is_pmd_open = check_domain_fault_condition(addr);

	/* check whether this s_pool is shared */
	if (p->is_shared == 0) {
#ifdef DEBUG
		printk(KERN_LEVEL "[domain_fault_handler] non-shared domain, s_pool_id :%d, ref_count: %d, is_open:%s, cpu_id:%d\n", p->s_pool_id, p->ref_count, p->is_open?"True":"False", cpu_id);
#endif
		/**
		 * if not shared, we need to check domid
		 * performance good only when opened and domid not change
		 */
		if (p->is_open == 1 && cur_domid == s_pool_domid) {
				if (is_pmd_open == 0) {
					open_s_pool(p, cur_domid);
					printk(KERN_LEVEL "[domain_fault_handler] non-share domain, attention: p->is_open open! cpu_id:%d\n", cpu_id);
				}
				goto good_area;
		}

		/* open it with current domid */
#ifdef DEBUG
		if (cur_domid != s_pool_domid)
			printk(KERN_LEVEL "[domain_fault_handler] TODO execution resumed on different core! old cpu_id:%d, new cpu_id:%d\n", p->cpu_id, cpu_id);
#endif
		open_s_pool(p, cur_domid);
	} else {
		/* if shared, check open state */
#ifdef DEBUG
		printk(KERN_LEVEL "[domain_fault_handler] shared domain fault, s_pool_id :%d, ref_count: %d, is_open:%s, cpu_id:%d\n", p->s_pool_id, p->ref_count, p->is_open?"True":"False", cpu_id);
#endif
		if (p->is_open == 1) {
			if (is_pmd_open == 0) {
				open_s_pool(p, DOMAIN_SHARED);
				printk(KERN_LEVEL "[domain_fault_handler] shared domain, attention: p->is_open open! cpu_id:%d\n", cpu_id);
			}
			goto good_area;
		} else
			open_s_pool(p, DOMAIN_SHARED);
	}

good_area:
	/* restore DACR */
	restore_DACR(cpu_id, p->is_shared);
	close_active_s_pool_list(cpu_id, d);

#ifdef DEBUG
	check_domain_fault_condition(addr);
#endif

#ifdef STRICT_DOMAIN_FAULT
	spin_unlock(&p->domain_fault_lock);
#endif

	return 0;

bad_area:
	/* real fault, may kill user thread if in user mode */
	(*do_user_fault)(current, addr, fsr, SIGSEGV, SEGV_ACCERR, regs);
	return 1;
}

module_init(init_dmm_module);
module_exit(exit_dmm_module);
