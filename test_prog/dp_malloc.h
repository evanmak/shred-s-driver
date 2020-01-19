#ifndef _DP_MALLOC_H
#define _DP_MALLOC_H

/**
  * dp_malloc.h
  */

/* support bool type */
#define bool	int
#define true	1
#define false	0

/**
 * Max region number, a region is associated with a heap memory chunk list,
 * at any time, on a cpu, can one region be opened. The kernel only open access
 * for a certain region, so we need to guarantee we do malloc on a opened region.
 */
#define MAX_REGION 20
#define EOS -1	// current state is out of scope, invalid call to set_DACR
#define EUD -2	// error undefined, unsuccessful

#define CHECK_ALIGN(bp, size)	(!((size_t)bp & (size - 1)))

#define assert(condition) do {										\
		if (!(condition)) {									\
			printf("Condition does not holds in %s, at line %d\n",__func__, __LINE__);	\
			exit(0);									\
		}											\
	} while (0)


//#define POWER_2_CHUNK // chunk size must be power of 2 MB
/**
 * BORROW a lot from CSAPP
 * different from normal malloc, dp_malloc manage a double linked list of
 * mega-byte aligned chunks. So we have in inner-chunk operations
 * that is normal block operations, and inter-chunk operations, that
 * is operation between domain protected MB aligned chunks.
 * block header and footer are used to keep block size and alloc status,
 * chunk header and footer are used to keep chunk size and prev, next chunk addr,
 * block are continuous, so they don't need pointer to next block, however,
 * chunks are not continuous, so they need to keep that info.
 */
#define WSIZE 4 /* word size */
#define DSIZE 8 /* double words size */
#define BC_SIZE (1<<20) /* basic chunk size is 1MB, can be 2 or more MB */

/* Alloc status, using least 3 bits*/
#define FREE	0x0
#define ALLOC	0x1
#define CHUNK_END	0x2	/* marks the end of in a chunk, chunk can be several MBs */

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define ALIGN(size, align) ((size + align - 1) & (~(align - 1)))

/* =*= below are inner chunk operations =*= */

/**
 * PACK is used to pack size with alloc status,
 * status can be 0x0, 0x01, 0x2
 * FREE		: 0x0
 * ALLOC	: 0x1
 * CHUNK_END	: 0x2
 * Actually, least three bits are reserved, for the alignment requirement
 * is 8 bytes. We only use 0x0, 0x1, 0x2. The other ending pattern
 * ranged from 0x3 - 0x7 are reserved.
 * 
 * PACK_CHUNK is used to pack chunk pointer with chunk size and end mark.
 * size is in MB, and pointer should always be MB alligned.
 * Actually, pointer should always be chunk header addr, which by defination
 * is MB aligned.
 */
#define PACK(size, alloc) ((size) | (alloc))
#define PACK_CHUNK(pointer, size, mark) (((size_t)pointer)|((size & (BC_SIZE - 1)) << 3) | (mark))

/* read and write a word at addr p */
#define GET(p) (*(unsigned int *)(p))
#define PUT(p, val) (*(unsigned int *)(p) = (val))

/* read the size and allocated field at addr p */
#define GET_SIZE(p) (GET(p) & ~0x7)
#define GET_ALLOC(p) (GET(p) & 0x7)

/* Given block ptr bp, compute bp's address of header and footer */
#define HDRP(bp) ((char *)(bp) - WSIZE)
#define FTRP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE)

/* Given block ptr bp, compute address of next and previous blocks */
#define NEXT_BLKP(bp) (FTRP(bp) + DSIZE)
#define PREV_BLKP(bp) ((char *)(bp) - GET_SIZE(bp - DSIZE))

/* =*= below are inter chunk operations =*= */

/* read the chunk size and chunk status, size using bit 3-19, 17 bits in total*/
#define GET_CHUNK_SIZE(p) ((GET(p) & (BC_SIZE - 1)) >> 3)
#define GET_CHUNK_STATUS(p) (GET(p) & 0x7)

/* Given chunk ptr cp, chunk size(MB) , compute cp's address of header and footer */
#ifdef POWER_2_CHUNK
	#define CHDRP(cp, s) ((char *)(cp) & ~(s * BC_SIZE - 1))
#else
	#define CHDRP(hp, s) (hp)
#endif

#define CFTRP(cp, s) (CHDRP(cp, s) + (s * BC_SIZE) - WSIZE)

/* Given chunk ptr cp, chunk size(MB) compute address of next and previous chunk */
#define NEXT_CNKP(cp, s) ((void *)((size_t)GET(CFTRP(cp, s)) & ~(BC_SIZE - 1)))
#define PREV_CNKP(cp, s) (GET(CHDRP(cp, s)) & ~(BC_SIZE - 1))

/* Given cur_chunk_header, get the first block pointer within that chunk */
#define GET_FIRST_BLKP(cc_header) ((char *)cc_header + 2*WSIZE)

/**
 * bundle a heap_header pointer with a region ID
 * we could have a concurrency error here when two or more cpus are accessing dh_array
 * but due to the per-cpu design, that would not be a problem, each cpu will modify their
 * own entry.
 */
typedef struct {
	size_t region_id;
	void *cur_chunk_header;
	bool ini_flag;
}dp_heap;

dp_heap dp_heap_array[MAX_REGION];

/* if we reenter a region, we need use this func to get the heap index */
void set_heap_index_by_region_id(size_t region_id);

/* if succeed, return 0; else return -1; */
size_t dp_initialize(size_t region_id);
void *dp_malloc(size_t size);
size_t dp_free(void *ptr);

/**
 * if in scope, return the current region ID, kernel will open this region for us;
 * Otherwise return EOS.
 *   EOS: current state is out of scope.
 */
size_t get_current_region_ID(void);

/**
 * @ptr: points to a continuous of mega-byte aligned memory blocks.
 * @num: number of mega-byte block.
 * @return
 * 	if successful, return 0;
 *  	if unsuccessful, return 
 * 		EOS: current state is out of scope, invalid call to set_DACR
 *  		EUD: error undefined, unsuccessful
 */
size_t set_DACR(char *ptr, int num);

#endif
