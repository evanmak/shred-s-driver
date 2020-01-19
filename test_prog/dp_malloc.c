#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include "dp_malloc.h"
#include "shred_wrapper.h"

#define DEBUG

static inline void *get_cur_chunk_header(void);
static inline size_t mega_byte_rounded(size_t size);
static inline void set_cur_chunk_header(void *cp);
static void *find_fit(char *bp, size_t size);
static void *place(void *bp, size_t rsize);
static void *extend_heap(size_t N);
static void insert_chunk(void *cp, void *eh_header, size_t masize);
static void *coalesce(void *bp);
static void do_dp_free(void *ptr);

#define IN_CHUNK(ptr, ck_header, ck_size) (ptr >= ck_header && ptr < ck_header + ck_size)

/**
 * keep which dp_heap we are now working on, initial value -1, for we have no dp_heap
 * to work on.
 */
__thread size_t cur_dp_heap_index = -1;

/* the dp_heap count can only increase, we do not free region. */
size_t dp_heap_count = 0;


size_t get_current_region_ID(void) {
	// TODO: fake interface
	return 0;
}

size_t set_DACR(char *ptr, int num) {
	// TODO: fake interface
	return 0;
}

/**
 * keep in mind that, this function is called each time we enter malloc,
 * and it sets the cur_dp_heap_index for all furture dp_heap_array access.
 */
void set_heap_index_by_region_id(size_t region_id) {
	int i;

	for (i = 0; i < dp_heap_count; i++) {
		if (dp_heap_array[i].region_id == region_id)
			break;
	}

	/* no region_id found in the list, alloc new one, increase count by 1 */
	if (i == dp_heap_count)
		dp_heap_count++;

	/* now we know which dp_heap entry we are working on, set it */
	cur_dp_heap_index = i;
	return;
}

size_t dp_initialize(size_t region_id) {
	char *dp_header;
	int res;

	/* size = 1MB, alignement BC_SIZE = 1MB */
	dp_header = shred_alloc(1);

	/* By defination dp_header should be MB aligned. If not, we are done! */
	assert(CHECK_ALIGN(dp_header, BC_SIZE));

	/* check if aligned_alloc success */
	if(!dp_header)
		return -1;

	/* size = 1MB */
	res = set_DACR(dp_header, 1);

	/* check if set_DACR succeed, it operates in kernel */
	if(res < 0)
		return -1;

	/**
	 * assert if we are the first time to initialize this entry, otherwise,
	 * something went wrong!
	 */
#ifdef DEBUG
	printf("[dp_initialize] cur_dp_heap_index : %d\n", cur_dp_heap_index);
#endif
	assert(dp_heap_array[cur_dp_heap_index].ini_flag == false);

	/* initialize dp_heap_array with region_id and dp_header */
	dp_heap_array[cur_dp_heap_index].region_id = region_id;
	dp_heap_array[cur_dp_heap_index].cur_chunk_header = dp_header;
	dp_heap_array[cur_dp_heap_index].ini_flag = true;

	/**
	 * initialize the 1MB memory chunk pointed by dp_header, chunk is organised into
	 * a double-linked list. CHUNK HEADER points to prev chunk, FOOTER points to
	 * next chunk.
	 */

	/* CHUNK header , overlap with malloc alignment padding */
	PUT(dp_header, PACK_CHUNK(dp_header, 1, 0));

	PUT(dp_header + (1*WSIZE), PACK(DSIZE, 1));	/* Prologue header */
	PUT(dp_header + (2*WSIZE), PACK(DSIZE, 1));	/* Prologue footer */

	/**
	 * First free block, usually chunk_size - 4*WSIZE, but in order not to
	 * overlap with malloc header, we deduct end in advance, leave the last 2 words empty
	 * for malloc use. so we have free block size equals chunk_size - 4*WSIZE.
	 */
	PUT(dp_header + (3*WSIZE), PACK(BC_SIZE - 4*WSIZE, 0));
	PUT(FTRP(dp_header + (4*WSIZE)), PACK(BC_SIZE - 4*WSIZE, 0));

	/* CHUNK footer, overlap with epilogue header, now is marked CHUNK_END */
	PUT(CFTRP(dp_header, 1), PACK_CHUNK(dp_header, 1, CHUNK_END));

	return 0;
}

static void *extend_heap(size_t N) {
	char *eh_header;
	size_t res;

	eh_header = shred_alloc(N);

	/* By defination eh_header should be MB aligned. If not, we are done! */
	assert(CHECK_ALIGN(eh_header, BC_SIZE));

	if (eh_header == NULL)
		return NULL;

	res = set_DACR(eh_header, N);
	if (res < 0)
		return NULL;

	return eh_header;
}


void *dp_malloc(size_t size) {
	char *ck_header, *eh_header, *next_ck_header, *cp;
	char *bp_header, *bp;
	size_t asize, masize, ck_size;
	
	/* Ignore spurious alloc */
	if (size == 0)
		return NULL;

	if (size <= DSIZE)
		asize = 2*DSIZE;
	else
		asize = ALIGN(size + DSIZE, DSIZE);

	/**
	 * traverse chunk list, and search free blocks within each chunk for a fit
	 * ck_header is where the traverse starts, we keep it for end-checking.
	 */
	ck_header = get_cur_chunk_header();
	
	/* traverse starts! */
	cp = ck_header;				/* chunk pointer */
	ck_size = GET_CHUNK_SIZE(cp);		/* chunk size of cp */
	bp_header = GET_FIRST_BLKP(cp); 	/* first block pointer */

#ifdef DEBUG
	printf("[dp_malloc] cp:%p, ck_size:0x%x\n", cp, ck_size);
#endif

	/* search within a chunk */
	bp = find_fit(bp_header, asize);

	/* chunk list is a double-linked list, so the ending requirement is next_ck_header == ck_header */
	while((bp == NULL) && (next_ck_header = NEXT_CNKP(cp, ck_size)) != ck_header) {
		ck_size = GET_CHUNK_SIZE(next_ck_header);

		/* get the first block pointer within chunk */
		cp = next_ck_header;
		bp_header = GET_FIRST_BLKP(cp);

		/* search the next chunk for a fit */
		bp = find_fit(bp_header, asize);
	}
	
	if (bp) { /* find one, good! */
		place(bp, asize);

		/* hopefully make it quicker for next search */
		set_cur_chunk_header(cp);

	} else {
		/**
		 * get the mega-byte ceiled masize of size
		 * Note: for a new chunk, the usable size is CHUNK_SIZE - 4*WSIZE
		 */
		masize = mega_byte_rounded(asize + 4*WSIZE);
		eh_header = extend_heap(masize);

		/* insert the new chunk into the double-linked list, and initilize it at same time */
		insert_chunk(cp, eh_header, masize);

		/* we are going to alloc from this new chunk, so set it as our current chunk header */
		set_cur_chunk_header(eh_header);
		
		/* search for a fit memory block */
		bp_header = GET_FIRST_BLKP(eh_header);
		bp = find_fit(bp_header, asize);
	
		// we should succeed now, for we just get masize MB free block
		if (bp) 
			place(bp, asize);
		else
			return NULL;
	}
	return (void *)bp;
}

size_t dp_free(void *ptr) {
	void *ck_header, *cp, *next_ck_header;
	size_t ck_size;

	/**
	 * traverse chunk list, and search if ptr in chunk range
	 * ck_header is where the traverse starts, we keep it for end-checking.
	 */
	ck_header = get_cur_chunk_header();

	/* traverse starts! */
	cp = ck_header;				/* chunk pointer */
	ck_size = GET_CHUNK_SIZE(cp);		/* chunk size of cp */

#ifdef DEBUG
	printf("[dp_free] start ck_header:%p, ck_size:0x%x, ptr:%p\n", cp, ck_size, ptr);
#endif
	/* chunk list is a double-linked list, so the ending requirement is next_ck_header == ck_header */
	while((!IN_CHUNK(ptr, cp, ck_size)) && (next_ck_header = NEXT_CNKP(cp, ck_size)) != ck_header) {
		ck_size = GET_CHUNK_SIZE(next_ck_header);
		cp = next_ck_header;
#ifdef DEBUG
	printf("[dp_free] traverse cp:%p, ck_size:0x%x, ptr:%p\n", cp, ck_size, ptr);
#endif
	}

#ifdef DEBUG
	printf("[dp_free] end cp:%p, ck_size:0x%x, ptr:%p\n", cp, ck_size, ptr);
#endif

	if(IN_CHUNK(ptr, cp, ck_size)){
		do_dp_free(ptr);
		return 0;
	} else
		return -1;
}

static void do_dp_free(void *ptr) {
        size_t size = GET_SIZE(HDRP(ptr));

        PUT(HDRP(ptr), PACK(size, 0));
        PUT(FTRP(ptr), PACK(size, 0));

	//printf("sblibc:free! bp = %lx\n", ptr);
        coalesce(ptr);
}

/* insert eh_header into double-linked chunk list after cp */
static void insert_chunk(void *cp, void *eh_header, size_t masize) {
	size_t ck_size, next_size;

	ck_size = GET_CHUNK_SIZE(cp);
	next_size = GET_CHUNK_SIZE(NEXT_CNKP(cp, ck_size));

	/**
	 * First, insert eh_header into chunk list.
	 *
	 * classical way to insert into a double-linked list:
	 * new.next = cp->next, new.prev = cp
	 * cp->next.prev = new, cp.next = new
	 */
	PUT(CFTRP(eh_header, masize), PACK_CHUNK(NEXT_CNKP(cp, ck_size), masize, CHUNK_END));
	PUT(CHDRP(eh_header, masize), PACK_CHUNK(cp, masize, 0));
	PUT(CHDRP(NEXT_CNKP(cp, ck_size), next_size), PACK_CHUNK(eh_header, next_size, 0));
	PUT(CFTRP(cp, ck_size), PACK_CHUNK(eh_header, ck_size, CHUNK_END));

	/**
	 * Second, initilize the new chunk.
	 *
	 * Note: each new chunk should be initilized as a self-contained mallacable unit
	 */

	PUT(eh_header + (1*WSIZE), PACK(DSIZE, 1));	/* Prologue header */
	PUT(eh_header + (2*WSIZE), PACK(DSIZE, 1));	/* Prologue footer */

	/**
	 * First big free block in new chunk, usually chunk_size - 4*WSIZE
	 * Be careful when use macro FTRP(bp), it require bp points to the start of block.
	 * but not the header of it.
	 */

	PUT(eh_header + (3*WSIZE), PACK(masize * BC_SIZE - 4 * WSIZE, 0)); 		/* First free block header */
	PUT(FTRP(eh_header + (4*WSIZE)), PACK(masize * BC_SIZE - 4 * WSIZE, 0));	/* First free block footer */
}

/**
 * coalesce adjact free block, even when next_blkp is CHUNK FOOTER, CHUNK_END
 * mark can still be regonized as alloced, so no need to change coalesce even
 * when we transfer from malloc to dp_malloc!
 */
static void *coalesce(void *bp)
{
	size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(bp)));
	size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
	size_t size = GET_SIZE(HDRP(bp));

	if (prev_alloc && next_alloc){	/* case 1 */
		return bp;
	}

	else if (prev_alloc && !next_alloc){	/* case 2 */
		size += GET_SIZE(HDRP(NEXT_BLKP(bp)));
		PUT(HDRP(bp), PACK(size, 0));
		PUT(FTRP(bp), PACK(size, 0));
	}

	else if (!prev_alloc && next_alloc){	/* case 3 */
		size += GET_SIZE(HDRP(PREV_BLKP(bp)));
		PUT(FTRP(bp), PACK(size, 0));
		PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
		bp = PREV_BLKP(bp);
	}

	else {
		size += GET_SIZE(HDRP(PREV_BLKP(bp))) +
		     GET_SIZE(HDRP(NEXT_BLKP(bp)));
		PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
		PUT(FTRP(NEXT_BLKP(bp)), PACK(size, 0));
		bp = PREV_BLKP(bp);
	}
	return bp;
}

/* find first fit for size */
static void *find_fit(char *bp, size_t size)
{
	void *p = NEXT_BLKP(bp);

	while(GET_ALLOC(HDRP(p)) != CHUNK_END) {
		if (GET_ALLOC(HDRP(p)) == 0 &&
			GET_SIZE(HDRP(p)) >= size)
			return p;
		else
			p = NEXT_BLKP(p);
	}

	return NULL;
}

/* place free block bp, split it when necessary*/
static void *place(void *bp, size_t rsize)
{
	size_t bsize = GET_SIZE(HDRP(bp));
	size_t nsize = bsize - rsize;


	/* if block size is larger than request size, then split it */
	if (bsize > rsize) {
		PUT(HDRP(bp + rsize), PACK(nsize, 0));
		PUT(FTRP(bp + rsize), PACK(nsize, 0));
	}

	PUT(HDRP(bp), PACK(rsize, 1));
	PUT(FTRP(bp), PACK(rsize, 1));
	return bp;
}

/* querry dp_heap_array with cur_dp_heap_index for cur_chunk_header */
static inline void *get_cur_chunk_header(void) {
#ifdef DEBUG
	int idx = cur_dp_heap_index;
	printf("[get_cur_chunk_header] cur_dp_heap_index:%d, s_pool_id:%d, header:%p\n", idx, dp_heap_array[idx].region_id, dp_heap_array[idx].cur_chunk_header);
#endif
	return dp_heap_array[cur_dp_heap_index].cur_chunk_header;
}

/* return value in MBs */
static inline size_t mega_byte_rounded(size_t size) {
	return ALIGN(size, BC_SIZE) >> 20;
}

static inline void set_cur_chunk_header(void *cp){
	dp_heap_array[cur_dp_heap_index].cur_chunk_header = cp;
}
