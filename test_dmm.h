#ifndef _TEST_DMM_H
#define _TEST_DMM_H
void shred_enter(int s_pool_id, int is_shared);
void *shred_alloc(int size);
void shred_exit(int s_pool_id);
#endif
