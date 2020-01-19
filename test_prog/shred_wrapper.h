#ifndef _TEST_DMM_H
#define _TEST_DMM_H
void shred_enter(int s_pool_id, int is_shared);
void *shred_alloc(int size);
void shred_exit(int s_pool_id);
void *s_pool_alloc(int size);
int get_current_s_pool_id(void);
#endif
